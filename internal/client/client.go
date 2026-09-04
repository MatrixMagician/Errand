// Package client dials a configured host: TCP, host key verification against
// known_hosts, and non-interactive public key authentication (SPEC §8).
package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/MatrixMagician/Errand/internal/config"
	"github.com/MatrixMagician/Errand/internal/result"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Diag reports one errand diagnostic line. The caller owns the "errand: "
// prefix and whether the line is printed at all.
type Diag func(format string, args ...any)

// Conn is an authenticated connection to a configured host.
type Conn struct {
	*ssh.Client
	Host    config.Host
	Connect time.Duration

	raw       net.Conn
	stopKA    func()
	abortOnce sync.Once
}

// Dial connects, verifies the host key and authenticates. Every error is
// wrapped with the host alias and the phase it failed in, unless ctx ran out
// first: then the outcome is the timeout or the interrupt, not the symptom the
// aborted handshake reported.
func Dial(ctx context.Context, h config.Host, diag Diag) (*Conn, error) {
	c, err := dial(ctx, h, diag)
	if err != nil && stopped(ctx) {
		return nil, result.StopCause(ctx)
	}
	return c, err
}

// stopped reports whether ctx has run out. The deadline is checked as well as
// Err because a dial fails on the socket deadline net sets from ctx, which can
// land fractionally before ctx's own timer marks it done.
func stopped(ctx context.Context) bool {
	if ctx.Err() != nil {
		return true
	}
	deadline, ok := ctx.Deadline()
	return ok && !time.Now().Before(deadline)
}

func dial(ctx context.Context, h config.Host, diag Diag) (*Conn, error) {
	if diag == nil {
		diag = func(string, ...any) {}
	}
	addr := net.JoinHostPort(h.Hostname, strconv.Itoa(h.Port))
	start := time.Now()

	verify, err := hostKeyPolicy(h, diag)
	if err != nil {
		return nil, err
	}

	var dialer net.Dialer
	raw, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, result.Connect.Wrap(h.Alias, err)
	}
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stop()

	methods, closeAgent := authMethods(h, diag)
	defer closeAgent()

	// The callback is the only place that knows the handshake got past the
	// key exchange, so it is where the phase advances.
	var state struct {
		sync.Mutex
		phase result.Phase
		err   error
	}
	state.phase = result.Connect
	cfg := &ssh.ClientConfig{
		User: h.User,
		Auth: methods,
		HostKeyCallback: func(_ string, remote net.Addr, key ssh.PublicKey) error {
			state.Lock()
			defer state.Unlock()
			state.phase = result.HostKey
			if state.err = verify(addr, remote, key); state.err != nil {
				return state.err
			}
			state.phase = result.Auth
			return nil
		},
	}

	sc, chans, reqs, err := ssh.NewClientConn(raw, addr, cfg)
	if err != nil {
		_ = raw.Close()
		state.Lock()
		defer state.Unlock()
		switch {
		case state.err != nil:
			return nil, result.HostKey.Wrap(h.Alias, state.err)
		case state.phase == result.Auth:
			return nil, result.Auth.Wrap(h.Alias, authError(err, len(methods)))
		}
		return nil, result.Connect.Wrap(h.Alias, err)
	}
	return &Conn{
		Client:  ssh.NewClient(sc, chans, reqs),
		Host:    h,
		Connect: time.Since(start),
		raw:     raw,
	}, nil
}

// Abort forces the connection down without blocking: the socket deadline is
// the guarantee, closing the client is the courtesy.
func (c *Conn) Abort(grace time.Duration) {
	c.abortOnce.Do(func() {
		_ = c.raw.SetDeadline(time.Now().Add(grace))
		_ = c.Client.Close()
	})
}

// Close stops the keepalive loop and closes the connection.
func (c *Conn) Close() error {
	if c.stopKA != nil {
		c.stopKA()
	}
	return c.Client.Close()
}

// authError keeps x/crypto's text, which already lists both the methods we
// attempted and the ones the server still offers, and drops its redundant
// "handshake failed" framing.
func authError(err error, methods int) error {
	msg := err.Error()
	msg, _ = strings.CutPrefix(msg, "ssh: handshake failed: ")
	if methods == 0 {
		return fmt.Errorf("no usable identities: %s", msg)
	}
	return errors.New(msg)
}

// hostKeyPolicy is the whole of SPEC §8 for one host. A configured pin replaces
// known_hosts outright, accept_new may record a key known_hosts has never seen,
// and nothing may accept a key that changed.
func hostKeyPolicy(h config.Host, diag Diag) (ssh.HostKeyCallback, error) {
	if h.HostKey != "" {
		pin, _, _, _, err := ssh.ParseAuthorizedKey([]byte(h.HostKey))
		if err != nil {
			return nil, result.Resolve.Wrap(h.Alias, fmt.Errorf("host_key: %w", err))
		}
		return func(addr string, _ net.Addr, key ssh.PublicKey) error {
			if bytes.Equal(key.Marshal(), pin.Marshal()) {
				return nil
			}
			return pinMismatch(addr, key, pin)
		}, nil
	}

	check, err := knownHostsCheck(h.KnownHosts)
	if err != nil {
		return nil, result.HostKey.Wrap(h.Alias, err)
	}
	unknown := unknownKey
	if h.AcceptNew {
		unknown = func(addr string, key ssh.PublicKey) error { return trustNew(h.KnownHosts, addr, key, diag) }
	}
	return func(addr string, remote net.Addr, key ssh.PublicKey) error {
		err := check(addr, remote, key)
		var ke *knownhosts.KeyError
		switch {
		case err == nil:
			return nil
		case !errors.As(err, &ke):
			return err
		case len(ke.Want) == 0:
			return unknown(addr, key)
		}
		return changedKey(addr, key, ke.Want[0])
	}, nil
}

// knownHostsCheck reads the files that are there and skips the ones that are
// not. When none can be read every key comes back as an unknown one, which is
// the safe reading of "the operator recorded nothing".
func knownHostsCheck(files []string) (ssh.HostKeyCallback, error) {
	var present []string
	for _, f := range files {
		if _, err := os.Stat(f); err == nil {
			present = append(present, f)
		}
	}
	if len(present) == 0 {
		return func(string, net.Addr, ssh.PublicKey) error { return &knownhosts.KeyError{} }, nil
	}
	return knownhosts.New(present...)
}

// trustNew records an unknown key in the first configured known_hosts file so
// the connection can proceed. A key we failed to write down is a key we never
// agreed to trust, so a failed append fails the connection.
func trustNew(files []string, addr string, key ssh.PublicKey, diag Diag) error {
	path := config.ExpandHome("~/.ssh/known_hosts")
	if len(files) > 0 {
		path = files[0]
	}
	if err := appendLine(path, knownhosts.Line([]string{addr}, key)); err != nil {
		return fmt.Errorf("cannot record the host key for %s in %s: %w", knownhosts.Normalize(addr), path, err)
	}
	diag("added host key for %s to %s (accept_new)", knownhosts.Normalize(addr), path)
	return nil
}

func appendLine(path, line string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	// A file the operator left without a final newline would otherwise have its
	// last entry silently joined to ours.
	var last [1]byte
	if info, err := f.Stat(); err == nil && info.Size() > 0 {
		if _, err := f.ReadAt(last[:], info.Size()-1); err == nil && last[0] != '\n' {
			line = "\n" + line
		}
	}
	if _, err := f.WriteString(line + "\n"); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func pinMismatch(addr string, key, pin ssh.PublicKey) error {
	return fmt.Errorf("host key for %s does not match the configured pin: host_key is %s %s, server offered %s %s",
		knownhosts.Normalize(addr), pin.Type(), ssh.FingerprintSHA256(pin),
		key.Type(), ssh.FingerprintSHA256(key))
}

func unknownKey(addr string, key ssh.PublicKey) error {
	return fmt.Errorf("unknown host key for %s (%s %s); add to known_hosts: %s",
		knownhosts.Normalize(addr), key.Type(), ssh.FingerprintSHA256(key),
		knownhosts.Line([]string{addr}, key))
}

func changedKey(addr string, key ssh.PublicKey, want knownhosts.KnownKey) error {
	return fmt.Errorf("host key changed for %s: %s:%d says %s %s, server offered %s %s",
		knownhosts.Normalize(addr), want.Filename, want.Line,
		want.Key.Type(), ssh.FingerprintSHA256(want.Key),
		key.Type(), ssh.FingerprintSHA256(key))
}

// authMethods offers the agent's identities first, then each configured
// identity file. Nothing ever prompts; unusable identities are noted and
// skipped so the server still gets a chance to say what it accepts.
func authMethods(h config.Host, diag Diag) ([]ssh.AuthMethod, func()) {
	var methods []ssh.AuthMethod
	closeAgent := func() {}
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		conn, err := net.Dial("unix", sock)
		if err != nil {
			diag("skipping SSH agent at %s: %v", sock, err)
		} else {
			closeAgent = func() { _ = conn.Close() }
			methods = append(methods, ssh.PublicKeysCallback(agent.NewClient(conn).Signers))
		}
	}
	for _, path := range h.IdentityFiles {
		pem, err := os.ReadFile(path)
		if err != nil {
			diag("skipping %s: %v", path, err)
			continue
		}
		signer, err := ssh.ParsePrivateKey(pem)
		var locked *ssh.PassphraseMissingError
		switch {
		case errors.As(err, &locked):
			diag("skipping %s: passphrase-protected", path)
			continue
		case err != nil:
			diag("skipping %s: %v", path, err)
			continue
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}
	return methods, closeAgent
}
