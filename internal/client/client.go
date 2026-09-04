// Package client dials a configured host: TCP, host key verification against
// known_hosts, and non-interactive public key authentication (SPEC §8).
package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
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
// wrapped with the host alias and the phase it failed in.
func Dial(ctx context.Context, h config.Host, diag Diag) (*Conn, error) {
	if diag == nil {
		diag = func(string, ...any) {}
	}
	addr := net.JoinHostPort(h.Hostname, strconv.Itoa(h.Port))
	start := time.Now()

	var dialer net.Dialer
	raw, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, result.Connect.Wrap(h.Alias, err)
	}
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stop()

	verify, err := hostKeyVerifier(h.KnownHosts)
	if err != nil {
		_ = raw.Close()
		return nil, result.HostKey.Wrap(h.Alias, err)
	}

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

// hostKeyVerifier builds the known_hosts check. Files that are not there are
// skipped; when none can be read every key is unknown, which is the safe
// reading of "the operator recorded nothing".
func hostKeyVerifier(files []string) (ssh.HostKeyCallback, error) {
	var present []string
	for _, f := range files {
		if _, err := os.Stat(f); err == nil {
			present = append(present, f)
		}
	}
	if len(present) == 0 {
		return func(addr string, _ net.Addr, key ssh.PublicKey) error { return unknownKey(addr, key) }, nil
	}
	check, err := knownhosts.New(present...)
	if err != nil {
		return nil, err
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
			return unknownKey(addr, key)
		}
		return changedKey(addr, key, ke.Want[0])
	}, nil
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
