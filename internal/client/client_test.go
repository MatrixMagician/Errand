package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MatrixMagician/Errand/internal/config"
	"github.com/MatrixMagician/Errand/internal/result"
	"github.com/MatrixMagician/Errand/internal/sshtest"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func testKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func authorized(key ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}

func TestHostKeyPolicyPinIgnoresKnownHosts(t *testing.T) {
	server, other := testKey(t), testKey(t)
	h := config.Host{Alias: "h", HostKey: authorized(server), KnownHosts: []string{"/nonexistent/known_hosts"}}

	verify, _, err := hostKeyPolicy(h, nil)
	if err != nil {
		t.Fatalf("hostKeyPolicy: %v", err)
	}
	if err := verify("127.0.0.1:2222", nil, server); err != nil {
		t.Errorf("the pinned key was rejected: %v", err)
	}
	err = verify("127.0.0.1:2222", nil, other)
	if err == nil || !strings.Contains(err.Error(), "pin") {
		t.Errorf("a key other than the pin gave %v, want a pin mismatch", err)
	}

	h.HostKey = "not-a-key"
	_, _, err = hostKeyPolicy(h, nil)
	if err == nil || !strings.Contains(err.Error(), "resolve: host_key:") {
		t.Errorf("a malformed pin gave %v, want a resolve error", err)
	}
}

func TestHostKeyPolicyAcceptNewRecordsTheKey(t *testing.T) {
	key := testKey(t)
	path := filepath.Join(t.TempDir(), "ssh", "known_hosts")
	var notes []string
	verify, _, err := hostKeyPolicy(
		config.Host{Alias: "h", AcceptNew: true, KnownHosts: []string{path}},
		func(format string, args ...any) { notes = append(notes, fmt.Sprintf(format, args...)) },
	)
	if err != nil {
		t.Fatalf("hostKeyPolicy: %v", err)
	}
	if err := verify("127.0.0.1:2222", nil, key); err != nil {
		t.Fatalf("accept_new rejected an unknown key: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("known_hosts was not created: %v", err)
	}
	if want := knownhosts.Line([]string{"127.0.0.1:2222"}, key) + "\n"; string(got) != want {
		t.Errorf("known_hosts = %q, want %q", got, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("known_hosts mode = %v, want 0600", info.Mode().Perm())
	}
	if len(notes) != 1 || !strings.Contains(notes[0], "accept_new") {
		t.Errorf("diagnostics = %q, want one accept_new note", notes)
	}
}

// TestHostKeyPolicyOtherKeyTypeIsNotAChange covers a server that offers a key
// of a type known_hosts has no entry for. That is not evidence of a changed
// key, so it must not read as one, and without accept_new it is not trusted.
func TestHostKeyPolicyOtherKeyTypeIsNotAChange(t *testing.T) {
	const addr = "127.0.0.1:2222"
	recorded := testKey(t)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	offered, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	kh := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(kh, []byte(knownhosts.Line([]string{addr}, recorded)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	verify, _, err := hostKeyPolicy(config.Host{Alias: "h", KnownHosts: []string{kh}}, nil)
	if err != nil {
		t.Fatalf("hostKeyPolicy: %v", err)
	}
	err = verify(addr, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2222}, offered)
	if err == nil {
		t.Fatal("a key of an unrecorded type was accepted without accept_new")
	}
	if strings.Contains(err.Error(), "changed") {
		t.Errorf("an unrecorded key type gave %q, want no claim that the key changed", err)
	}
	if want := "no recorded ecdsa-sha2-nistp256 host key"; !strings.Contains(err.Error(), want) {
		t.Errorf("error = %q, want it to say %q", err, want)
	}
}

// TestAuthRejected separates the server refusing our identities, which new
// credentials fix, from the transport failing mid-exchange, which a retry
// might. The texts are the shapes x/crypto returns from NewClientConn.
func TestAuthRejected(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{errors.New("ssh: handshake failed: ssh: unable to authenticate, attempted methods [none publickey], no supported methods remain"), true},
		{errors.New("ssh: handshake failed: ssh: disconnect, reason 2: Too many authentication failures"), true},
		{fmt.Errorf("ssh: handshake failed: %w", io.EOF), false},
		{errors.New("ssh: handshake failed: read tcp 127.0.0.1:50000->127.0.0.1:2222: read: connection reset by peer"), false},
	} {
		if got := authRejected(tc.err); got != tc.want {
			t.Errorf("authRejected(%q) = %v, want %v", tc.err, got, tc.want)
		}
	}
}

func TestAppendLineTerminatesAnUnfinishedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(path, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := appendLine(path, "second"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := "first\nsecond\n"; string(got) != want {
		t.Errorf("file = %q, want %q", got, want)
	}
}

// TestKeepaliveRequestsKeepFlowing is the observable half of SPEC §11. The
// harness sshd logs at INFO and so never records the global requests, which
// leaves the client side as the only place to see them: the hook counts each
// request and reports what the server answered, so a request that never left
// the process and one the server never saw both fail the test. Abort is
// checked in the same connection because it is the path exec takes on a
// wedged transport, where a loop only Close stops would outlive its own
// connection.
func TestKeepaliveRequestsKeepFlowing(t *testing.T) {
	s := sshtest.Start(t)
	t.Setenv("SSH_AUTH_SOCK", "")

	var mu sync.Mutex
	var errs []error
	sent := func() int {
		mu.Lock()
		defer mu.Unlock()
		return len(errs)
	}
	ship := sendKeepalive
	sendKeepalive, keepaliveInterval = func(c ssh.Conn) error {
		err := ship(c)
		mu.Lock()
		defer mu.Unlock()
		errs = append(errs, err)
		return err
	}, 100*time.Millisecond
	t.Cleanup(func() { sendKeepalive, keepaliveInterval = ship, 30*time.Second })

	dir := t.TempDir()
	conn, err := Dial(context.Background(), config.Host{
		Alias: "h", Hostname: "127.0.0.1", Port: s.Port, User: "root",
		KnownHosts:    []string{sshtest.WriteFile(t, dir, "known_hosts", s.KnownHostsLine()+"\n")},
		IdentityFiles: []string{s.ClientKey.Path},
	}, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	sess, err := conn.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	if err := sess.Run("sleep 1"); err != nil {
		t.Fatalf("sleep 1: %v", err)
	}
	_ = sess.Close()

	mu.Lock()
	t.Logf("%d keepalive requests answered during a 1s command", len(errs))
	if len(errs) < 5 {
		t.Errorf("sent %d keepalives in a 1s command at a 100ms interval, want at least 5", len(errs))
	}
	for i, err := range errs {
		if err != nil {
			t.Errorf("keepalive %d was not answered: %v", i, err)
		}
	}
	mu.Unlock()

	conn.Abort(time.Second)
	after := sent()
	time.Sleep(5 * keepaliveInterval)
	if grew := sent(); grew != after {
		t.Errorf("%d keepalives went out after Abort, want the loop stopped", grew-after)
	}
}

// TestDialStopsAHungAgent covers an agent that takes the connection and never
// answers, as a locked 1Password or gpg-agent waiting on a GUI prompt does.
// The handshake blocks reading the agent socket, not the TCP one, so only
// closing the agent connection lets the connect budget end it.
func TestDialStopsAHungAgent(t *testing.T) {
	s := sshtest.Start(t)
	dir, err := os.MkdirTemp("", "agent")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	var held []net.Conn
	var heldMu sync.Mutex
	t.Cleanup(func() {
		heldMu.Lock()
		defer heldMu.Unlock()
		for _, c := range held {
			_ = c.Close()
		}
	})
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			heldMu.Lock()
			held = append(held, c)
			heldMu.Unlock()
		}
	}()
	t.Setenv("SSH_AUTH_SOCK", sock)

	const budget = 500 * time.Millisecond
	ctx, cancel := context.WithTimeoutCause(context.Background(), budget, result.ErrTimeout)
	defer cancel()
	knownHosts := sshtest.WriteFile(t, t.TempDir(), "known_hosts", s.KnownHostsLine()+"\n")
	start := time.Now()
	done := make(chan error, 1)
	go func() {
		conn, err := Dial(ctx, config.Host{
			Alias: "h", Hostname: "127.0.0.1", Port: s.Port, User: "root",
			KnownHosts: []string{knownHosts},
		}, nil)
		if conn != nil {
			_ = conn.Close()
		}
		done <- err
	}()

	select {
	case err := <-done:
		if elapsed := time.Since(start); elapsed > budget+time.Second {
			t.Errorf("Dial took %v, want within the %v connect budget", elapsed, budget)
		}
		if code := (result.Result{Err: err}).ExitCode(); code != 254 {
			t.Errorf("Dial gave %v (exit %d), want the connect timeout (exit 254)", err, code)
		}
	case <-time.After(budget + 3*time.Second):
		t.Fatal("Dial is still blocked on the hung agent")
	}
}
