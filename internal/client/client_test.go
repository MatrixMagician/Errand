package client

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MatrixMagician/Errand/internal/config"
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

	verify, err := hostKeyPolicy(h, nil)
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
	_, err = hostKeyPolicy(h, nil)
	if err == nil || !strings.Contains(err.Error(), "resolve: host_key:") {
		t.Errorf("a malformed pin gave %v, want a resolve error", err)
	}
}

func TestHostKeyPolicyAcceptNewRecordsTheKey(t *testing.T) {
	key := testKey(t)
	path := filepath.Join(t.TempDir(), "ssh", "known_hosts")
	var notes []string
	verify, err := hostKeyPolicy(
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
