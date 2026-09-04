package main

import (
	"crypto/ed25519"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/MatrixMagician/Errand/internal/sshtest"
	"golang.org/x/crypto/ssh"
)

// hostConfig describes the config file one test needs. The zero value points
// alias "h" at the harness with its client key and an empty known_hosts.
type hostConfig struct {
	knownHosts string
	identities []string
	hostname   string
	port       int
}

func writeConfig(t *testing.T, s *sshtest.Server, o hostConfig) string {
	t.Helper()
	if o.identities == nil {
		o.identities = []string{s.ClientKey.Path}
	}
	if o.hostname == "" {
		o.hostname = "127.0.0.1"
	}
	if o.port == 0 {
		o.port = s.Port
	}
	quoted := make([]string, len(o.identities))
	for i, p := range o.identities {
		quoted[i] = strconv.Quote(p)
	}
	dir := t.TempDir()
	kh := sshtest.WriteFile(t, dir, "known_hosts", o.knownHosts)
	return sshtest.WriteFile(t, dir, "config.toml", fmt.Sprintf(`[defaults]
user           = "root"
known_hosts    = %q
identity_files = [%s]

[hosts.h]
hostname = %q
port     = %d
`, kh, strings.Join(quoted, ", "), o.hostname, o.port))
}

// trusting is the configuration in which everything should work.
func trusting(t *testing.T, s *sshtest.Server) string {
	t.Helper()
	return writeConfig(t, s, hostConfig{knownHosts: s.KnownHostsLine() + "\n"})
}

// errand runs the built binary with the developer's SSH agent kept out of it.
func errand(t *testing.T, cfg, stdin string, args ...string) (int, string, string) {
	t.Helper()
	env := []string{"ERRAND_CONFIG=" + cfg, "SSH_AUTH_SOCK="}
	return sshtest.Run(t, sshtest.Binary(t), env, stdin, args...)
}

func TestIntegrationHosts(t *testing.T) {
	s := sshtest.Start(t)
	code, stdout, stderr := errand(t, trusting(t, s), "", "hosts")
	if code != 0 {
		t.Fatalf("errand hosts exited %d, stderr: %s", code, stderr)
	}
	for _, want := range []string{"h", "127.0.0.1", fmt.Sprint(s.Port)} {
		if !strings.Contains(stdout, want) {
			t.Errorf("errand hosts stdout missing %q:\n%s", want, stdout)
		}
	}
}

func TestIntegrationRunStreamsUnmerged(t *testing.T) {
	s := sshtest.Start(t)
	code, stdout, stderr := errand(t, trusting(t, s), "", "run", "h", "--", "echo out; echo err >&2")
	// The harness runs sshd with -e and LogLevel DEBUG, so its own log lines
	// share the session's stderr; assert on errand's contribution to it.
	if code != 0 || stdout != "out\n" {
		t.Errorf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if !strings.Contains(stderr, "err\n") || strings.Contains(stderr, "errand: ") {
		t.Errorf("stderr should carry the remote's line and no diagnostics: %q", stderr)
	}
}

func TestIntegrationRunExitCodes(t *testing.T) {
	s := sshtest.Start(t)
	cfg := trusting(t, s)
	for _, c := range []struct {
		command string
		want    int
	}{{"true", 0}, {"exit 7", 7}, {"exit 255", 255}} {
		t.Run(c.command, func(t *testing.T) {
			code, stdout, stderr := errand(t, cfg, "", "run", "h", "--", c.command)
			if code != c.want {
				t.Errorf("code=%d, want %d; stdout=%q stderr=%q", code, c.want, stdout, stderr)
			}
		})
	}
}

func TestIntegrationRunSignalledRemote(t *testing.T) {
	s := sshtest.Start(t)
	code, _, stderr := errand(t, trusting(t, s), "", "run", "h", "--", "kill -TERM $$")
	t.Logf("stderr: %s", stderr)
	if code != 143 || !strings.Contains(stderr, "errand: ") || !strings.Contains(stderr, "SIGTERM") {
		t.Errorf("code=%d, want 143; stderr=%q", code, stderr)
	}
}

func TestIntegrationRunWrongClientKey(t *testing.T) {
	s := sshtest.Start(t)
	cfg := writeConfig(t, s, hostConfig{
		knownHosts: s.KnownHostsLine() + "\n",
		identities: []string{s.RejectedKey.Path},
	})
	code, _, stderr := errand(t, cfg, "", "run", "h", "--", "true")
	t.Logf("stderr: %s", stderr)
	if code != 252 || !strings.Contains(stderr, "publickey") {
		t.Errorf("code=%d, want 252; stderr=%q", code, stderr)
	}
}

func TestIntegrationRunUnknownHostKey(t *testing.T) {
	s := sshtest.Start(t)
	code, stdout, stderr := errand(t, writeConfig(t, s, hostConfig{}), "", "run", "h", "--", "true")
	t.Logf("stderr: %s", stderr)
	if code != 251 {
		t.Errorf("code=%d, want 251; stderr=%q", code, stderr)
	}
	if stdout != "" {
		t.Errorf("diagnostics leaked into stdout: %q", stdout)
	}
	for _, want := range []string{"SHA256:", s.KnownHostsLine()} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr missing %q:\n%s", want, stderr)
		}
	}
}

func TestIntegrationRunChangedHostKey(t *testing.T) {
	s := sshtest.Start(t)
	cfg := writeConfig(t, s, hostConfig{knownHosts: s.WrongKnownHostsLine() + "\n"})
	code, _, stderr := errand(t, cfg, "", "run", "h", "--", "true")
	t.Logf("stderr: %s", stderr)
	if code != 251 || !strings.Contains(stderr, "changed") {
		t.Errorf("code=%d, want 251; stderr=%q", code, stderr)
	}
}

func TestIntegrationRunNetworkFailures(t *testing.T) {
	s := sshtest.Start(t)
	cases := map[string]hostConfig{
		"unresolvable": {knownHosts: s.KnownHostsLine() + "\n", hostname: "nonexistent.invalid"},
		"refused":      {knownHosts: s.KnownHostsLine() + "\n", port: closedPort(t)},
	}
	for name, o := range cases {
		t.Run(name, func(t *testing.T) {
			code, _, stderr := errand(t, writeConfig(t, s, o), "", "run", "h", "--", "true")
			t.Logf("stderr: %s", stderr)
			if code != 253 {
				t.Errorf("code=%d, want 253; stderr=%q", code, stderr)
			}
		})
	}
}

func TestIntegrationRunEncryptedIdentitySkipped(t *testing.T) {
	s := sshtest.Start(t)
	locked := lockedKey(t, s.ClientKey.Path)
	cfg := writeConfig(t, s, hostConfig{
		knownHosts: s.KnownHostsLine() + "\n",
		identities: []string{locked, s.ClientKey.Path},
	})
	code, _, stderr := errand(t, cfg, "", "run", "h", "--", "true")
	t.Logf("stderr: %s", stderr)
	if code != 0 || !strings.Contains(stderr, "passphrase-protected") || !strings.Contains(stderr, locked) {
		t.Errorf("code=%d, want 0; stderr=%q", code, stderr)
	}
}

func TestIntegrationRunStdin(t *testing.T) {
	s := sshtest.Start(t)
	cfg := trusting(t, s)
	code, stdout, stderr := errand(t, cfg, "hi\n", "run", "h", "--", "cat")
	if code != 0 || stdout != "" {
		t.Errorf("without --stdin: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	code, stdout, stderr = errand(t, cfg, "hi\n", "run", "h", "--stdin", "--", "cat")
	if code != 0 || stdout != "hi\n" {
		t.Errorf("with --stdin after the host: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestIntegrationRunWithoutSeparator(t *testing.T) {
	s := sshtest.Start(t)
	code, _, stderr := errand(t, trusting(t, s), "", "run", "h", "true")
	if code != 0 {
		t.Errorf("code=%d, want 0; stderr=%q", code, stderr)
	}
}

// closedPort returns a port nothing is listening on.
func closedPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

// lockedKey re-encrypts an existing private key under a passphrase.
func lockedKey(t *testing.T, from string) string {
	t.Helper()
	raw, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.ParseRawPrivateKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	if ed, ok := key.(*ed25519.PrivateKey); ok {
		key = *ed
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(key, "", []byte("hunter2"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "locked_key")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestIntegrationRawDial(t *testing.T) {
	s := sshtest.Start(t)

	client, err := dial(s, s.ClientKey)
	if err != nil {
		t.Fatalf("dial with the authorized key: %v\ncontainer logs:\n%s", err, s.Logs(t))
	}
	defer func() { _ = client.Close() }()

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer func() { _ = session.Close() }()
	if err := session.Run("true"); err != nil {
		t.Fatalf("run true: %v", err)
	}

	rejected, err := dial(s, s.RejectedKey)
	if err == nil {
		_ = rejected.Close()
		t.Fatal("dial with the rejected key succeeded, want an auth failure")
	}
}

func dial(s *sshtest.Server, key sshtest.Key) (*ssh.Client, error) {
	return ssh.Dial("tcp", s.Addr, &ssh.ClientConfig{
		User:            "root",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(key.Signer)},
		HostKeyCallback: ssh.FixedHostKey(s.HostKey),
		Timeout:         10 * time.Second,
	})
}
