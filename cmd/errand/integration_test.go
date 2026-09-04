package main

import (
	"crypto/ed25519"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
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
	timeout    string
	maxOutput  string
	acceptNew  bool
	hostKey    string
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
	settings := ""
	if o.timeout != "" {
		settings += fmt.Sprintf("timeout    = %q\n", o.timeout)
	}
	if o.maxOutput != "" {
		settings += fmt.Sprintf("max_output = %q\n", o.maxOutput)
	}
	if o.acceptNew {
		settings += "accept_new = true\n"
	}
	if o.hostKey != "" {
		settings += fmt.Sprintf("host_key   = %q\n", o.hostKey)
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
%s`, kh, strings.Join(quoted, ", "), o.hostname, o.port, settings))
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
	if code != 0 || stdout != "out\n" || stderr != "err\n" {
		t.Errorf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
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

// knownHostsPath is the file writeConfig put beside the config it returned.
func knownHostsPath(cfg string) string {
	return filepath.Join(filepath.Dir(cfg), "known_hosts")
}

func authorizedKey(key ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestIntegrationRunAcceptNew(t *testing.T) {
	s := sshtest.Start(t)
	cfg := writeConfig(t, s, hostConfig{acceptNew: true})
	kh := knownHostsPath(cfg)

	code, _, stderr := errand(t, cfg, "", "run", "h", "--", "true")
	t.Logf("stderr: %s", stderr)
	if code != 0 || !strings.Contains(stderr, "accept_new") {
		t.Fatalf("code=%d, want 0 with an accept_new note; stderr=%q", code, stderr)
	}
	recorded := readFile(t, kh)
	if want := s.KnownHostsLine() + "\n"; recorded != want {
		t.Errorf("known_hosts = %q, want %q", recorded, want)
	}

	// The key is known now, so the second run is an ordinary trusting run.
	code, _, stderr = errand(t, cfg, "", "run", "h", "--", "true")
	if code != 0 || strings.Contains(stderr, "accept_new") {
		t.Errorf("second run: code=%d, want 0 with no note; stderr=%q", code, stderr)
	}
	if again := readFile(t, kh); again != recorded {
		t.Errorf("known_hosts changed on the second run: %q, want %q", again, recorded)
	}
}

// TestIntegrationRunAcceptNewChangedKey is the one refusal with no override:
// accept_new records a key nobody has seen, never one that changed.
func TestIntegrationRunAcceptNewChangedKey(t *testing.T) {
	s := sshtest.Start(t)
	before := s.WrongKnownHostsLine() + "\n"
	cfg := writeConfig(t, s, hostConfig{acceptNew: true, knownHosts: before})
	code, _, stderr := errand(t, cfg, "", "run", "h", "--", "true")
	t.Logf("stderr: %s", stderr)
	if code != 251 || !strings.Contains(stderr, "changed") {
		t.Errorf("code=%d, want 251 for a changed key; stderr=%q", code, stderr)
	}
	if after := readFile(t, knownHostsPath(cfg)); after != before {
		t.Errorf("known_hosts = %q, want it untouched at %q", after, before)
	}
}

func TestIntegrationRunPinnedHostKey(t *testing.T) {
	s := sshtest.Start(t)
	cases := []struct {
		name       string
		hostKey    string
		knownHosts string
		code       int
		diagnostic string
	}{
		{"matching pin needs no known_hosts", authorizedKey(s.HostKey), "", 0, ""},
		{"mismatched pin beats a trusting known_hosts", authorizedKey(s.ClientKey.Public), s.KnownHostsLine() + "\n", 251, "pin"},
		{"malformed pin", "not-a-key", s.KnownHostsLine() + "\n", 250, "host_key"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := writeConfig(t, s, hostConfig{hostKey: c.hostKey, knownHosts: c.knownHosts})
			code, _, stderr := errand(t, cfg, "", "run", "h", "--", "true")
			t.Logf("stderr: %s", stderr)
			if code != c.code {
				t.Errorf("code=%d, want %d; stderr=%q", code, c.code, stderr)
			}
			if c.diagnostic != "" && !strings.Contains(stderr, c.diagnostic) {
				t.Errorf("stderr=%q, want it to mention %q", stderr, c.diagnostic)
			}
		})
	}
}

func TestIntegrationHostsShowsHostKeyPolicy(t *testing.T) {
	s := sshtest.Start(t)
	cfg := writeConfig(t, s, hostConfig{acceptNew: true, hostKey: authorizedKey(s.HostKey)})
	code, stdout, stderr := errand(t, cfg, "", "hosts")
	if code != 0 {
		t.Fatalf("errand hosts exited %d, stderr: %s", code, stderr)
	}
	t.Logf("stdout:\n%s", stdout)
	for _, want := range []string{"ACCEPT_NEW", "HOST_KEY", "yes", s.HostKey.Type() + " (pinned)"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("errand hosts stdout missing %q:\n%s", want, stdout)
		}
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

// timed runs errand and reports how long the process took, so a test can prove
// "promptly" rather than merely "eventually".
func timed(t *testing.T, cfg string, args ...string) (int, string, time.Duration) {
	t.Helper()
	start := time.Now()
	code, _, stderr := errand(t, cfg, "", args...)
	took := time.Since(start)
	t.Logf("%v -> exit %d in %v, stderr: %s", args, code, took, stderr)
	return code, stderr, took
}

// startErrand launches the binary and returns once the remote command has
// announced itself on stdout, so a test can act while it is genuinely running.
// The command must begin with "echo started".
func startErrand(t *testing.T, cfg string, args ...string) (*exec.Cmd, *strings.Builder) {
	t.Helper()
	cmd := exec.Command(sshtest.Binary(t), args...)
	cmd.Env = append(os.Environ(), "ERRAND_CONFIG="+cfg, "SSH_AUTH_SOCK=")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr := &strings.Builder{}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(stdout, make([]byte, len("started\n"))); err != nil {
		t.Fatalf("waiting for the remote command to start: %v; stderr: %s", err, stderr)
	}
	return cmd, stderr
}

func TestIntegrationRunTimeout(t *testing.T) {
	s := sshtest.Start(t)
	code, stderr, took := timed(t, trusting(t, s), "run", "h", "--timeout", "2s", "--", "sleep 30")
	if code != 254 {
		t.Errorf("code=%d, want 254", code)
	}
	if !strings.Contains(stderr, "errand: ") || !strings.Contains(stderr, "timeout") {
		t.Errorf("stderr=%q, want an errand timeout diagnostic", stderr)
	}
	if took > 4*time.Second {
		t.Errorf("took %v, want the 2s budget plus teardown", took)
	}
}

// TestIntegrationRunTimeoutTeardownIsPrompt is the "server ignores KILL" case.
// The container's sshd honours signals, so the worst case is staged at the
// transport instead: once the proxy freezes, the KILL request goes nowhere and
// no exit status can arrive, leaving Abort's socket deadline as the only thing
// that ends the run.
func TestIntegrationRunTimeoutTeardownIsPrompt(t *testing.T) {
	s := sshtest.Start(t)
	p := newFreezingProxy(t, s.Addr)
	cfg := writeConfig(t, s, hostConfig{
		knownHosts: fmt.Sprintf("[127.0.0.1]:%d %s\n", p.Port, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.HostKey)))),
		port:       p.Port,
	})
	cmd, stderr := startErrand(t, cfg, "run", "h", "--timeout", "2s", "--", "echo started; sleep 30")
	p.Freeze()
	start := time.Now()
	err := cmd.Wait()
	took := time.Since(start)
	t.Logf("exit %d in %v after the transport froze, stderr: %s", cmd.ProcessState.ExitCode(), took, stderr)
	if code := cmd.ProcessState.ExitCode(); code != 254 {
		t.Errorf("code=%d (%v), want 254", code, err)
	}
	// The 2s budget, then the 2s teardown and 1s flush graces, doubled for CI.
	if took > 10*time.Second {
		t.Errorf("took %v: teardown waited on a server that can never answer", took)
	}
}

func TestIntegrationRunConnectTimeout(t *testing.T) {
	s := sshtest.Start(t)
	// An address in the unrouted RFC 1918 range: packets are dropped, so the
	// TCP handshake never completes and only the deadline ends the dial.
	cfg := writeConfig(t, s, hostConfig{knownHosts: s.KnownHostsLine() + "\n", hostname: "10.255.255.1", port: 22})
	code, stderr, took := timed(t, cfg, "run", "h", "--connect-timeout", "1s", "--", "true")
	if code != 254 {
		t.Errorf("code=%d, want 254 (253 means the dial failed for another reason)", code)
	}
	if !strings.Contains(stderr, "timeout") {
		t.Errorf("stderr=%q, want a timeout diagnostic", stderr)
	}
	if took > 3*time.Second {
		t.Errorf("took %v, want the 1s connect budget", took)
	}
}

func TestIntegrationRunCancelledBySIGINT(t *testing.T) {
	s := sshtest.Start(t)
	cmd, stderr := startErrand(t, trusting(t, s), "run", "h", "--", "echo started; sleep 30")
	start := time.Now()
	if err := cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	err := cmd.Wait()
	took := time.Since(start)
	t.Logf("exit %d in %v after SIGINT, stderr: %s", cmd.ProcessState.ExitCode(), took, stderr)
	if code := cmd.ProcessState.ExitCode(); code != 130 {
		t.Errorf("code=%d (%v), want 130", code, err)
	}
	if !strings.Contains(stderr.String(), "cancelled") {
		t.Errorf("stderr=%q, want a cancelled diagnostic", stderr)
	}
	if took > 3*time.Second {
		t.Errorf("took %v to exit after SIGINT", took)
	}
}

func TestIntegrationRunPerHostTimeout(t *testing.T) {
	s := sshtest.Start(t)
	cfg := writeConfig(t, s, hostConfig{knownHosts: s.KnownHostsLine() + "\n", timeout: "1s"})
	if code, _, took := timed(t, cfg, "run", "h", "--", "sleep 30"); code != 254 || took > 3*time.Second {
		t.Errorf("per-host timeout: code=%d took=%v, want 254 promptly", code, took)
	}
	if code, _, took := timed(t, cfg, "run", "h", "--timeout", "5s", "--", "sleep 2"); code != 0 {
		t.Errorf("flag overriding the per-host timeout: code=%d took=%v, want 0", code, took)
	}
}

// freezingProxy forwards one TCP connection to addr until Freeze, then goes
// silent in both directions. It never closes the frozen connection: that a
// hung peer stays open is exactly what teardown has to survive.
type freezingProxy struct {
	Port   int
	frozen chan struct{}
}

func newFreezingProxy(t *testing.T, addr string) *freezingProxy {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	p := &freezingProxy{Port: l.Addr().(*net.TCPAddr).Port, frozen: make(chan struct{})}
	go func() {
		down, err := l.Accept()
		if err != nil {
			return
		}
		up, err := net.Dial("tcp", addr)
		if err != nil {
			_ = down.Close()
			return
		}
		go p.pipe(down, up)
		go p.pipe(up, down)
	}()
	return p
}

func (p *freezingProxy) Freeze() { close(p.frozen) }

func (p *freezingProxy) pipe(dst, src net.Conn) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		select {
		case <-p.frozen:
			return
		default:
		}
		if n > 0 {
			if _, err := dst.Write(buf[:n]); err != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func TestIntegrationRunOutputCap(t *testing.T) {
	s := sshtest.Start(t)
	start := time.Now()
	code, stdout, stderr := errand(t, trusting(t, s), "", "run", "h", "--max-output", "64KiB", "--", "yes")
	took := time.Since(start)
	t.Logf("exit %d in %v with %d stdout bytes, stderr: %s", code, took, len(stdout), stderr)
	if code != 254 {
		t.Errorf("code=%d, want 254: the remote never exited on its own", code)
	}
	if len(stdout) != 65536 {
		t.Errorf("delivered %d stdout bytes, want exactly the 65536-byte cap", len(stdout))
	}
	if !strings.Contains(stderr, "errand: output truncated at 65536 bytes") {
		t.Errorf("stderr=%q, want the truncation diagnostic", stderr)
	}
	if took > 4*time.Second {
		t.Errorf("took %v, want a prompt teardown", took)
	}
}

func TestIntegrationRunUnderTheCapIsUntouched(t *testing.T) {
	s := sshtest.Start(t)
	code, stdout, stderr := errand(t, trusting(t, s), "", "run", "h", "--max-output", "64KiB", "--", "echo hi; exit 3")
	if code != 3 || stdout != "hi\n" || strings.Contains(stderr, "truncated") {
		t.Errorf("code=%d stdout=%q stderr=%q, want 3, %q and no truncation", code, stdout, stderr, "hi\n")
	}
}

// TestIntegrationRunCapStraddledByAnExit is SPEC 5.4's asymmetry with a
// timeout: output that runs past the cap still exits with the remote's own
// code when that code arrives inside killGrace.
func TestIntegrationRunCapStraddledByAnExit(t *testing.T) {
	s := sshtest.Start(t)
	code, stdout, stderr := errand(t, trusting(t, s), "", "run", "h", "--max-output", "64KiB", "--", "head -c 200000 /dev/zero; exit 7")
	t.Logf("exit %d with %d stdout bytes, stderr: %s", code, len(stdout), stderr)
	if code != 7 {
		t.Errorf("code=%d, want the remote's own 7", code)
	}
	if len(stdout) != 65536 {
		t.Errorf("delivered %d stdout bytes, want exactly the 65536-byte cap", len(stdout))
	}
	if !strings.Contains(stderr, "truncated") {
		t.Errorf("stderr=%q, want a truncation diagnostic", stderr)
	}
}

func TestIntegrationRunCapDisabled(t *testing.T) {
	s := sshtest.Start(t)
	code, stdout, stderr := errand(t, trusting(t, s), "", "run", "h", "--max-output", "0", "--", "head -c 2000000 /dev/zero")
	if code != 0 || len(stdout) != 2000000 {
		t.Errorf("code=%d with %d stdout bytes, want 0 and 2000000; stderr=%q", code, len(stdout), stderr)
	}
}

// TestIntegrationRunCapSpansBothStreams checks the budget is shared, not per
// stream. Only the remote writes a "z", so errand's own diagnostic on stderr
// cannot be mistaken for delivered stderr.
func TestIntegrationRunCapSpansBothStreams(t *testing.T) {
	s := sshtest.Start(t)
	code, stdout, stderr := errand(t, trusting(t, s), "", "run", "h", "--max-output", "10", "--", "printf aaaaaa; printf zzzzzz >&2; sleep 5")
	t.Logf("exit %d, stdout=%q stderr=%q", code, stdout, stderr)
	delivered := len(stdout) + strings.Count(stderr, "z")
	if code != 254 || delivered != 10 {
		t.Errorf("code=%d with %d bytes delivered across both streams, want 254 and 10", code, delivered)
	}
	if !strings.Contains(stderr, "output truncated at 10 bytes") {
		t.Errorf("stderr=%q, want the diagnostic to count both streams", stderr)
	}
}

func TestIntegrationRunPerHostMaxOutput(t *testing.T) {
	s := sshtest.Start(t)
	cfg := writeConfig(t, s, hostConfig{knownHosts: s.KnownHostsLine() + "\n", maxOutput: "1KiB"})
	// The trailing sleep keeps the remote alive past the breach, so the exit
	// code says whether the cap fired rather than which of the two won a race.
	const command = "head -c 5000 /dev/zero; sleep 1"
	if code, _, stderr := errand(t, cfg, "", "run", "h", "--", command); code != 254 {
		t.Errorf("per-host max_output: code=%d, want 254; stderr=%q", code, stderr)
	}
	code, stdout, stderr := errand(t, cfg, "", "run", "h", "--max-output", "1MiB", "--", command)
	if code != 0 || len(stdout) != 5000 {
		t.Errorf("flag overriding max_output: code=%d with %d stdout bytes, want 0 and 5000; stderr=%q", code, len(stdout), stderr)
	}
}
