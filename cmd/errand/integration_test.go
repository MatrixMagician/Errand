package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
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
	auditLog   string
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
	// Every config names an audit log inside its own temp dir. Left unset, a
	// run would append to the developer's own ~/.local/state log instead.
	if o.auditLog == "" {
		o.auditLog = filepath.Join(dir, "audit.jsonl")
	}
	kh := sshtest.WriteFile(t, dir, "known_hosts", o.knownHosts)
	return sshtest.WriteFile(t, dir, "config.toml", fmt.Sprintf(`[defaults]
user           = "root"
known_hosts    = %q
identity_files = [%s]
audit_log      = %q

[hosts.h]
hostname = %q
port     = %d
%s`, kh, strings.Join(quoted, ", "), o.auditLog, o.hostname, o.port, settings))
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

// TestIntegrationPutInterruptedTransportFrozen is the other half: a connection
// stalled hard enough that no request can leave. Nothing can be tidied over a
// transport that has stopped carrying packets, so the guarantee narrows to the
// one the spec actually makes, that the final name never appears.
func TestIntegrationPutInterruptedTransportFrozen(t *testing.T) {
	s := sshtest.Start(t)
	direct := trusting(t, s)
	dir := remoteDir(t, direct)
	local := sparsePayload(t, interruptSize)

	p := newFreezingProxy(t, s.Addr)
	cfg := writeConfig(t, s, hostConfig{
		knownHosts: fmt.Sprintf("[127.0.0.1]:%d %s\n", p.Port, authorizedKey(s.HostKey)),
		port:       p.Port,
	})
	cmd := exec.Command(sshtest.Binary(t), "put", "h", "--max-size", "600MiB", "--timeout", "2s", local, dir+"/file")
	cmd.Env = append(os.Environ(), "ERRAND_CONFIG="+cfg, "SSH_AUTH_SOCK=")
	stderr := &strings.Builder{}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	p.Freeze()
	start := time.Now()
	err := cmd.Wait()
	took := time.Since(start)

	code := cmd.ProcessState.ExitCode()
	t.Logf("exit %d in %v after the transport froze, stderr: %s", code, took, stderr)
	if code != 254 {
		t.Errorf("code=%d (%v), want 254", code, err)
	}
	// The 2s budget, then the 500ms cleanup window and the 2s teardown grace,
	// doubled for CI.
	if took > 10*time.Second {
		t.Errorf("took %v: teardown waited on a transport that can never answer", took)
	}
	left := remote(t, direct, "ls -A "+dir)
	t.Logf("after the freeze, ls -A %s = %q", dir, left)
	for _, name := range strings.Fields(left) {
		if name == "file" {
			t.Errorf("the final name survives a frozen transfer: ls -A = %q", left)
		}
	}
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
func startErrand(t *testing.T, cfg string, args ...string) (*exec.Cmd, io.Reader, *strings.Builder) {
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
	return cmd, stdout, stderr
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
	cmd, _, stderr := startErrand(t, cfg, "run", "h", "--timeout", "2s", "--", "echo started; sleep 30")
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
	cmd, _, stderr := startErrand(t, trusting(t, s), "run", "h", "--", "echo started; sleep 30")
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

// TestIntegrationRunEnv is both halves of the AcceptEnv contract. The harness
// accepts FOO and nothing else, so BAR is the documented silent refusal: the
// variable never arrives and the command runs anyway.
func TestIntegrationRunEnv(t *testing.T) {
	s := sshtest.Start(t)
	cfg := trusting(t, s)
	cases := []struct {
		name    string
		args    []string
		command string
		stdout  string
	}{
		{"accepted", []string{"--env", "FOO=bar"}, "echo $FOO", "bar\n"},
		{"refused", []string{"--env", "BAR=1"}, "echo x$BAR", "x\n"},
		{"repeated", []string{"--env", "FOO=one", "--env", "FOO=two"}, "echo $FOO", "two\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			args := append([]string{"run", "h"}, c.args...)
			code, stdout, stderr := errand(t, cfg, "", append(args, "--", c.command)...)
			if code != 0 || stdout != c.stdout {
				t.Errorf("code=%d stdout=%q, want 0 and %q; stderr=%q", code, stdout, c.stdout, stderr)
			}
		})
	}
}

func TestIntegrationRunEnvMalformed(t *testing.T) {
	s := sshtest.Start(t)
	code, _, stderr := errand(t, trusting(t, s), "", "run", "h", "--env", "NOEQUALS", "--", "true")
	t.Logf("stderr: %s", stderr)
	if code != 250 || !strings.Contains(stderr, "KEY=VAL") {
		t.Errorf("code=%d, want 250 with a KEY=VAL complaint; stderr=%q", code, stderr)
	}
}

// TestIntegrationRunPTY pins the flag to something only a PTY can change:
// tty(1) fails on a plain exec channel and succeeds on a pty-req.
func TestIntegrationRunPTY(t *testing.T) {
	s := sshtest.Start(t)
	cfg := trusting(t, s)
	code, stdout, stderr := errand(t, cfg, "", "run", "h", "--pty", "--", "tty")
	t.Logf("with --pty: exit %d stdout=%q stderr=%q", code, stdout, stderr)
	if code != 0 || !strings.HasPrefix(stdout, "/dev/pts") {
		t.Errorf("code=%d stdout=%q, want 0 and a /dev/pts device", code, stdout)
	}
	if code, stdout, _ = errand(t, cfg, "", "run", "h", "--", "tty"); code != 1 {
		t.Errorf("without --pty: code=%d stdout=%q, want 1", code, stdout)
	}
}

// TestIntegrationRunQuiet is the line SPEC 4.1 draws: --quiet owns errand's
// own stderr and nothing else on it.
func TestIntegrationRunQuiet(t *testing.T) {
	s := sshtest.Start(t)
	code, _, stderr := errand(t, writeConfig(t, s, hostConfig{}), "", "run", "h", "--quiet", "--", "true")
	if code != 251 || stderr != "" {
		t.Errorf("unknown host key: code=%d stderr=%q, want 251 and nothing on stderr", code, stderr)
	}
	code, _, stderr = errand(t, trusting(t, s), "", "run", "h", "--quiet", "--", "echo err >&2")
	if code != 0 || stderr != "err\n" {
		t.Errorf("remote stderr: code=%d stderr=%q, want 0 and %q", code, stderr, "err\n")
	}
}

func TestIntegrationCheckSucceeds(t *testing.T) {
	s := sshtest.Start(t)
	code, stdout, stderr := errand(t, trusting(t, s), "", "check", "h")
	t.Logf("stderr: %s", stderr)
	if code != 0 {
		t.Fatalf("code=%d, want 0; stderr=%q", code, stderr)
	}
	if stdout != "" {
		t.Errorf("stdout=%q, want nothing: check discards the remote's streams", stdout)
	}
	want := regexp.MustCompile(fmt.Sprintf(`^errand: ok root@127\.0\.0\.1:%d connect=\d+ms\n$`, s.Port))
	if !want.MatchString(stderr) {
		t.Errorf("stderr=%q, want a line matching %v", stderr, want)
	}

	// The summary is a diagnostic, so --quiet takes it away without changing
	// the answer the exit code carries.
	code, _, stderr = errand(t, trusting(t, s), "", "check", "h", "--quiet")
	if code != 0 || stderr != "" {
		t.Errorf("--quiet: code=%d stderr=%q, want 0 and silence", code, stderr)
	}
}

// TestIntegrationCheckFailsLikeRun is the ticket's promise: a 251 or 252 from
// check tells the agent exactly what run would have said, so the preflight can
// be trusted in place of the real thing.
func TestIntegrationCheckFailsLikeRun(t *testing.T) {
	s := sshtest.Start(t)
	cases := []struct {
		name string
		cfg  hostConfig
		want int
	}{
		{"unknown host key", hostConfig{}, 251},
		{"wrong client key", hostConfig{knownHosts: s.KnownHostsLine() + "\n", identities: []string{s.RejectedKey.Path}}, 252},
		{"refused", hostConfig{knownHosts: s.KnownHostsLine() + "\n", port: closedPort(t)}, 253},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := writeConfig(t, s, c.cfg)
			code, _, stderr := errand(t, cfg, "", "check", "h")
			t.Logf("stderr: %s", stderr)
			runCode, _, runStderr := errand(t, cfg, "", "run", "h", "--", "true")
			if code != c.want || runCode != c.want {
				t.Errorf("check exited %d and run exited %d, want %d both; stderr=%q", code, runCode, c.want, stderr)
			}
			if stderr != runStderr {
				t.Errorf("check said %q, run said %q", stderr, runStderr)
			}
		})
	}
}

func TestIntegrationCheckConnectTimeout(t *testing.T) {
	s := sshtest.Start(t)
	cfg := writeConfig(t, s, hostConfig{knownHosts: s.KnownHostsLine() + "\n", hostname: "10.255.255.1", port: 22})
	code, stderr, took := timed(t, cfg, "check", "h", "--connect-timeout", "1s")
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

func TestIntegrationCheckUnknownAlias(t *testing.T) {
	s := sshtest.Start(t)
	code, _, stderr := errand(t, trusting(t, s), "", "check", "ghost")
	t.Logf("stderr: %s", stderr)
	if code != 250 || !strings.Contains(stderr, `"ghost"`) {
		t.Errorf("code=%d, want 250 naming the alias; stderr=%q", code, stderr)
	}
}

// jsonEnvelope is SPEC section 6's object as a caller reads it back.
type jsonEnvelope struct {
	V           int     `json:"v"`
	Host        string  `json:"host"`
	Command     string  `json:"command"`
	Status      string  `json:"status"`
	ExitCode    int     `json:"exit_code"`
	Signal      *string `json:"signal"`
	DurationMS  int64   `json:"duration_ms"`
	ConnectMS   int64   `json:"connect_ms"`
	StdoutBytes int64   `json:"stdout_bytes"`
	StderrBytes int64   `json:"stderr_bytes"`
	Truncated   bool    `json:"truncated"`
	Error       *struct {
		Kind    string `json:"kind"`
		Message string `json:"message"`
	} `json:"error"`
}

// splitEnvelope takes stdout apart the way "tail -n 1 | jq" does, and returns
// everything before the final line alongside the parsed envelope.
func splitEnvelope(t *testing.T, stdout string) (string, jsonEnvelope) {
	t.Helper()
	trimmed := strings.TrimSuffix(stdout, "\n")
	before, last := "", trimmed
	if i := strings.LastIndex(trimmed, "\n"); i >= 0 {
		before, last = trimmed[:i+1], trimmed[i+1:]
	}
	var env jsonEnvelope
	if err := json.Unmarshal([]byte(last), &env); err != nil {
		t.Fatalf("the final stdout line is not the envelope: %v\nline: %q", err, last)
	}
	if env.V != 1 {
		t.Errorf("v = %d, want 1", env.V)
	}
	return before, env
}

// TestIntegrationRunJSONEnvelope is the acceptance table: one real failure of
// each kind, plus a success, each read back the way a caller would.
func TestIntegrationRunJSONEnvelope(t *testing.T) {
	s := sshtest.Start(t)
	trust := trusting(t, s)
	cases := []struct {
		name   string
		cfg    string
		args   []string
		status string
		code   int
		kind   string
	}{
		{
			"success", trust,
			[]string{"--", "echo hi; exit 3"}, "ok", 3, "",
		},
		{
			"auth failure",
			writeConfig(t, s, hostConfig{knownHosts: s.KnownHostsLine() + "\n", identities: []string{s.RejectedKey.Path}}),
			[]string{"--", "true"}, "client_error", 252, "auth",
		},
		{
			"hostkey failure",
			writeConfig(t, s, hostConfig{}),
			[]string{"--", "true"}, "client_error", 251, "hostkey",
		},
		{
			"network failure",
			writeConfig(t, s, hostConfig{knownHosts: s.KnownHostsLine() + "\n", port: closedPort(t)}),
			[]string{"--", "true"}, "client_error", 253, "network",
		},
		{
			"timeout", trust,
			[]string{"--timeout", "1s", "--", "sleep 30"}, "timeout", 254, "timeout",
		},
		{
			// The trailing sleep keeps the remote alive past the breach, so the
			// verdict is the cap's rather than a race with the remote's exit.
			"truncated", trust,
			[]string{"--max-output", "1KiB", "--", "head -c 5000 /dev/zero; sleep 1"}, "truncated", 254, "truncated",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			args := append([]string{"run", "h", "--json"}, c.args...)
			code, stdout, stderr := errand(t, c.cfg, "", args...)
			t.Logf("exit %d, stderr: %s", code, stderr)
			before, env := splitEnvelope(t, stdout)
			if code != c.code {
				t.Errorf("code=%d, want %d", code, c.code)
			}
			if env.ExitCode != code {
				t.Errorf("exit_code=%d, want the process exit code %d", env.ExitCode, code)
			}
			if env.Status != c.status {
				t.Errorf("status=%q, want %q", env.Status, c.status)
			}
			if env.Host != "h" {
				t.Errorf("host=%q, want %q", env.Host, "h")
			}
			switch {
			case c.kind == "" && env.Error != nil:
				t.Errorf("error=%+v, want null for an ok run", env.Error)
			case c.kind != "" && (env.Error == nil || env.Error.Kind != c.kind):
				t.Errorf("error=%+v, want kind %q", env.Error, c.kind)
			}
			switch c.name {
			case "success":
				if before != "hi\n" || env.StdoutBytes != 3 || env.StderrBytes != 0 {
					t.Errorf("stdout before the envelope=%q with %d/%d bytes counted, want %q and 3/0",
						before, env.StdoutBytes, env.StderrBytes, "hi\n")
				}
				if env.Command != "echo hi; exit 3" {
					t.Errorf("command=%q", env.Command)
				}
			case "truncated":
				if !env.Truncated {
					t.Error("truncated=false, want true")
				}
				if n := env.StdoutBytes + env.StderrBytes; n != 1024 {
					t.Errorf("counted %d bytes across both streams, want the 1024-byte cap", n)
				}
				if delivered := int64(len(before)); delivered != env.StdoutBytes+1 {
					t.Errorf("delivered %d stdout bytes before the envelope, want %d plus the separating newline",
						delivered, env.StdoutBytes)
				}
			default:
				if before != "" {
					t.Errorf("stdout before the envelope=%q, want nothing", before)
				}
			}
			if c.kind != "truncated" && env.Truncated {
				t.Error("truncated=true, want false")
			}
		})
	}
}

// TestIntegrationRunJSONCancelled is the one case that needs a signal, so it
// cannot join the table above.
func TestIntegrationRunJSONCancelled(t *testing.T) {
	s := sshtest.Start(t)
	cmd, stdout, stderr := startErrand(t, trusting(t, s), "run", "h", "--json", "--", "echo started; sleep 30")
	if err := cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	// Read to EOF before Wait, which closes the pipe out from under us.
	rest, err := io.ReadAll(stdout)
	if err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	code := cmd.ProcessState.ExitCode()
	t.Logf("exit %d after SIGINT, stdout tail %q, stderr: %s", code, rest, stderr)
	before, env := splitEnvelope(t, string(rest))
	if code != 130 || env.ExitCode != 130 || env.Status != "cancelled" {
		t.Errorf("code=%d envelope exit_code=%d status=%q, want 130 and cancelled", code, env.ExitCode, env.Status)
	}
	if env.Error == nil || env.Error.Kind != "cancelled" {
		t.Errorf("error=%+v, want kind cancelled", env.Error)
	}
	if before != "" {
		t.Errorf("stdout between the output and the envelope=%q, want nothing", before)
	}
}

// TestIntegrationRunJSONFinalLineIsAlwaysParseable is SPEC section 6's sharp
// edge end to end: the envelope is separated from output that did not end in a
// newline, and only from that.
func TestIntegrationRunJSONFinalLineIsAlwaysParseable(t *testing.T) {
	s := sshtest.Start(t)
	cfg := trusting(t, s)
	cases := []struct {
		command string
		before  string
		bytes   int64
	}{
		{"printf nonl", "nonl\n", 4},
		{"echo hi", "hi\n", 3},
	}
	for _, c := range cases {
		t.Run(c.command, func(t *testing.T) {
			code, stdout, stderr := errand(t, cfg, "", "run", "h", "--json", "--", c.command)
			if code != 0 {
				t.Fatalf("code=%d, want 0; stderr=%q", code, stderr)
			}
			before, env := splitEnvelope(t, stdout)
			if before != c.before {
				t.Errorf("stdout before the envelope=%q, want %q", before, c.before)
			}
			if strings.Contains(stdout, "\n\n") {
				t.Errorf("a blank line separates the output from the envelope: %q", stdout)
			}
			if env.StdoutBytes != c.bytes {
				t.Errorf("stdout_bytes=%d, want the %d the remote delivered", env.StdoutBytes, c.bytes)
			}
		})
	}
}

func TestIntegrationCheckJSON(t *testing.T) {
	s := sshtest.Start(t)
	code, stdout, stderr := errand(t, trusting(t, s), "", "check", "h", "--json")
	if code != 0 {
		t.Fatalf("code=%d, want 0; stderr=%q", code, stderr)
	}
	before, env := splitEnvelope(t, stdout)
	if before != "" || env.Status != "ok" || env.ExitCode != 0 || env.Error != nil {
		t.Errorf("stdout=%q envelope=%+v, want the envelope alone, ok and 0", stdout, env)
	}
	if env.Command != "true" || env.ConnectMS < 0 {
		t.Errorf("command=%q connect_ms=%d", env.Command, env.ConnectMS)
	}
}

// auditRecord is the audit line read back the way an operator's jq would.
type auditRecord struct {
	TS          string `json:"ts"`
	Op          string `json:"op"`
	Host        string `json:"host"`
	Target      string `json:"target"`
	Command     string `json:"command"`
	Status      string `json:"status"`
	Kind        string `json:"kind"`
	ExitCode    int    `json:"exit_code"`
	DurationMS  int64  `json:"duration_ms"`
	ConnectMS   int64  `json:"connect_ms"`
	StdoutBytes int64  `json:"stdout_bytes"`
	StderrBytes int64  `json:"stderr_bytes"`
	Truncated   bool   `json:"truncated"`
	Error       string `json:"error"`
}

// auditLog reads the log writeConfig placed beside cfg, returning the parsed
// records and the raw file.
func auditLog(t *testing.T, cfg string) ([]auditRecord, string) {
	t.Helper()
	raw := readFile(t, filepath.Join(filepath.Dir(cfg), "audit.jsonl"))
	var records []auditRecord
	for _, line := range strings.Split(strings.TrimSuffix(raw, "\n"), "\n") {
		var r auditRecord
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("audit line is not JSON: %v\nline: %q", err, line)
		}
		records = append(records, r)
	}
	return records, raw
}

// TestIntegrationAuditRecordsARun is the acceptance case: the fields SPEC §10
// names, and the output the log must not have seen. The command assembles the
// secret rather than naming it, because the command string is itself a logged
// field: finding SECRETOUTPUT in the file can then only mean output was logged.
func TestIntegrationAuditRecordsARun(t *testing.T) {
	s := sshtest.Start(t)
	cfg := trusting(t, s)
	const command = "s=SECRET; echo ${s}OUTPUT"
	code, stdout, stderr := errand(t, cfg, "", "run", "h", "--", command)
	if code != 0 || stdout != "SECRETOUTPUT\n" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}

	records, raw := auditLog(t, cfg)
	if len(records) != 1 {
		t.Fatalf("log has %d lines after one run, want 1:\n%s", len(records), raw)
	}
	got := records[0]
	want := auditRecord{
		Op: "run", Host: "h", Target: fmt.Sprintf("root@127.0.0.1:%d", s.Port),
		Command: command, Status: "ok", ExitCode: 0, StdoutBytes: 13,
		DurationMS: got.DurationMS, ConnectMS: got.ConnectMS, TS: got.TS,
	}
	if got != want {
		t.Errorf("record = %+v\nwant     %+v", got, want)
	}
	if _, err := time.Parse(time.RFC3339, got.TS); err != nil {
		t.Errorf("ts %q is not RFC 3339: %v", got.TS, err)
	}
	if !strings.HasSuffix(got.TS, "Z") {
		t.Errorf("ts %q is not UTC", got.TS)
	}
	if got.DurationMS <= 0 || got.ConnectMS <= 0 {
		t.Errorf("duration_ms=%d connect_ms=%d, want both timed", got.DurationMS, got.ConnectMS)
	}
	if strings.Contains(raw, "SECRETOUTPUT") {
		t.Errorf("the remote's output reached the log:\n%s", raw)
	}

	if code, _, stderr := errand(t, cfg, "", "run", "h", "--", "true"); code != 0 {
		t.Fatalf("second run: code=%d stderr=%q", code, stderr)
	}
	records, raw = auditLog(t, cfg)
	if len(records) != 2 || records[0] != got {
		t.Errorf("a second run did not append after the first:\n%s", raw)
	}
}

// TestIntegrationAuditRecordsEveryOutcome is issue #10's second criterion: a
// run that ended badly is exactly the one an operator comes to the log for.
func TestIntegrationAuditRecordsEveryOutcome(t *testing.T) {
	s := sshtest.Start(t)
	cases := []struct {
		name   string
		trust  bool
		args   []string
		status string
		kind   string
	}{
		{"timeout", true, []string{"--timeout", "1s", "--", "sleep 30"}, "timeout", "timeout"},
		{"truncated", true, []string{"--max-output", "64KiB", "--", "yes"}, "truncated", "truncated"},
		{"hostkey", false, []string{"--", "true"}, "client_error", "hostkey"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := writeConfig(t, s, hostConfig{})
			if c.trust {
				cfg = trusting(t, s)
			}
			code, _, _ := errand(t, cfg, "", append([]string{"run", "h"}, c.args...)...)
			records, raw := auditLog(t, cfg)
			if len(records) != 1 {
				t.Fatalf("log has %d lines, want 1:\n%s", len(records), raw)
			}
			got := records[0]
			if got.Status != c.status || got.Kind != c.kind {
				t.Errorf("status=%q kind=%q, want %q and %q", got.Status, got.Kind, c.status, c.kind)
			}
			if got.ExitCode != code {
				t.Errorf("logged exit_code %d, want the %d errand exited with", got.ExitCode, code)
			}
			if got.Error == "" {
				t.Errorf("a %s line carries no error message: %s", c.status, raw)
			}
			if got.Op != "run" || got.Host != "h" {
				t.Errorf("op=%q host=%q, want run and h", got.Op, got.Host)
			}
		})
	}
}

func TestIntegrationAuditRecordsCancellation(t *testing.T) {
	s := sshtest.Start(t)
	cfg := trusting(t, s)
	cmd, _, stderr := startErrand(t, cfg, "run", "h", "--", "echo started; sleep 30")
	if err := cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	t.Logf("exit %d after SIGINT, stderr: %s", cmd.ProcessState.ExitCode(), stderr)
	records, raw := auditLog(t, cfg)
	if len(records) != 1 || records[0].Status != "cancelled" || records[0].ExitCode != 130 {
		t.Errorf("log after SIGINT:\n%s", raw)
	}
}

// TestIntegrationAuditUnwritablePathWarns is SPEC §10's "not fatal": the log
// path leads through a regular file, so no directory can be made for it.
func TestIntegrationAuditUnwritablePathWarns(t *testing.T) {
	s := sshtest.Start(t)
	blocker := sshtest.WriteFile(t, t.TempDir(), "not-a-directory", "")
	cfg := writeConfig(t, s, hostConfig{
		knownHosts: s.KnownHostsLine() + "\n",
		auditLog:   filepath.Join(blocker, "audit.jsonl"),
	})
	code, stdout, stderr := errand(t, cfg, "", "run", "h", "--", "echo hi; exit 7")
	t.Logf("exit %d, stderr: %s", code, stderr)
	if code != 7 {
		t.Errorf("code=%d, want the remote's own 7: a log failure is not fatal", code)
	}
	if stdout != "hi\n" {
		t.Errorf("stdout=%q, want the remote's output regardless", stdout)
	}
	if !strings.Contains(stderr, "errand: audit:") {
		t.Errorf("stderr=%q, want an audit warning", stderr)
	}
}

// TestIntegrationAuditRecordsCheck covers the other half of "every operation":
// a preflight reached a host and sent it a command, so it is recorded too.
func TestIntegrationAuditRecordsCheck(t *testing.T) {
	s := sshtest.Start(t)
	cfg := trusting(t, s)
	if code, _, stderr := errand(t, cfg, "", "check", "h"); code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
	records, raw := auditLog(t, cfg)
	if len(records) != 1 || records[0].Op != "check" || records[0].Status != "ok" || records[0].Command != "true" {
		t.Errorf("check did not record itself:\n%s", raw)
	}
}

// remoteDir gives each test its own directory under the container's /tmp, so
// the tests sharing the one sshd cannot collide on a destination.
func remoteDir(t *testing.T, cfg string) string {
	t.Helper()
	dir := "/tmp/" + strings.ReplaceAll(t.Name(), "/", "_")
	remote(t, cfg, "rm -rf "+dir+" && mkdir -p "+dir)
	return dir
}

// remote runs one command on the harness and returns its trimmed stdout.
func remote(t *testing.T, cfg, command string) string {
	t.Helper()
	code, stdout, stderr := errand(t, cfg, "", "run", "h", "--", command)
	if code != 0 {
		t.Fatalf("%q: exit %d, stderr: %s", command, code, stderr)
	}
	return strings.TrimSpace(stdout)
}

// payload writes n bytes of incompressible filler and returns the path and its
// checksum, so a round trip is checked against the source rather than against
// another copy of the same bytes.
func payload(t *testing.T, n int) (path, sum string) {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(t.TempDir(), "payload")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(b)
	return path, hex.EncodeToString(h[:])
}

// TestIntegrationPutRoundTrip is the acceptance case: the bytes that arrive are
// the bytes that left, the second put replaces the first, and the audit line
// carries the transfer paths where a run carries its command.
func TestIntegrationPutRoundTrip(t *testing.T) {
	s := sshtest.Start(t)
	cfg := trusting(t, s)
	dir := remoteDir(t, cfg)
	dst := dir + "/file"

	const size = 1 << 20
	local, sum := payload(t, size)
	start := time.Now()
	code, stdout, stderr := errand(t, cfg, "", "put", "h", local, dst)
	took := time.Since(start)
	if code != 0 || stdout != "" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	t.Logf("%d bytes in %v (%.1f MiB/s including connect)", size, took, float64(size)/(1<<20)/took.Seconds())
	if got := remote(t, cfg, "sha256sum "+dst); !strings.HasPrefix(got, sum) {
		t.Errorf("remote sha256 = %q, want %s", got, sum)
	}
	if got := remote(t, cfg, "ls -A "+dir); got != "file" {
		t.Errorf("ls -A %s = %q, want just the destination", dir, got)
	}

	second, sum2 := payload(t, 4096)
	if code, _, stderr := errand(t, cfg, "", "put", "h", second, dst); code != 0 {
		t.Fatalf("second put: code=%d stderr=%q", code, stderr)
	}
	if got := remote(t, cfg, "sha256sum "+dst); !strings.HasPrefix(got, sum2) {
		t.Errorf("after replacing, remote sha256 = %q, want %s", got, sum2)
	}

	records, raw := auditLog(t, cfg)
	i := slices.IndexFunc(records, func(r auditRecord) bool { return r.Op == "put" })
	if i < 0 {
		t.Fatalf("no put in the audit log:\n%s", raw)
	}
	rec := records[i]
	switch {
	case rec.Op != "put":
		t.Errorf("audit op = %q, want put", rec.Op)
	case rec.Command != local+" "+dst:
		t.Errorf("audit command = %q, want the transfer paths", rec.Command)
	case rec.Status != "ok" || rec.ExitCode != 0:
		t.Errorf("audit status=%q exit_code=%d", rec.Status, rec.ExitCode)
	case rec.StdoutBytes != size:
		t.Errorf("audit stdout_bytes = %d, want %d", rec.StdoutBytes, size)
	}
	if t.Failed() {
		t.Logf("audit log:\n%s", raw)
	}
}

func TestIntegrationPutMode(t *testing.T) {
	s := sshtest.Start(t)
	cfg := trusting(t, s)
	for _, tc := range []struct{ flag, want string }{
		{"", "644"},
		{"0755", "755"},
		{"600", "600"},
	} {
		t.Run("mode "+tc.flag, func(t *testing.T) {
			dir := remoteDir(t, cfg)
			local, _ := payload(t, 64)
			args := []string{"put", "h"}
			if tc.flag != "" {
				args = append(args, "--mode", tc.flag)
			}
			args = append(args, local, dir+"/file")
			if code, _, stderr := errand(t, cfg, "", args...); code != 0 {
				t.Fatalf("code=%d stderr=%q", code, stderr)
			}
			if got := remote(t, cfg, "stat -c %a "+dir+"/file"); got != tc.want {
				t.Errorf("remote mode = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestIntegrationPutOverMaxSize checks the rejection happens before the
// connection is used for anything: nothing at all appears in the destination.
func TestIntegrationPutOverMaxSize(t *testing.T) {
	s := sshtest.Start(t)
	cfg := trusting(t, s)
	dir := remoteDir(t, cfg)
	local, _ := payload(t, 1<<20)
	code, _, stderr := errand(t, cfg, "", "put", "h", "--max-size", "512KiB", local, dir+"/file")
	if code != 250 {
		t.Fatalf("code=%d, want 250; stderr=%q", code, stderr)
	}
	if !strings.Contains(stderr, "--max-size") || !strings.Contains(stderr, "1048576") {
		t.Errorf("stderr=%q, want the size and the flag that rejected it", stderr)
	}
	if got := remote(t, cfg, "ls -A "+dir); got != "" {
		t.Errorf("ls -A %s = %q, want nothing", dir, got)
	}
}

func TestIntegrationPutFailures(t *testing.T) {
	s := sshtest.Start(t)
	cfg := trusting(t, s)
	dir := remoteDir(t, cfg)
	local, _ := payload(t, 64)
	for _, tc := range []struct {
		name, local, remote string
		code                int
		want                string
	}{
		{"missing local file", filepath.Join(t.TempDir(), "absent"), dir + "/file", 250, "usage"},
		{"local is a directory", t.TempDir(), dir + "/file", 250, "usage"},
		{"missing remote directory", local, dir + "/absent/file", 253, "transfer"},
		{"unwritable remote path", local, "/proc/nope/file", 253, "transfer"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, _, stderr := errand(t, cfg, "", "put", "h", tc.local, tc.remote)
			if code != tc.code {
				t.Fatalf("code=%d, want %d; stderr=%q", code, tc.code, stderr)
			}
			if !strings.Contains(stderr, "errand: h: "+tc.want+": ") {
				t.Errorf("stderr=%q, want a %s phase", stderr, tc.want)
			}
		})
	}
	if got := remote(t, cfg, "ls -A "+dir); got != "" {
		t.Errorf("ls -A %s = %q, want nothing", dir, got)
	}
}

// TestIntegrationPutInterrupted is the half of the guarantee that matters: a
// transfer cut mid-flight leaves nothing under the final name. The temp file is
// unlinked in the same window where possible, which over loopback it is; the
// test records what the destination actually holds either way.
func TestIntegrationPutInterrupted(t *testing.T) {
	s := sshtest.Start(t)
	cfg := trusting(t, s)
	dir := remoteDir(t, cfg)
	local := sparsePayload(t, interruptSize)

	start := time.Now()
	code, stdout, stderr := errand(t, cfg, "", "put", "h", "--json",
		"--max-size", "600MiB", "--timeout", interruptAfter.String(), local, dir+"/file")
	took := time.Since(start)
	_, env := splitEnvelope(t, stdout)
	t.Logf("cut after %d of %d bytes (%.0f%%) in %v", env.StdoutBytes, interruptSize,
		100*float64(env.StdoutBytes)/interruptSize, took)
	if code != 254 || env.Status != "timeout" {
		t.Fatalf("code=%d status=%q, want 254 and timeout (a %d-byte put should not finish in %v); stderr=%q",
			code, env.Status, interruptSize, interruptAfter, stderr)
	}
	if !strings.Contains(stderr, "timeout") {
		t.Errorf("stderr=%q, want a timeout diagnostic", stderr)
	}
	// Without this the test would still pass if the cut landed during the
	// handshake, having proved nothing about a transfer in flight.
	if env.StdoutBytes <= 0 || env.StdoutBytes >= interruptSize {
		t.Fatalf("cut after %d bytes, want a cut partway through %d", env.StdoutBytes, interruptSize)
	}
	if took > interruptAfter+5*time.Second {
		t.Errorf("took %v, want the budget plus a bounded teardown", took)
	}
	left := remote(t, cfg, "ls -A "+dir)
	t.Logf("after the cut, ls -A %s = %q", dir, left)
	if strings.Contains(left, "\nfile") || left == "file" {
		t.Errorf("the final name survives a cut transfer: ls -A = %q", left)
	}
	if left != "" {
		t.Errorf("the temp file survives a cut transfer: ls -A = %q", left)
	}
}

// interruptSize and interruptAfter are measured, not guessed. Loopback to the
// container moves about 380 MiB/s, so 512 MiB is well over a second of
// transfer and the cut lands around a third of the way in. The margin is
// deliberately wide: the way this test goes wrong is a machine fast enough to
// finish before the budget, and the assertion on the byte count catches the
// opposite mistake of cutting before the transfer began.
const (
	interruptSize  = 512 << 20
	interruptAfter = 500 * time.Millisecond
)

// sparsePayload is a file of that many zero bytes that costs nothing to create
// and nothing to read: the transfer still has to move every one of them.
func sparsePayload(t *testing.T, n int64) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "payload")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(n); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}
