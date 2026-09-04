package sshtest

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	image    = "errand-sshtest:local"
	label    = "errand-sshtest=1"
	readyFor = 60 * time.Second
)

const sshdConfig = `Port 22
HostKey /etc/errand/host_key
AuthorizedKeysFile /etc/errand/authorized_keys
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitRootLogin yes
AcceptEnv FOO
StrictModes no
LogLevel DEBUG
`

var errNoRuntime = errors.New("no container runtime (docker/podman) found")

var startOnce = sync.OnceValues(startServer)

// Start returns the sshd container shared by every test in this process. Tests
// skip when no container runtime is available, unless ERRAND_TEST_REQUIRE_CONTAINER=1.
func Start(t testing.TB) *Server {
	t.Helper()
	s, err := startOnce()
	switch {
	case errors.Is(err, errNoRuntime) && os.Getenv("ERRAND_TEST_REQUIRE_CONTAINER") != "1":
		t.Skipf("skipping: %v", err)
	case err != nil:
		t.Fatalf("start sshd container: %v", err)
	}
	return s
}

// Logs returns the container's combined output, for diagnosing auth failures.
func (s *Server) Logs(t testing.TB) string {
	t.Helper()
	out, err := exec.Command(s.runtime, "logs", s.name).CombinedOutput()
	if err != nil {
		t.Fatalf("%s logs %s: %v: %s", s.runtime, s.name, err, out)
	}
	return string(out)
}

func startServer() (*Server, error) {
	rt := detectRuntime()
	if rt == "" {
		return nil, errNoRuntime
	}
	root, err := sharedDir()
	if err != nil {
		return nil, err
	}
	// The container mount holds only what sshd reads; the built binary stays
	// in the parent, out of reach of the :Z relabelling below.
	dir := filepath.Join(root, "server")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Server{Dir: dir, runtime: rt, name: fmt.Sprintf("errand-sshtest-%d", os.Getpid())}
	if err := writeServerFiles(s); err != nil {
		return nil, err
	}

	build := exec.Command(rt, "build", "-q", "-t", image, filepath.Join(sourceDir(), "testdata"))
	if out, err := build.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("%s build: %v: %s", rt, err, out)
	}
	sweepStale(rt)

	// :Z relabels the mount for SELinux, without which sshd cannot read the keys.
	run := exec.Command(rt, "run", "-d", "--rm", "--name", s.name, "--label", label,
		"-p", "127.0.0.1::22", "-v", dir+":/etc/errand:Z", image)
	if out, err := run.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("%s run: %v: %s", rt, err, out)
	}
	reapOnExit(fmt.Sprintf("%s rm -f %s", rt, s.name))

	if s.Port, err = publishedPort(rt, s.name); err != nil {
		return nil, err
	}
	s.Addr = net.JoinHostPort("127.0.0.1", strconv.Itoa(s.Port))
	if err := waitReady(s.Addr); err != nil {
		return nil, err
	}
	return s, nil
}

func writeServerFiles(s *Server) error {
	host, err := newKey(s.Dir, "host_key")
	if err != nil {
		return err
	}
	s.HostKey = host.Public
	if s.ClientKey, err = newKey(s.Dir, "client_key"); err != nil {
		return err
	}
	if s.RejectedKey, err = newKey(s.Dir, "rejected_key"); err != nil {
		return err
	}
	files := map[string][]byte{
		"host_key.pub":    ssh.MarshalAuthorizedKey(host.Public),
		"authorized_keys": ssh.MarshalAuthorizedKey(s.ClientKey.Public),
		"sshd_config":     []byte(sshdConfig),
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(s.Dir, name), content, 0o600); err != nil {
			return err
		}
	}
	return nil
}

// sourceDir is this package's directory, so tests in other packages can still
// find testdata/Dockerfile.
func sourceDir() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Dir(file)
}

func detectRuntime() string {
	for _, rt := range []string{"docker", "podman"} {
		if _, err := exec.LookPath(rt); err != nil {
			continue
		}
		if exec.Command(rt, "info").Run() == nil {
			return rt
		}
	}
	return ""
}

// sweepStale drops containers left behind by test processes that were killed
// before their cleanup could run, so reruns converge.
func sweepStale(rt string) {
	out, err := exec.Command(rt, "ps", "-aq", "--filter", "label="+label, "--filter", "until=1h").Output()
	if err != nil {
		return
	}
	for _, id := range strings.Fields(string(out)) {
		_ = exec.Command(rt, "rm", "-f", id).Run()
	}
}

func publishedPort(rt, name string) (int, error) {
	out, err := exec.Command(rt, "port", name, "22").Output()
	if err != nil {
		return 0, fmt.Errorf("%s port: %w", rt, err)
	}
	line, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
	if i := strings.LastIndex(line, ":"); i >= 0 {
		return strconv.Atoi(line[i+1:])
	}
	return 0, fmt.Errorf("%s port %s 22: unexpected output %q", rt, name, out)
}

func waitReady(addr string) error {
	deadline := time.Now().Add(readyFor)
	for time.Now().Before(deadline) {
		if banner(addr) {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("sshd at %s did not answer within %s", addr, readyFor)
}

func banner(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return false
	}
	buf := make([]byte, len("SSH-2.0"))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return false
	}
	return string(buf) == "SSH-2.0"
}

var sharedDir = sync.OnceValues(func() (string, error) {
	dir, err := os.MkdirTemp("", "errand-sshtest-")
	if err != nil {
		return "", err
	}
	reapOnExit("rm -rf " + dir)
	return dir, nil
})

// reapOnExit runs cmd once this test process is gone. Go offers no process-exit
// hook without TestMain, and the container outlives any single test's cleanup.
func reapOnExit(cmd string) {
	script := fmt.Sprintf("while kill -0 %d 2>/dev/null; do sleep 0.1; done; %s", os.Getpid(), cmd)
	reaper := exec.Command("sh", "-c", script+" >/dev/null 2>&1")
	if err := reaper.Start(); err != nil {
		return
	}
	go func() { _ = reaper.Wait() }()
}
