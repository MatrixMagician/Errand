// Package sshtest gives integration tests a real OpenSSH server in a container
// plus the ephemeral keys, config files, and subprocess plumbing to drive the
// built errand binary against it. See SPEC.md §14.
package sshtest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

// Key is an ed25519 keypair written to disk in OpenSSH format.
type Key struct {
	Signer ssh.Signer
	Public ssh.PublicKey
	Path   string
}

// Server is the running sshd container shared by every test in a process.
type Server struct {
	Addr        string
	Port        int
	HostKey     ssh.PublicKey
	ClientKey   Key
	RejectedKey Key
	Dir         string

	runtime string
	name    string

	wrongOnce sync.Once
	wrongKey  ssh.PublicKey
}

// KnownHostsLine is the known_hosts entry that matches the server.
func (s *Server) KnownHostsLine() string {
	return knownHostsLine(s.Addr, s.HostKey)
}

// WrongKnownHostsLine is a known_hosts entry for the server's address carrying
// a different key: the "host key changed" state.
func (s *Server) WrongKnownHostsLine() string {
	s.wrongOnce.Do(func() {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
		s.wrongKey, err = ssh.NewPublicKey(pub)
		if err != nil {
			panic(err)
		}
	})
	return knownHostsLine(s.Addr, s.wrongKey)
}

func knownHostsLine(addr string, key ssh.PublicKey) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host, port = addr, "22"
	}
	return fmt.Sprintf("[%s]:%s %s", host, port, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))))
}

// WriteFile writes content into dir and returns the path.
func WriteFile(t testing.TB, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// newKey generates a keypair and writes the private half to dir/name.
func newKey(dir, name string) (Key, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Key{}, err
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return Key{}, err
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		return Key{}, err
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return Key{}, err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return Key{}, err
	}
	return Key{Signer: signer, Public: sshPub, Path: path}, nil
}

var binaryOnce = sync.OnceValues(buildBinary)

// Binary builds ./cmd/errand once per test process and returns the path.
func Binary(t testing.TB) string {
	t.Helper()
	path, err := binaryOnce()
	if err != nil {
		t.Fatalf("build errand: %v", err)
	}
	return path
}

func buildBinary() (string, error) {
	root, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}").Output()
	if err != nil {
		return "", fmt.Errorf("locate module root: %w", err)
	}
	dir, err := sharedDir()
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "errand")
	build := exec.Command("go", "build", "-o", path, "./cmd/errand")
	build.Dir = strings.TrimSpace(string(root))
	if out, err := build.CombinedOutput(); err != nil {
		return "", fmt.Errorf("go build: %v: %s", err, out)
	}
	return path, nil
}

// Run executes the binary with env appended to the process environment and
// returns its exit code and streams separately.
func Run(t testing.TB, bin string, env []string, stdin string, args ...string) (int, string, string) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdin = strings.NewReader(stdin)
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil && cmd.ProcessState == nil {
		t.Fatalf("run %s: %v", bin, err)
	}
	return cmd.ProcessState.ExitCode(), stdout.String(), stderr.String()
}
