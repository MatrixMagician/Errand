package main

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/MatrixMagician/Errand/internal/sshtest"
	"golang.org/x/crypto/ssh"
)

func TestIntegrationHosts(t *testing.T) {
	s := sshtest.Start(t)
	dir := t.TempDir()
	knownHosts := sshtest.WriteFile(t, dir, "known_hosts", s.KnownHostsLine()+"\n")
	cfg := sshtest.WriteFile(t, dir, "config.toml", fmt.Sprintf(`[defaults]
user           = "root"
known_hosts    = %q
identity_files = [%q]

[hosts.h]
hostname = "127.0.0.1"
port     = %d
`, knownHosts, s.ClientKey.Path, s.Port))

	code, stdout, stderr := sshtest.Run(t, sshtest.Binary(t), []string{"ERRAND_CONFIG=" + cfg}, "", "hosts")
	if code != 0 {
		t.Fatalf("errand hosts exited %d, stderr: %s", code, stderr)
	}
	for _, want := range []string{"h", "127.0.0.1", fmt.Sprint(s.Port)} {
		if !strings.Contains(stdout, want) {
			t.Errorf("errand hosts stdout missing %q:\n%s", want, stdout)
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
