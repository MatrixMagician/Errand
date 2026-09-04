package sshtest

import (
	"bytes"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestKnownHostsLines(t *testing.T) {
	host, err := newKey(t.TempDir(), "host_key")
	if err != nil {
		t.Fatalf("newKey: %v", err)
	}
	s := &Server{Addr: "127.0.0.1:2222", Port: 2222, HostKey: host.Public}

	const prefix = "[127.0.0.1]:2222 "
	line := s.KnownHostsLine()
	if !strings.HasPrefix(line, prefix) {
		t.Errorf("KnownHostsLine() = %q, want prefix %q", line, prefix)
	}
	if strings.Contains(line, "\n") {
		t.Errorf("KnownHostsLine() = %q, want a single line", line)
	}
	if got := parseKey(t, line); !sameKey(got, host.Public) {
		t.Errorf("KnownHostsLine() key = %v, want the host key", got.Type())
	}

	wrong := s.WrongKnownHostsLine()
	if !strings.HasPrefix(wrong, prefix) {
		t.Errorf("WrongKnownHostsLine() = %q, want prefix %q", wrong, prefix)
	}
	if sameKey(parseKey(t, wrong), host.Public) {
		t.Error("WrongKnownHostsLine() carries the real host key")
	}
	if again := s.WrongKnownHostsLine(); again != wrong {
		t.Errorf("WrongKnownHostsLine() = %q on the second call, want %q", again, wrong)
	}
}

func parseKey(t *testing.T, line string) ssh.PublicKey {
	t.Helper()
	_, hosts, key, _, _, err := ssh.ParseKnownHosts([]byte(line))
	if err != nil {
		t.Fatalf("ParseKnownHosts(%q): %v", line, err)
	}
	if len(hosts) != 1 {
		t.Fatalf("ParseKnownHosts(%q) hosts = %v, want one", line, hosts)
	}
	return key
}

func sameKey(a, b ssh.PublicKey) bool {
	return bytes.Equal(a.Marshal(), b.Marshal())
}
