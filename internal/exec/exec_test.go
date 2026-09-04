package exec

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/MatrixMagician/Errand/internal/client"
	"github.com/MatrixMagician/Errand/internal/config"
	"github.com/MatrixMagician/Errand/internal/result"
	"github.com/MatrixMagician/Errand/internal/sshtest"
)

func TestCounterIsExact(t *testing.T) {
	var sink strings.Builder
	c := &counter{w: &sink}
	for _, s := range []string{"", "one", "two\n", strings.Repeat("x", 5000)} {
		if _, err := c.Write([]byte(s)); err != nil {
			t.Fatal(err)
		}
	}
	if want := int64(sink.Len()); c.n.Load() != want {
		t.Errorf("counted %d bytes, wrote %d", c.n.Load(), want)
	}
	if c.n.Load() != 5007 {
		t.Errorf("counted %d, want 5007", c.n.Load())
	}
}

func TestFromWait(t *testing.T) {
	remote, err := fromWait("h", nil)
	if err != nil || remote == nil || remote.Exit != 0 {
		t.Errorf("clean exit: remote=%+v err=%v", remote, err)
	}
	remote, err = fromWait("h", errors.New("connection lost"))
	var phased *result.Error
	if remote != nil || !errors.As(err, &phased) || phased.Phase != result.Exec {
		t.Errorf("lost connection: remote=%+v err=%v", remote, err)
	}
}

// TestRunTimeoutTeardownIsBounded drives the real teardown in-process, so the
// race detector covers the copiers, the Wait goroutine and the byte counters
// that a subprocess integration test leaves uninstrumented.
func TestRunTimeoutTeardownIsBounded(t *testing.T) {
	s := sshtest.Start(t)
	t.Setenv("SSH_AUTH_SOCK", "")
	dir := t.TempDir()
	h := config.Host{
		Alias: "h", Hostname: "127.0.0.1", Port: s.Port, User: "root",
		KnownHosts:    []string{sshtest.WriteFile(t, dir, "known_hosts", s.KnownHostsLine()+"\n")},
		IdentityFiles: []string{s.ClientKey.Path},
	}
	conn, err := client.Dial(context.Background(), h, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	ctx, cancel := context.WithTimeoutCause(context.Background(), 300*time.Millisecond, result.ErrTimeout)
	defer cancel()
	start := time.Now()
	r := Run(ctx, conn, Request{Command: "echo out; sleep 30"})
	took := time.Since(start)
	t.Logf("Run returned in %v: err=%v stdout=%d bytes", took, r.Err, r.StdoutBytes)

	if !errors.Is(r.Err, result.ErrTimeout) {
		t.Errorf("err=%v, want a timeout", r.Err)
	}
	if r.StdoutBytes != int64(len("out\n")) {
		t.Errorf("counted %d stdout bytes, want %d: the copiers had not finished", r.StdoutBytes, len("out\n"))
	}
	if want := killGrace + teardownGrace + flushGrace; took > 300*time.Millisecond+want {
		t.Errorf("took %v, want the budget plus at most %v of teardown", took, want)
	}
}
