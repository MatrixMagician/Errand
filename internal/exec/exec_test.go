package exec

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MatrixMagician/Errand/internal/client"
	"github.com/MatrixMagician/Errand/internal/config"
	"github.com/MatrixMagician/Errand/internal/result"
	"github.com/MatrixMagician/Errand/internal/sshtest"
)

// TestCapIsExactAcrossTwoStreams races both writers against one budget, which
// is the only place the cap can be off by a chunk.
func TestCapIsExactAcrossTwoStreams(t *testing.T) {
	const max, chunk, writes = 1000, 7, 200
	lim := newLimiter(max)
	var outSink, errSink bytes.Buffer
	out := &capWriter{w: &outSink, lim: lim}
	errOut := &capWriter{w: &errSink, lim: lim}

	var wg sync.WaitGroup
	for _, w := range []*capWriter{out, errOut} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range writes {
				n, err := w.Write(bytes.Repeat([]byte("x"), chunk))
				if n != chunk || err != nil {
					t.Errorf("Write = %d, %v; want %d, nil so the copier keeps draining", n, err, chunk)
					return
				}
			}
		}()
	}
	wg.Wait()

	if delivered := outSink.Len() + errSink.Len(); delivered != max {
		t.Errorf("delivered %d bytes across both streams, want exactly %d", delivered, max)
	}
	if out.n.Load() != int64(outSink.Len()) || errOut.n.Load() != int64(errSink.Len()) {
		t.Errorf("counts %d/%d disagree with the sinks %d/%d", out.n.Load(), errOut.n.Load(), outSink.Len(), errSink.Len())
	}
	select {
	case <-lim.breached:
	default:
		t.Errorf("wrote %d bytes against a cap of %d without breaching", 2*writes*chunk, max)
	}
}

// TestCapSwallowsWritesAfterTheBreach also proves the breach fires once: a
// second close of the channel would panic.
func TestCapSwallowsWritesAfterTheBreach(t *testing.T) {
	lim := newLimiter(4)
	var sink bytes.Buffer
	w := &capWriter{w: &sink, lim: lim}
	for _, s := range []string{"ab", "cdef", "gh", "", strings.Repeat("i", 5000)} {
		if n, err := w.Write([]byte(s)); n != len(s) || err != nil {
			t.Fatalf("Write(%d bytes) = %d, %v; want %d, nil", len(s), n, err, len(s))
		}
	}
	if sink.String() != "abcd" {
		t.Errorf("sink holds %q, want %q", sink.String(), "abcd")
	}
	if w.n.Load() != 4 {
		t.Errorf("counted %d, want 4", w.n.Load())
	}
}

func TestCapZeroNeverBreaches(t *testing.T) {
	lim := newLimiter(0)
	var sink bytes.Buffer
	w := &capWriter{w: &sink, lim: lim}
	for range 100 {
		if _, err := w.Write(bytes.Repeat([]byte("y"), 10000)); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-lim.breached:
		t.Error("an unlimited cap breached")
	default:
	}
	if w.n.Load() != 1_000_000 || sink.Len() != 1_000_000 {
		t.Errorf("counted %d into a %d-byte sink, want 1000000", w.n.Load(), sink.Len())
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
	conn := dialHarness(t)
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

// TestRunCapTeardownIsBounded is the cap's counterpart: the race detector sees
// the breach channel, the capping writers and the teardown that reads them.
func TestRunCapTeardownIsBounded(t *testing.T) {
	conn := dialHarness(t)
	start := time.Now()
	r := Run(context.Background(), conn, Request{Command: "yes; sleep 30", MaxOutput: 4096})
	took := time.Since(start)
	t.Logf("Run returned in %v: err=%v remote=%+v stdout=%d bytes", took, r.Err, r.Remote, r.StdoutBytes)

	if !errors.Is(r.Err, result.ErrTruncated) {
		t.Errorf("err=%v, want a truncation", r.Err)
	}
	if r.StdoutBytes+r.StderrBytes != 4096 {
		t.Errorf("delivered %d+%d bytes, want exactly the 4096-byte cap", r.StdoutBytes, r.StderrBytes)
	}
	if r.ExitCode() != 254 {
		t.Errorf("exit %d, want 254: the remote never exited on its own", r.ExitCode())
	}
	if want := killGrace + teardownGrace + flushGrace; took > want {
		t.Errorf("took %v, want at most %v of teardown", took, want)
	}
}

// dialHarness connects to a throwaway sshd with the developer's agent kept out
// of it, so only the harness key can authenticate.
func dialHarness(t *testing.T) *client.Conn {
	t.Helper()
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
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}
