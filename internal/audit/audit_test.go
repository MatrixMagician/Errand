package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MatrixMagician/Errand/internal/result"
)

// at is a timestamp an hour east of UTC, so an exact match proves the record
// is normalised rather than written in whatever zone the operator sits in.
var at = time.Date(2024, 5, 6, 7, 8, 9, 0, time.FixedZone("CEST", 3600))

// TestAppendWritesTheLine compares whole lines. An exact match is also what
// proves the negative SPEC §10 cares about: a field carrying output bytes
// could not appear without failing these.
func TestAppendWritesTheLine(t *testing.T) {
	cases := []struct {
		name string
		r    result.Result
		want string
	}{
		{
			"ok",
			result.Result{
				Op: "run", Host: "web", Target: "root@10.0.0.1:22", Command: "uptime",
				Remote:  &result.Remote{Exit: 0},
				Connect: 40 * time.Millisecond, Elapsed: 250 * time.Millisecond,
				StdoutBytes: 62, StderrBytes: 0,
			},
			`{"ts":"2024-05-06T06:08:09Z","op":"run","host":"web","target":"root@10.0.0.1:22","command":"uptime","status":"ok","exit_code":0,"duration_ms":250,"connect_ms":40,"stdout_bytes":62,"stderr_bytes":0,"truncated":false}`,
		},
		{
			"timeout",
			result.Result{
				Op: "run", Host: "web", Target: "root@10.0.0.1:22", Command: "sleep 30 > /tmp/x",
				Err:     result.ErrTimeout,
				Connect: 40 * time.Millisecond, Elapsed: 2 * time.Second,
				StdoutBytes: 5, StderrBytes: 1,
			},
			`{"ts":"2024-05-06T06:08:09Z","op":"run","host":"web","target":"root@10.0.0.1:22","command":"sleep 30 > /tmp/x","status":"timeout","kind":"timeout","exit_code":254,"duration_ms":2000,"connect_ms":40,"stdout_bytes":5,"stderr_bytes":1,"truncated":false,"error":"timeout after 2s"}`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state", "audit.jsonl")
			if err := Append(path, at, c.r); err != nil {
				t.Fatalf("Append: %v", err)
			}
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if got := string(b); got != c.want+"\n" {
				t.Errorf("line =\n%s\nwant\n%s\n", got, c.want)
			}
		})
	}
}

func TestAppendCreatesThemPrivately(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	path := filepath.Join(dir, "audit.jsonl")
	if err := Append(path, at, result.Result{Op: "run"}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	for _, c := range []struct {
		path string
		want os.FileMode
	}{{dir, 0o700}, {path, 0o600}} {
		fi, err := os.Stat(c.path)
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode().Perm(); got != c.want {
			t.Errorf("%s mode = %o, want %o", c.path, got, c.want)
		}
	}
}

func TestAppendAddsToWhatIsThere(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	for range 3 {
		if err := Append(path, at, result.Result{Op: "run"}); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(b), "\n"); got != 3 {
		t.Errorf("log has %d lines after three appends, want 3:\n%s", got, b)
	}
}

func TestAppendReportsAnUnwritablePath(t *testing.T) {
	dir := t.TempDir()
	if err := Append(dir, at, result.Result{Op: "run"}); err == nil {
		t.Errorf("appending to the directory %s succeeded, want an error", dir)
	}
}
