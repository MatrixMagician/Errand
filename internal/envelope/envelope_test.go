package envelope

import (
	"bytes"
	"errors"
	"io"
	"syscall"
	"testing"
	"time"

	"github.com/MatrixMagician/Errand/internal/result"
)

// TestEncode pins the wire format itself: every status, the exit code and kind
// each one carries, and the exact bytes a caller's jq will see.
func TestEncode(t *testing.T) {
	cases := []struct {
		name string
		res  result.Result
		want string
	}{
		{
			"ok with an exit code",
			result.Result{
				Host: "web-prod", Command: "echo hi; exit 3",
				Remote:  &result.Remote{Exit: 3},
				Connect: 96 * time.Millisecond, Elapsed: 412 * time.Millisecond,
				StdoutBytes: 3,
			},
			`{"v":1,"host":"web-prod","command":"echo hi; exit 3","status":"ok","exit_code":3,"signal":null,"duration_ms":412,"connect_ms":96,"stdout_bytes":3,"stderr_bytes":0,"truncated":false,"error":null}`,
		},
		{
			"ok with a signalled remote",
			result.Result{
				Host: "h", Command: "kill -TERM $$",
				Remote: &result.Remote{Signal: "TERM"},
			},
			`{"v":1,"host":"h","command":"kill -TERM $$","status":"ok","exit_code":143,"signal":"TERM","duration_ms":0,"connect_ms":0,"stdout_bytes":0,"stderr_bytes":0,"truncated":false,"error":null}`,
		},
		{
			"usage",
			result.Result{Err: result.Usage.Wrap("", errors.New("run: missing <command>"))},
			`{"v":1,"host":"","command":"","status":"client_error","exit_code":250,"signal":null,"duration_ms":0,"connect_ms":0,"stdout_bytes":0,"stderr_bytes":0,"truncated":false,"error":{"kind":"usage","message":"usage: run: missing <command>"}}`,
		},
		{
			"config",
			result.Result{Host: "ghost", Err: result.Resolve.Wrap("ghost", errors.New(`unknown host "ghost"`))},
			`{"v":1,"host":"ghost","command":"","status":"client_error","exit_code":250,"signal":null,"duration_ms":0,"connect_ms":0,"stdout_bytes":0,"stderr_bytes":0,"truncated":false,"error":{"kind":"config","message":"ghost: resolve: unknown host \"ghost\""}}`,
		},
		{
			"hostkey",
			result.Result{Host: "h", Command: "true", Err: result.HostKey.Wrap("h", errors.New("host key changed"))},
			`{"v":1,"host":"h","command":"true","status":"client_error","exit_code":251,"signal":null,"duration_ms":0,"connect_ms":0,"stdout_bytes":0,"stderr_bytes":0,"truncated":false,"error":{"kind":"hostkey","message":"h: hostkey: host key changed"}}`,
		},
		{
			"auth",
			result.Result{Host: "h", Command: "true", Err: result.Auth.Wrap("h", errors.New("no supported methods remain"))},
			`{"v":1,"host":"h","command":"true","status":"client_error","exit_code":252,"signal":null,"duration_ms":0,"connect_ms":0,"stdout_bytes":0,"stderr_bytes":0,"truncated":false,"error":{"kind":"auth","message":"h: auth: no supported methods remain"}}`,
		},
		{
			"network",
			result.Result{Host: "h", Command: "true", Err: result.Connect.Wrap("h", errors.New("connection refused"))},
			`{"v":1,"host":"h","command":"true","status":"client_error","exit_code":253,"signal":null,"duration_ms":0,"connect_ms":0,"stdout_bytes":0,"stderr_bytes":0,"truncated":false,"error":{"kind":"network","message":"h: connect: connection refused"}}`,
		},
		{
			"timeout",
			result.Result{Host: "h", Command: "sleep 30", Err: result.ErrTimeout, Elapsed: 2 * time.Second},
			`{"v":1,"host":"h","command":"sleep 30","status":"timeout","exit_code":254,"signal":null,"duration_ms":2000,"connect_ms":0,"stdout_bytes":0,"stderr_bytes":0,"truncated":false,"error":{"kind":"timeout","message":"timeout after 2s"}}`,
		},
		{
			"cancelled",
			result.Result{Host: "h", Command: "sleep 30", Err: result.Interrupt{Signal: syscall.SIGINT}},
			`{"v":1,"host":"h","command":"sleep 30","status":"cancelled","exit_code":130,"signal":null,"duration_ms":0,"connect_ms":0,"stdout_bytes":0,"stderr_bytes":0,"truncated":false,"error":{"kind":"cancelled","message":"cancelled by SIGINT"}}`,
		},
		{
			"truncated with no remote exit",
			result.Result{Host: "h", Command: "yes", Err: result.ErrTruncated, StdoutBytes: 1024},
			`{"v":1,"host":"h","command":"yes","status":"truncated","exit_code":254,"signal":null,"duration_ms":0,"connect_ms":0,"stdout_bytes":1024,"stderr_bytes":0,"truncated":true,"error":{"kind":"truncated","message":"output truncated at 1024 bytes"}}`,
		},
		{
			"truncated by a remote that still exited",
			result.Result{
				Host: "h", Command: "head -c 5000 /dev/zero; exit 7",
				Remote: &result.Remote{Exit: 7}, Err: result.ErrTruncated,
				StdoutBytes: 1000, StderrBytes: 24,
			},
			`{"v":1,"host":"h","command":"head -c 5000 /dev/zero; exit 7","status":"truncated","exit_code":7,"signal":null,"duration_ms":0,"connect_ms":0,"stdout_bytes":1000,"stderr_bytes":24,"truncated":true,"error":{"kind":"truncated","message":"output truncated at 1024 bytes"}}`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Encode(c.res)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != c.want {
				t.Errorf("Encode:\n got %s\nwant %s", got, c.want)
			}
		})
	}
}

// TestWriterSeparatesTheEnvelopeOnlyWhenNeeded is SPEC §6's sharp edge: the
// envelope is preceded by a newline exactly when the remote's last byte was
// not one, so it is always the final line and never leaves a blank one.
func TestWriterSeparatesTheEnvelopeOnlyWhenNeeded(t *testing.T) {
	res := result.Result{Host: "h", Command: "true", Remote: &result.Remote{}}
	line, err := Encode(res)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		writes []string
		want   string
	}{
		{"nothing written", nil, ""},
		{"output ended in a newline", []string{"hi\n"}, "hi\n"},
		{"output did not", []string{"nonl"}, "nonl\n"},
		{"only the last write counts", []string{"a\n", "b"}, "a\nb\n"},
		{"and it counts the other way round", []string{"a", "b\n"}, "ab\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := New(&buf)
			for _, s := range c.writes {
				if _, err := io.WriteString(w, s); err != nil {
					t.Fatal(err)
				}
			}
			if err := w.Emit(res); err != nil {
				t.Fatal(err)
			}
			if want := c.want + string(line) + "\n"; buf.String() != want {
				t.Errorf("stdout = %q, want %q", buf.String(), want)
			}
		})
	}
}
