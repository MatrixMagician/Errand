package result

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"testing"
)

func TestVerdict(t *testing.T) {
	boom := errors.New("boom")
	cases := []struct {
		name string
		res  Result
		want Status
		kind Kind
		code int
	}{
		{"usage", Result{Err: Usage.Wrap("h", boom)}, StatusClientError, KindUsage, 250},
		{"resolve", Result{Err: Resolve.Wrap("h", boom)}, StatusClientError, KindConfig, 250},
		{"connect", Result{Err: Connect.Wrap("h", boom)}, StatusClientError, KindNetwork, 253},
		{"hostkey", Result{Err: HostKey.Wrap("h", boom)}, StatusClientError, KindHostKey, 251},
		{"auth", Result{Err: Auth.Wrap("h", boom)}, StatusClientError, KindAuth, 252},
		{"exec", Result{Err: Exec.Wrap("h", boom)}, StatusClientError, KindNetwork, 253},
		{"transfer", Result{Err: Transfer.Wrap("h", boom)}, StatusClientError, KindNetwork, 253},

		{"remote exit 7", Result{Remote: &Remote{Exit: 7}}, StatusOK, "", 7},
		{"remote exit 255", Result{Remote: &Remote{Exit: 255}}, StatusOK, "", 255},
		{"remote exit 0", Result{Remote: &Remote{}}, StatusOK, "", 0},
		{"remote signalled", Result{Remote: &Remote{Signal: "TERM"}}, StatusOK, "", 143},
		{"remote unknown signal", Result{Remote: &Remote{Signal: "NOPE"}}, StatusOK, "", 128},

		{"truncated with remote", Result{Err: ErrTruncated, Remote: &Remote{Exit: 7}}, StatusTruncated, KindTruncated, 7},
		{"truncated without remote", Result{Err: ErrTruncated}, StatusTruncated, KindTruncated, 254},
		{"timeout beats remote", Result{Err: ErrTimeout, Remote: &Remote{Exit: 0}}, StatusTimeout, KindTimeout, 254},
		{"interrupt", Result{Err: Interrupt{Signal: syscall.SIGINT}}, StatusCancelled, KindCancelled, 130},
		{"phase beats remote", Result{Err: Auth.Wrap("h", boom), Remote: &Remote{Exit: 0}}, StatusClientError, KindAuth, 252},
		{"bare error", Result{Err: boom}, StatusClientError, KindNetwork, 253},
		{"zero", Result{}, StatusClientError, KindNetwork, 253},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.res.Status(); got != c.want {
				t.Errorf("Status() = %q, want %q", got, c.want)
			}
			if got := c.res.Kind(); got != c.kind {
				t.Errorf("Kind() = %q, want %q", got, c.kind)
			}
			if got := c.res.ExitCode(); got != c.code {
				t.Errorf("ExitCode() = %d, want %d", got, c.code)
			}
		})
	}
}

func TestEveryPhaseIsMapped(t *testing.T) {
	for p := Usage; p <= Transfer; p++ {
		if p.String() == "unknown" {
			t.Errorf("phase %d has no name", p)
		}
		if byPhase[p].exit == 0 || byPhase[p].kind == "" {
			t.Errorf("phase %s is not in byPhase", p)
		}
	}
}

func TestWrap(t *testing.T) {
	if Usage.Wrap("h", nil) != nil {
		t.Error("Wrap(nil) must be nil")
	}
	inner := Auth.Wrap("h", errors.New("boom"))
	outer := Exec.Wrap("h", fmt.Errorf("while running: %w", inner))
	var e *Error
	if !errors.As(outer, &e) || e.Phase != Auth {
		t.Errorf("wrapping an *Error must keep the inner phase, got %v", outer)
	}
	if got := inner.Error(); got != "h: auth: boom" {
		t.Errorf("Error() = %q", got)
	}
	if got := Auth.Wrap("", errors.New("boom")).Error(); got != "auth: boom" {
		t.Errorf("Error() with no host = %q", got)
	}
}

func TestDiagnostic(t *testing.T) {
	cases := []struct {
		res  Result
		want string
	}{
		{Result{}, ""},
		{Result{Remote: &Remote{Exit: 7}}, ""},
		{Result{Remote: &Remote{Signal: "TERM"}}, "remote terminated by SIGTERM"},
		{Result{Err: HostKey.Wrap("h", errors.New("unknown key"))}, "h: hostkey: unknown key"},
		{Result{Err: Interrupt{Signal: syscall.SIGINT}}, "cancelled by SIGINT"},
		{Result{Err: ErrTruncated, StdoutBytes: 900, StderrBytes: 124}, "output truncated at 1024 bytes"},
	}
	for _, c := range cases {
		if got := c.res.Diagnostic(); got != c.want {
			t.Errorf("Diagnostic() = %q, want %q", got, c.want)
		}
		if strings.Contains(c.res.Diagnostic(), "\n") {
			t.Errorf("Diagnostic() must be one line: %q", c.res.Diagnostic())
		}
	}
	if got := (Result{Err: ErrTimeout, Elapsed: 2000000000}).Diagnostic(); got != "timeout after 2s" {
		t.Errorf("Diagnostic() = %q", got)
	}
}

func TestTruncated(t *testing.T) {
	if !(Result{Err: ErrTruncated}).Truncated() || (Result{}).Truncated() {
		t.Error("Truncated() must follow ErrTruncated")
	}
}
