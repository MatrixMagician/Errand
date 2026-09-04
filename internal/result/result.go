// Package result is the single place where errand decides what a run means:
// its status, its error kind, and its process exit code (SPEC §5.2, §6).
// A Result carries facts; the verdict is derived. It imports nothing project-local.
package result

import (
	"context"
	"errors"
	"strconv"
	"syscall"
	"time"
)

// Phase names the stage an operation failed in (SPEC §12). It drives both the
// exit code and the JSON envelope's error.kind.
type Phase uint8

const (
	Usage Phase = iota + 1
	Resolve
	Connect
	HostKey
	Auth
	Exec
	Transfer
)

func (p Phase) String() string {
	switch p {
	case Usage:
		return "usage"
	case Resolve:
		return "resolve"
	case Connect:
		return "connect"
	case HostKey:
		return "hostkey"
	case Auth:
		return "auth"
	case Exec:
		return "exec"
	case Transfer:
		return "transfer"
	}
	return "unknown"
}

// Wrap tags err with the phase and host alias. It is nil-safe, and an error
// that already carries a phase keeps the one it has: the innermost phase is
// the one that happened.
func (p Phase) Wrap(host string, err error) error {
	if err == nil {
		return nil
	}
	var already *Error
	if errors.As(err, &already) {
		return err
	}
	return &Error{Phase: p, Host: host, Err: err}
}

// Error is a phase-tagged, host-tagged failure.
type Error struct {
	Phase Phase
	Host  string
	Err   error
}

func (e *Error) Error() string {
	if e.Host == "" {
		return e.Phase.String() + ": " + e.Err.Error()
	}
	return e.Host + ": " + e.Phase.String() + ": " + e.Err.Error()
}

func (e *Error) Unwrap() error { return e.Err }

// Stop causes. These are not phase failures: the operation was cut short.
var (
	ErrTimeout   = errors.New("timeout")
	ErrTruncated = errors.New("output truncated")
)

// Interrupt is a signal errand itself received (SPEC §5.3).
type Interrupt struct{ Signal syscall.Signal }

func (i Interrupt) Error() string { return "cancelled by " + signalName(int(i.Signal)) }

// StopCause reports why ctx ended: an Interrupt if one caused it, else a timeout.
func StopCause(ctx context.Context) error {
	var i Interrupt
	if cause := context.Cause(ctx); errors.As(cause, &i) {
		return i
	}
	return ErrTimeout
}

// Remote is how the remote command ended. When Signal is set (an SSH signal
// name without the "SIG" prefix) Exit carries no meaning.
type Remote struct {
	Exit   int
	Signal string
}

func (r Remote) code() int {
	if r.Signal == "" {
		return r.Exit
	}
	if n, ok := signalNumbers[r.Signal]; ok {
		return 128 + n
	}
	return 128
}

// Result is everything one errand operation produced.
type Result struct {
	Op      string // run, check, put, get
	Host    string // the configured alias
	Target  string // user@hostname:port
	Command string // the joined command, or "<src> <dst>" for transfers

	Remote *Remote // nil: no exit status arrived
	Err    error   // nil: ran to completion

	Connect, Elapsed         time.Duration
	StdoutBytes, StderrBytes int64
}

// Status is the envelope's status field.
type Status string

const (
	StatusOK          Status = "ok"
	StatusClientError Status = "client_error"
	StatusTimeout     Status = "timeout"
	StatusCancelled   Status = "cancelled"
	StatusTruncated   Status = "truncated"
)

// Kind is the envelope's error.kind field. For timeout, cancelled and
// truncated it mirrors the status, since §6 requires an error whenever the
// status is not ok.
type Kind string

const (
	KindUsage     Kind = "usage"
	KindConfig    Kind = "config"
	KindHostKey   Kind = "hostkey"
	KindAuth      Kind = "auth"
	KindNetwork   Kind = "network"
	KindTimeout   Kind = "timeout"
	KindCancelled Kind = "cancelled"
	KindTruncated Kind = "truncated"
)

var byPhase = [...]struct {
	exit int
	kind Kind
}{
	Usage:    {250, KindUsage},
	Resolve:  {250, KindConfig},
	Connect:  {253, KindNetwork},
	HostKey:  {251, KindHostKey},
	Auth:     {252, KindAuth},
	Exec:     {253, KindNetwork},
	Transfer: {253, KindNetwork},
}

// verdict derives status, kind and exit code from the facts, in a fixed
// precedence: timeout, interrupt, truncation, phase failure, remote exit.
// Anything else fails closed to a client-side network error.
func (r Result) verdict() (Status, Kind, int) {
	var intr Interrupt
	var phased *Error
	switch {
	case errors.Is(r.Err, ErrTimeout):
		return StatusTimeout, KindTimeout, 254
	case errors.As(r.Err, &intr):
		return StatusCancelled, KindCancelled, 128 + int(intr.Signal)
	case errors.Is(r.Err, ErrTruncated):
		if r.Remote != nil {
			return StatusTruncated, KindTruncated, r.Remote.code()
		}
		return StatusTruncated, KindTruncated, 254
	case errors.As(r.Err, &phased):
		if p := int(phased.Phase); p < len(byPhase) && byPhase[p].exit != 0 {
			return StatusClientError, byPhase[p].kind, byPhase[p].exit
		}
	case r.Err == nil && r.Remote != nil:
		return StatusOK, "", r.Remote.code()
	}
	return StatusClientError, KindNetwork, 253
}

// Status reports the envelope status.
func (r Result) Status() Status { s, _, _ := r.verdict(); return s }

// Kind reports the envelope error kind, empty when the status is ok.
func (r Result) Kind() Kind { _, k, _ := r.verdict(); return k }

// ExitCode reports the process exit code (SPEC §5.2).
func (r Result) ExitCode() int { _, _, c := r.verdict(); return c }

// Truncated reports whether the output cap was breached.
func (r Result) Truncated() bool { return errors.Is(r.Err, ErrTruncated) }

// Diagnostic is the one stderr line describing the outcome, without the
// "errand: " prefix. It is empty when there is nothing to say.
func (r Result) Diagnostic() string {
	var intr Interrupt
	var phased *Error
	switch {
	case errors.Is(r.Err, ErrTimeout):
		return "timeout after " + r.Elapsed.Round(time.Millisecond).String()
	case errors.As(r.Err, &intr):
		return intr.Error()
	case errors.Is(r.Err, ErrTruncated):
		return "output truncated at " + strconv.FormatInt(r.StdoutBytes+r.StderrBytes, 10) + " bytes"
	case errors.As(r.Err, &phased):
		return phased.Error()
	case r.Err != nil:
		return r.Err.Error()
	case r.Remote != nil && r.Remote.Signal != "":
		return "remote terminated by SIG" + r.Remote.Signal
	}
	return ""
}

// signalNumbers maps the SSH signal names (RFC 4254 §6.10) to the POSIX
// numbers the remote used, so 128+n matches what a shell would report.
var signalNumbers = map[string]int{
	"ABRT": 6, "ALRM": 14, "FPE": 8, "HUP": 1, "ILL": 4, "INT": 2,
	"KILL": 9, "PIPE": 13, "QUIT": 3, "SEGV": 11, "TERM": 15,
	"USR1": 10, "USR2": 12,
}

func signalName(num int) string {
	for name, n := range signalNumbers {
		if n == num {
			return "SIG" + name
		}
	}
	return "signal " + strconv.Itoa(num)
}
