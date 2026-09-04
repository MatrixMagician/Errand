// Package envelope writes the --json result envelope: one JSON object as the
// final line of stdout (SPEC §6). It serialises a verdict result already
// reached and holds no policy of its own.
package envelope

import (
	"bytes"
	"encoding/json"
	"io"

	"github.com/MatrixMagician/Errand/internal/result"
)

// Writer passes remote stdout through untouched while remembering whether the
// last byte written was a newline. That is the only thing Emit needs to know:
// output whose last line was not newline-terminated would otherwise abut the
// envelope and leave the final line unparseable.
type Writer struct {
	w      io.Writer
	lastNL bool
}

// New wraps w. Nothing has been written yet, so the envelope of a run that
// produces no output needs no separating newline.
func New(w io.Writer) *Writer { return &Writer{w: w, lastNL: true} }

func (e *Writer) Write(p []byte) (int, error) {
	n, err := e.w.Write(p)
	if n > 0 {
		e.lastNL = p[n-1] == '\n'
	}
	return n, err
}

// Emit writes the envelope and the newline that ends it.
func (e *Writer) Emit(r result.Result) error {
	b, err := Encode(r)
	if err != nil {
		return err
	}
	if !e.lastNL {
		b = append([]byte{'\n'}, b...)
	}
	_, err = e.Write(append(b, '\n'))
	return err
}

// Encode renders one Result as the envelope object, with no trailing newline.
func Encode(r result.Result) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	// A command is far likelier to contain > or & than to be pasted into HTML,
	// so the redirection an operator typed stays readable in the envelope.
	enc.SetEscapeHTML(false)
	if err := enc.Encode(wireOf(r)); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}

// wire is the envelope's field order and its nullability, and nothing else.
// These fields appear in the order SPEC §6 prints them.
type wire struct {
	V           int      `json:"v"`
	Host        string   `json:"host"`
	Command     string   `json:"command"`
	Status      string   `json:"status"`
	ExitCode    int      `json:"exit_code"`
	Signal      *string  `json:"signal"`
	DurationMS  int64    `json:"duration_ms"`
	ConnectMS   int64    `json:"connect_ms"`
	StdoutBytes int64    `json:"stdout_bytes"`
	StderrBytes int64    `json:"stderr_bytes"`
	Truncated   bool     `json:"truncated"`
	Error       *wireErr `json:"error"`
}

type wireErr struct {
	Kind    string `json:"kind"`
	Message string `json:"message"`
}

func wireOf(r result.Result) wire {
	w := wire{
		V:           1,
		Host:        r.Host,
		Command:     r.Command,
		Status:      string(r.Status()),
		ExitCode:    r.ExitCode(),
		DurationMS:  r.Elapsed.Milliseconds(),
		ConnectMS:   r.Connect.Milliseconds(),
		StdoutBytes: r.StdoutBytes,
		StderrBytes: r.StderrBytes,
		Truncated:   r.Truncated(),
	}
	if r.Remote != nil && r.Remote.Signal != "" {
		sig := r.Remote.Signal
		w.Signal = &sig
	}
	if w.Status != string(result.StatusOK) {
		w.Error = &wireErr{Kind: string(r.Kind()), Message: r.Diagnostic()}
	}
	return w
}
