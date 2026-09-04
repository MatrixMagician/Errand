// Package audit appends one line per operation to the audit log (SPEC §10).
// It records what was done, never what was seen: there is no field for output
// bytes, so a secret that transited stdout cannot reach the log. The status
// and error vocabulary is result's, read here rather than restated.
package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/MatrixMagician/Errand/internal/result"
)

// Append adds one JSON line describing r to the log at path, creating the file
// and its directory when they do not exist. Both are private to the operator:
// the log names every host reached and every command sent.
func Append(path string, now time.Time, r result.Result) error {
	b, err := encode(now, r)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	// One Write of the whole line. An O_APPEND write is a single atomic
	// extend, so concurrent errands interleave whole lines instead of
	// splitting one between them.
	_, err = f.Write(b)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// line is the audit record's field order and its omissions, and nothing else.
// The verdict fields are asked of result, which is where they are decided.
type line struct {
	TS          string `json:"ts"`
	Op          string `json:"op"`
	Host        string `json:"host"`
	Target      string `json:"target"`
	Command     string `json:"command"`
	Status      string `json:"status"`
	Kind        string `json:"kind,omitempty"`
	ExitCode    int    `json:"exit_code"`
	DurationMS  int64  `json:"duration_ms"`
	ConnectMS   int64  `json:"connect_ms"`
	StdoutBytes int64  `json:"stdout_bytes"`
	StderrBytes int64  `json:"stderr_bytes"`
	Truncated   bool   `json:"truncated"`
	Error       string `json:"error,omitempty"`
}

func encode(now time.Time, r result.Result) ([]byte, error) {
	l := line{
		TS:          now.UTC().Format(time.RFC3339),
		Op:          r.Op,
		Host:        r.Host,
		Target:      r.Target,
		Command:     r.Command,
		Status:      string(r.Status()),
		Kind:        string(r.Kind()),
		ExitCode:    r.ExitCode(),
		DurationMS:  r.Elapsed.Milliseconds(),
		ConnectMS:   r.Connect.Milliseconds(),
		StdoutBytes: r.StdoutBytes,
		StderrBytes: r.StderrBytes,
		Truncated:   r.Truncated(),
	}
	if r.Err != nil {
		l.Error = r.Diagnostic()
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	// A command is far likelier to contain > or & than to be pasted into HTML,
	// so the redirection an operator typed stays greppable in the log.
	enc.SetEscapeHTML(false)
	err := enc.Encode(l) // Encode ends the object with the newline the line needs.
	return b.Bytes(), err
}
