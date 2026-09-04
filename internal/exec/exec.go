// Package exec runs one command on an established connection and enforces the
// §5 stream and exit-code contract. It knows nothing about the CLI.
package exec

import (
	"cmp"
	"context"
	"errors"
	"io"

	"github.com/MatrixMagician/Errand/internal/client"
	"github.com/MatrixMagician/Errand/internal/result"
	"golang.org/x/crypto/ssh"
)

// Request is one remote command.
type Request struct {
	Command string

	// Stdin is forwarded only when non-nil, so a forgotten pipe cannot make
	// the remote command wait for input that never comes.
	Stdin          io.Reader
	Stdout, Stderr io.Writer

	MaxOutput int64    // combined cap across both streams; 0 disables
	Env       []string // KEY=VAL, sent as SSH env requests
	PTY       bool
}

// Run executes req and reports what happened. It never returns an error: the
// outcome, including failure, is the Result.
func Run(ctx context.Context, c *client.Conn, req Request) result.Result {
	alias := c.Host.Alias
	r := result.Result{Host: alias, Command: req.Command}

	sess, err := c.NewSession()
	if err != nil {
		r.Err = result.Exec.Wrap(alias, err)
		return r
	}
	defer func() { _ = sess.Close() }()

	// The writer form, not the pipe form: Wait joins the copiers, so a
	// returned Wait proves every byte reached Stdout and Stderr.
	// ticket #6: MaxOutput swaps these for the capping writers.
	out, errOut := &counter{w: cmp.Or(req.Stdout, io.Writer(io.Discard))}, &counter{w: cmp.Or(req.Stderr, io.Writer(io.Discard))}
	sess.Stdout, sess.Stderr = out, errOut

	if req.Stdin != nil {
		w, err := sess.StdinPipe()
		if err != nil {
			r.Err = result.Exec.Wrap(alias, err)
			return r
		}
		// Detached and never joined: Wait drains its own stdin copier, and
		// would block forever on a local stdin that never reaches EOF.
		go func() {
			_, _ = io.Copy(w, req.Stdin)
			_ = w.Close()
		}()
	}

	if err := sess.Start(req.Command); err != nil {
		r.Err = result.Exec.Wrap(alias, err)
		return r
	}
	// ticket #5: ctx and the cap breach select against Wait here, then tear down.
	r.Remote, r.Err = fromWait(alias, sess.Wait())
	r.StdoutBytes, r.StderrBytes = out.n, errOut.n
	return r
}

// fromWait turns x/crypto's Wait error into an exit status, or into an exec
// phase failure when the connection died without one.
func fromWait(alias string, err error) (*result.Remote, error) {
	var exit *ssh.ExitError
	switch {
	case err == nil:
		return &result.Remote{}, nil
	case errors.As(err, &exit):
		return &result.Remote{Exit: exit.ExitStatus(), Signal: exit.Signal()}, nil
	}
	return nil, result.Exec.Wrap(alias, err)
}

// counter forwards bytes and records how many. Wait joins the copier that
// writes here, so n is final once Wait has returned.
type counter struct {
	w io.Writer
	n int64
}

func (c *counter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}
