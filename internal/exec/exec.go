// Package exec runs one command on an established connection and enforces the
// §5 stream and exit-code contract. It knows nothing about the CLI.
package exec

import (
	"cmp"
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

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
	lim := newLimiter(req.MaxOutput)
	out := &capWriter{w: cmp.Or(req.Stdout, io.Writer(io.Discard)), lim: lim}
	errOut := &capWriter{w: cmp.Or(req.Stderr, io.Writer(io.Discard)), lim: lim}
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
	waitC := make(chan error, 1)
	go func() { waitC <- sess.Wait() }()

	select {
	case werr := <-waitC:
		r.Remote, r.Err = fromWait(alias, werr)
	case <-ctx.Done():
		r.Err = result.StopCause(ctx)
		teardown(c, sess, waitC, false)
	case <-lim.breached:
		r.Err = result.ErrTruncated
		r.Remote = teardown(c, sess, waitC, true)
	}
	r.StdoutBytes, r.StderrBytes = out.n.Load(), errOut.n.Load()
	return r
}

// Graces bounding teardown. Their sum is the worst case an operator waits for
// after a timeout, cancellation or cap breach.
const (
	killGrace     = 200 * time.Millisecond
	teardownGrace = 2 * time.Second
	flushGrace    = time.Second
)

// teardown ends a session that is still running and returns the remote's own
// exit status when one arrives in time. It is bounded whatever the server does.
func teardown(c *client.Conn, sess *ssh.Session, waitC <-chan error, onCap bool) *result.Remote {
	select {
	case err := <-waitC:
		return remoteOf(c, err)
	default:
	}

	// Fire and forget: a wedged transport blocks these writes indefinitely,
	// and the SSH signal request is a courtesy many servers ignore anyway.
	go func() { _ = sess.Signal(ssh.SIGKILL) }()
	go func() { _ = sess.Close() }()

	// Only a cap breach lets the remote's own code win (SPEC 5.4), so only it
	// pays for the wait.
	if onCap {
		if err, ok := waitWithin(waitC, killGrace); ok {
			return ownExit(c, err)
		}
	}

	// Abort's socket deadline is the guarantee that everything above unblocks.
	c.Abort(teardownGrace)
	err, ok := waitWithin(waitC, flushGrace)
	if ok && onCap {
		return ownExit(c, err)
	}
	return nil
}

// ownExit keeps only a status the remote reached by itself. Servers that
// honour the courtesy KILL above answer it with an exit-signal, and crediting
// that to the remote would score every cap breach 128+9 instead of the 254
// SPEC 5.4 asks for. Only a status that outran our own signal is the remote's.
func ownExit(c *client.Conn, err error) *result.Remote {
	remote := remoteOf(c, err)
	if remote != nil && remote.Signal == string(ssh.SIGKILL) {
		return nil
	}
	return remote
}

func waitWithin(waitC <-chan error, d time.Duration) (error, bool) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case err := <-waitC:
		return err, true
	case <-timer.C:
		return nil, false
	}
}

// remoteOf keeps only the exit status from a Wait: the stop cause already in
// the Result outranks whatever the dying connection reported.
func remoteOf(c *client.Conn, err error) *result.Remote {
	remote, _ := fromWait(c.Host.Alias, err)
	return remote
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

// limiter is the output budget the two streams share. A max of 0 disables it.
type limiter struct {
	max      int64
	total    atomic.Int64
	breached chan struct{}
	once     sync.Once
}

func newLimiter(max int64) *limiter {
	return &limiter{max: max, breached: make(chan struct{})}
}

// take reserves up to n bytes of the budget and reports how many of them may
// be delivered. The reservation is one atomic add, so two streams racing at
// the boundary still deliver exactly max bytes between them.
func (l *limiter) take(n int64) int64 {
	if l.max == 0 {
		return n
	}
	over := l.total.Add(n) - l.max
	if over <= 0 {
		return n
	}
	l.once.Do(func() { close(l.breached) })
	if over >= n {
		return 0
	}
	return n - over
}

// capWriter delivers bytes until the shared budget runs out, then swallows the
// rest and still reports a full write. Reporting short would stall the copier
// and with it the SSH window, and the window has to keep moving for a remote
// that is already exiting to land its status inside killGrace.
type capWriter struct {
	w   io.Writer
	lim *limiter

	// n is delivered bytes on this stream. It is atomic because teardown
	// reads it on a bounded wait, with the copier possibly still running.
	n atomic.Int64
}

func (c *capWriter) Write(p []byte) (int, error) {
	allowed := c.lim.take(int64(len(p)))
	if allowed == 0 {
		return len(p), nil
	}
	n, err := c.w.Write(p[:allowed])
	c.n.Add(int64(n))
	if err != nil {
		return n, err
	}
	return len(p), nil
}
