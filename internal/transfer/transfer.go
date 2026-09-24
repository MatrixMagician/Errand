// Package transfer moves one file over SFTP on an established connection. It
// knows nothing about the CLI (SPEC §9): no globbing, no recursion, no resume.
package transfer

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/MatrixMagician/Errand/internal/client"
	"github.com/MatrixMagician/Errand/internal/result"
	"github.com/pkg/sftp"
)

// Graces bounding a cancelled transfer, mirroring exec's teardown: the temp
// file gets a window to be unlinked while the connection is still up, then the
// socket deadline ends the copy whatever the server is doing.
const (
	cleanupGrace = 500 * time.Millisecond
	abortGrace   = 2 * time.Second
)

// Put uploads local to remote. The bytes go to a temporary name in the
// destination directory and are renamed into place, so a partial upload never
// appears under the final name. It never returns an error: the outcome,
// including failure, is the Result.
func Put(ctx context.Context, c *client.Conn, local, remote string, mode fs.FileMode, maxSize int64) result.Result {
	alias := c.Host.Alias
	r := result.Result{Host: alias, Command: local + " " + remote}
	early := context.AfterFunc(ctx, func() { c.Abort(abortGrace) })
	defer early()

	fi, err := os.Stat(local)
	if err != nil {
		r.Err = result.Usage.Wrap(alias, err)
		return r
	}
	if fi.IsDir() {
		r.Err = result.Usage.Wrap(alias, fmt.Errorf("%s is a directory, and put moves one file", local))
		return r
	}
	if !fi.Mode().IsRegular() {
		r.Err = result.Usage.Wrap(alias, fmt.Errorf("%s is not a regular file, so its size says nothing about its length", local))
		return r
	}
	if maxSize > 0 && fi.Size() > maxSize {
		r.Err = result.Usage.Wrap(alias, fmt.Errorf("%s is %d bytes, over --max-size %d", local, fi.Size(), maxSize))
		return r
	}
	src, err := os.Open(local)
	if err != nil {
		r.Err = result.Usage.Wrap(alias, err)
		return r
	}
	defer func() { _ = src.Close() }()

	sc, err := sftp.NewClient(c.Client)
	if err != nil {
		r.Err = requestErr(ctx, alias, err)
		return r
	}
	defer func() { _ = sc.Close() }()

	tmp := tempName(remote)
	return move(ctx, c, r.Command, early,
		func() (int64, error) { return upload(sc, src, tmp, remote, mode, maxSize) },
		func() { _ = sc.Remove(tmp) })
}

// Get downloads remote to local, the same guarantee in the other direction: the
// bytes go to a temporary name in the local destination directory and are
// renamed into place, so a partial download never appears under the final name.
func Get(ctx context.Context, c *client.Conn, remote, local string, maxSize int64) result.Result {
	alias := c.Host.Alias
	r := result.Result{Host: alias, Command: remote + " " + local}
	early := context.AfterFunc(ctx, func() { c.Abort(abortGrace) })
	defer early()

	if fi, err := os.Stat(local); err == nil && fi.IsDir() {
		r.Err = result.Usage.Wrap(alias, fmt.Errorf("%s is a directory, and get names the file to write", local))
		return r
	}
	if _, err := os.Stat(filepath.Dir(local)); err != nil {
		r.Err = result.Usage.Wrap(alias, err)
		return r
	}

	sc, err := sftp.NewClient(c.Client)
	if err != nil {
		r.Err = requestErr(ctx, alias, err)
		return r
	}
	defer func() { _ = sc.Close() }()

	fi, err := sc.Stat(remote)
	if err != nil {
		r.Err = requestErr(ctx, alias, err)
		return r
	}
	if fi.IsDir() {
		r.Err = result.Transfer.Wrap(alias, fmt.Errorf("%s is a directory, and get moves one file", remote))
		return r
	}
	if !fi.Mode().IsRegular() {
		r.Err = result.Usage.Wrap(alias, fmt.Errorf("%s is not a regular file, so its size says nothing about its length", remote))
		return r
	}
	if maxSize > 0 && fi.Size() > maxSize {
		r.Err = result.Usage.Wrap(alias, fmt.Errorf("%s is %d bytes, over --max-size %d", remote, fi.Size(), maxSize))
		return r
	}
	src, err := sc.Open(remote)
	if err != nil {
		r.Err = requestErr(ctx, alias, err)
		return r
	}
	defer func() { _ = src.Close() }()

	tmp := localTempName(local)
	return move(ctx, c, r.Command, early,
		func() (int64, error) { return download(src, tmp, local, maxSize) },
		func() { _ = os.Remove(tmp) })
}

// requestErr scores a failed SFTP request made before the copy. A done context
// means the early abort closed the connection under it, so the timeout or
// interrupt is the cause rather than whatever the request reported.
func requestErr(ctx context.Context, alias string, err error) error {
	if ctx.Err() != nil {
		return result.StopCause(ctx)
	}
	return result.Transfer.Wrap(alias, err)
}

// move runs the copy a transfer is and scores it. body writes to a temporary
// name and renames into place; discard unlinks that temporary on whichever side
// holds it. Cancellation gets discard in while the connection is still up, then
// takes the socket away, and move does not return until that window has closed:
// returning earlier would let the caller's Conn.Close cut cleanup short.
//
// early is the caller's plain abort, armed before its first SFTP request so a
// remote open or stat that never returns still ends inside the budget. move
// takes over from it here; if it already fired there is no connection to copy
// over.
func move(ctx context.Context, c *client.Conn, command string, early func() bool, body func() (int64, error), discard func()) result.Result {
	r := result.Result{Host: c.Host.Alias, Command: command}
	if !early() {
		r.Err = result.StopCause(ctx)
		return r
	}
	cleaned := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(cleaned)
		abandon(c, discard)
	})
	defer func() {
		if !stop() {
			<-cleaned
		}
	}()

	n, err := body()
	r.StdoutBytes = n
	switch {
	case ctx.Err() != nil:
		r.Err = result.StopCause(ctx)
	case err != nil:
		discard()
		r.Err = result.Transfer.Wrap(c.Host.Alias, err)
	default:
		r.Remote = &result.Remote{}
	}
	return r
}

// tempName is a sibling of the destination, so the rename that follows stays
// within one filesystem. The leading dot keeps it out of an unsuffixed glob. The
// random suffix is what makes the exclusive create safe in a directory others
// can write: nobody can plant a symlink at a name they cannot predict, and two
// errands never share a file.
func tempName(remote string) string {
	return path.Join(path.Dir(remote), "."+path.Base(remote)+".errand-"+randomSuffix())
}

// localTempName is the same name on this side of the connection, where the
// separator is the local one rather than SFTP's slash.
func localTempName(local string) string {
	return filepath.Join(filepath.Dir(local), "."+filepath.Base(local)+".errand-"+randomSuffix())
}

func randomSuffix() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b) // never fails: crypto/rand aborts the program instead
	return hex.EncodeToString(b)
}

func upload(sc *sftp.Client, src io.Reader, tmp, remote string, mode fs.FileMode, maxSize int64) (int64, error) {
	w, err := sc.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		return 0, err
	}
	// Before any bytes: pkg/sftp creates with no attributes, so the temp starts
	// at the server's default and a 0600 payload would be readable in flight.
	var n int64
	err = w.Chmod(mode)
	if err == nil {
		n, err = copyCapped(w, src, maxSize)
	}
	if cerr := w.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return n, err
	}
	return n, rename(sc, tmp, remote)
}

// download writes 0644 before umask, the mode a shell redirect would give the
// file: the remote bits are the sender's, and carrying them across would let a
// remote 0777 decide what this machine ends up with.
func download(src io.Reader, tmp, local string, maxSize int64) (int64, error) {
	w, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return 0, err
	}
	n, err := copyCapped(w, src, maxSize)
	if cerr := w.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return n, err
	}
	return n, os.Rename(tmp, local)
}

// copyCapped enforces --max-size on the bytes themselves, which the stat check
// cannot: a file that grows during the copy passes the stat and keeps going.
// One byte past the cap is enough to know it was crossed. A zero cap is none.
func copyCapped(w io.Writer, src io.Reader, maxSize int64) (int64, error) {
	if maxSize <= 0 {
		return io.Copy(w, src)
	}
	n, err := io.Copy(w, io.LimitReader(src, maxSize+1))
	if err == nil && n > maxSize {
		err = fmt.Errorf("source grew past --max-size %d during the copy", maxSize)
	}
	return n, err
}

// rename puts the finished bytes under their final name with posix-rename,
// which replaces an existing destination in one step. A server without the
// extension is refused rather than emulated: remove-then-rename would leave a
// moment with neither file, and pkg/sftp's Remove also removes an empty
// directory standing at the destination.
func rename(sc *sftp.Client, tmp, remote string) error {
	if _, ok := sc.HasExtension("posix-rename@openssh.com"); !ok {
		return fmt.Errorf("server lacks the posix-rename@openssh.com extension, so %s cannot be replaced atomically", remote)
	}
	return sc.PosixRename(tmp, remote)
}

// abandon unlinks the temp file while the connection is still up, then takes
// the socket away whatever the server is doing. Unlinking a file the copy still
// holds open is what leaves the destination with neither name; on a connection
// already stalled hard enough that a remote unlink cannot go out, the window
// expires and the temp file survives. The final name never appears either way.
func abandon(c *client.Conn, discard func()) {
	removed := make(chan struct{})
	go func() {
		defer close(removed)
		discard()
	}()
	select {
	case <-removed:
	case <-time.After(cleanupGrace):
	}
	c.Abort(abortGrace)
}
