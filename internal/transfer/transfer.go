// Package transfer moves one file over SFTP on an established connection. It
// knows nothing about the CLI (SPEC §9): no globbing, no recursion, no resume.
package transfer

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strconv"
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

	fi, err := os.Stat(local)
	if err != nil {
		r.Err = result.Usage.Wrap(alias, err)
		return r
	}
	if fi.IsDir() {
		r.Err = result.Usage.Wrap(alias, fmt.Errorf("%s is a directory, and put moves one file", local))
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
		r.Err = result.Transfer.Wrap(alias, err)
		return r
	}
	defer func() { _ = sc.Close() }()

	tmp := tempName(remote)
	return move(ctx, c, r.Command,
		func() (int64, error) { return upload(sc, src, tmp, remote, mode) },
		func() { _ = sc.Remove(tmp) })
}

// Get downloads remote to local, the same guarantee in the other direction: the
// bytes go to a temporary name in the local destination directory and are
// renamed into place, so a partial download never appears under the final name.
func Get(ctx context.Context, c *client.Conn, remote, local string, maxSize int64) result.Result {
	alias := c.Host.Alias
	r := result.Result{Host: alias, Command: remote + " " + local}

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
		r.Err = result.Transfer.Wrap(alias, err)
		return r
	}
	defer func() { _ = sc.Close() }()

	fi, err := sc.Stat(remote)
	if err != nil {
		r.Err = result.Transfer.Wrap(alias, err)
		return r
	}
	if fi.IsDir() {
		r.Err = result.Transfer.Wrap(alias, fmt.Errorf("%s is a directory, and get moves one file", remote))
		return r
	}
	if maxSize > 0 && fi.Size() > maxSize {
		r.Err = result.Usage.Wrap(alias, fmt.Errorf("%s is %d bytes, over --max-size %d", remote, fi.Size(), maxSize))
		return r
	}
	src, err := sc.Open(remote)
	if err != nil {
		r.Err = result.Transfer.Wrap(alias, err)
		return r
	}
	defer func() { _ = src.Close() }()

	tmp := localTempName(local)
	return move(ctx, c, r.Command,
		func() (int64, error) { return download(src, tmp, local) },
		func() { _ = os.Remove(tmp) })
}

// move runs the copy a transfer is and scores it. body writes to a temporary
// name and renames into place; discard unlinks that temporary on whichever side
// holds it. Cancellation gets discard in while the connection is still up, then
// takes the socket away, and move does not return until that window has closed:
// returning earlier would let the caller's Conn.Close cut cleanup short.
func move(ctx context.Context, c *client.Conn, command string, body func() (int64, error), discard func()) result.Result {
	r := result.Result{Host: c.Host.Alias, Command: command}
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
// within one filesystem. The leading dot keeps it out of an unsuffixed glob and
// the pid keeps two concurrent errands off each other's file.
func tempName(remote string) string {
	return path.Join(path.Dir(remote), "."+path.Base(remote)+".errand-"+strconv.Itoa(os.Getpid()))
}

// localTempName is the same name on this side of the connection, where the
// separator is the local one rather than SFTP's slash.
func localTempName(local string) string {
	return filepath.Join(filepath.Dir(local), "."+filepath.Base(local)+".errand-"+strconv.Itoa(os.Getpid()))
}

func upload(sc *sftp.Client, src io.Reader, tmp, remote string, mode fs.FileMode) (int64, error) {
	w, err := sc.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(w, src)
	if err == nil {
		err = w.Chmod(mode)
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
func download(src io.Reader, tmp, local string) (int64, error) {
	w, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(w, src)
	if cerr := w.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return n, err
	}
	return n, os.Rename(tmp, local)
}

// rename puts the finished bytes under their final name. posix-rename replaces
// an existing destination in one step; without the extension the destination
// has to go first, which is the one moment a reader can see neither file.
func rename(sc *sftp.Client, tmp, remote string) error {
	if _, ok := sc.HasExtension("posix-rename@openssh.com"); ok {
		return sc.PosixRename(tmp, remote)
	}
	_ = sc.Remove(remote)
	return sc.Rename(tmp, remote)
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
