package transfer

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/MatrixMagician/Errand/internal/sshtest"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// suffix matches the random tail both temp names end in: 8 bytes of hex,
// which nobody can plant a symlink at ahead of time the way a pid allowed.
var suffix = regexp.MustCompile(`^\.errand-[0-9a-f]{16}$`)

func TestTempNameIsAHiddenUnpredictableSiblingOfTheDestination(t *testing.T) {
	for _, tc := range []struct{ remote, prefix string }{
		{"/tmp/dest/f.txt", "/tmp/dest/.f.txt"},
		{"/f", "/.f"},
		{"f", ".f"},
		{"a/b/../c", "a/.c"},
	} {
		got := tempName(tc.remote)
		rest, ok := strings.CutPrefix(got, tc.prefix)
		if !ok || !suffix.MatchString(rest) {
			t.Errorf("tempName(%q) = %q, want %s.errand-<16 hex>", tc.remote, got, tc.prefix)
		}
		if again := tempName(tc.remote); again == got {
			t.Errorf("tempName(%q) returned %q twice, want a fresh name per call", tc.remote, got)
		}
	}
}

func TestLocalTempNameIsAHiddenUnpredictableSiblingOfTheDestination(t *testing.T) {
	for _, tc := range []struct{ local, prefix string }{
		{"/tmp/dest/f.txt", "/tmp/dest/.f.txt"},
		{"/f", "/.f"},
		{"f", ".f"},
		{"a/b/../c", "a/.c"},
	} {
		got := localTempName(tc.local)
		rest, ok := strings.CutPrefix(got, tc.prefix)
		if !ok || !suffix.MatchString(rest) {
			t.Errorf("localTempName(%q) = %q, want %s.errand-<16 hex>", tc.local, got, tc.prefix)
		}
	}
}

// TestDownloadRefusesAPlantedTemp is a symlink already standing at the exact
// temporary name: the create must fail rather than write through it.
func TestDownloadRefusesAPlantedTemp(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	local := filepath.Join(dir, "file")
	tmp := localTempName(local)
	if err := os.Symlink(victim, tmp); err != nil {
		t.Fatal(err)
	}

	if _, err := download(strings.NewReader("payload"), tmp, local, 0); err == nil {
		t.Error("download wrote through a planted symlink and reported no error")
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" {
		t.Errorf("victim holds %q, want it untouched", b)
	}
	if _, err := os.Lstat(local); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("lstat %s = %v, want the final name never to appear", local, err)
	}
}

// TestUploadAgainstOpenSSH runs upload against the harness's real sftp-server,
// whose handling of the exclusive-create flag is the thing under test.
func TestUploadAgainstOpenSSH(t *testing.T) {
	s := sshtest.Start(t)
	conn, err := ssh.Dial("tcp", s.Addr, &ssh.ClientConfig{
		User:              "root",
		Auth:              []ssh.AuthMethod{ssh.PublicKeys(s.ClientKey.Signer)},
		HostKeyCallback:   ssh.FixedHostKey(s.HostKey),
		HostKeyAlgorithms: []string{s.HostKey.Type()},
		Timeout:           10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	sc, err := sftp.NewClient(conn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sc.Close() })
	dir := "/tmp/" + t.Name()
	_ = sc.RemoveAll(dir)
	if err := sc.MkdirAll(dir); err != nil {
		t.Fatal(err)
	}

	t.Run("planted temp", func(t *testing.T) {
		victim, dest := dir+"/victim", dir+"/planted"
		writeRemote(t, sc, victim, "keep")
		tmp := tempName(dest)
		if err := sc.Symlink(victim, tmp); err != nil {
			t.Fatal(err)
		}
		if _, err := upload(sc, strings.NewReader("payload"), tmp, dest, 0o644, 0); err == nil {
			t.Error("upload wrote through a planted symlink and reported no error")
		}
		if got := readRemote(t, sc, victim); got != "keep" {
			t.Errorf("victim holds %q, want it untouched", got)
		}
		if _, err := sc.Lstat(dest); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("lstat %s = %v, want the final name never to appear", dest, err)
		}
	})

	t.Run("mode before bytes", func(t *testing.T) {
		dest := dir + "/secret"
		tmp := tempName(dest)
		pr, pw := io.Pipe()
		done := make(chan error, 1)
		go func() {
			_, err := upload(sc, pr, tmp, dest, 0o600, 0)
			done <- err
		}()
		if _, err := pw.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
		if fi, err := sc.Stat(tmp); err != nil {
			t.Error(err)
		} else if fi.Mode().Perm() != 0o600 {
			t.Errorf("temp mode mid-upload = %04o, want 0600 before the first byte lands", fi.Mode().Perm())
		}
		_ = pw.CloseWithError(errors.New("cut"))
		if err := <-done; err == nil {
			t.Error("upload of a cut source reported no error")
		}
	})
}

func writeRemote(t *testing.T, sc *sftp.Client, name, content string) {
	t.Helper()
	f, err := sc.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func readRemote(t *testing.T, sc *sftp.Client, name string) string {
	t.Helper()
	f, err := sc.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestDownloadCutPartwayNeverReachesTheFinalName is the local half of the
// guarantee: bytes that stop arriving stay under the temporary name, which the
// caller unlinks, and the destination the operator asked for never appears.
func TestDownloadCutPartwayNeverReachesTheFinalName(t *testing.T) {
	dir := t.TempDir()
	local := filepath.Join(dir, "file")
	tmp := localTempName(local)
	src := io.MultiReader(strings.NewReader("half"), iotest.ErrReader(errors.New("cut")))

	n, err := download(src, tmp, local, 0)
	if err == nil {
		t.Fatalf("download copied %d bytes and reported no error", n)
	}
	if _, err := os.Stat(local); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("stat %s = %v, want the final name never to appear", local, err)
	}
	if _, err := os.Stat(tmp); err != nil {
		t.Errorf("stat %s = %v, want the partial bytes under the temporary name", tmp, err)
	}
}

// TestDownloadPastMaxSizeNeverReachesTheFinalName is a source that grows after
// its stat said it fit: the copy stops one byte past the cap and the bytes stay
// under the temporary name.
func TestDownloadPastMaxSizeNeverReachesTheFinalName(t *testing.T) {
	local := filepath.Join(t.TempDir(), "file")
	tmp := localTempName(local)

	n, err := download(strings.NewReader(strings.Repeat("x", 100)), tmp, local, 10)
	if err == nil || !strings.Contains(err.Error(), "--max-size") {
		t.Errorf("download = %d, %v; want an error naming --max-size", n, err)
	}
	if n != 11 {
		t.Errorf("download copied %d bytes, want 11: the cap plus the one that proves it was crossed", n)
	}
	if _, err := os.Stat(local); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("stat %s = %v, want the final name never to appear", local, err)
	}
}

// TestRenameWithoutPosixRenameLeavesTheDestinationAlone pins the one rename
// path: a server that lacks posix-rename gets an error, never a remove-then-
// rename that would take an empty directory standing at the destination.
func TestRenameWithoutPosixRenameLeavesTheDestinationAlone(t *testing.T) {
	if err := sftp.SetSFTPExtensions(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = sftp.SetSFTPExtensions("hardlink@openssh.com", "posix-rename@openssh.com", "statvfs@openssh.com")
	})

	cr, sw := io.Pipe()
	sr, cw := io.Pipe()
	srv, err := sftp.NewServer(struct {
		io.Reader
		io.WriteCloser
	}{sr, sw})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve() }()
	sc, err := sftp.NewClientPipe(cr, cw)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = srv.Close()
		_ = sc.Close()
	})

	dest := filepath.Join(t.TempDir(), "emptydir")
	if err := os.Mkdir(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	tmp := tempName(dest)
	if err := os.WriteFile(tmp, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	err = rename(sc, tmp, dest)
	if err == nil || !strings.Contains(err.Error(), "posix-rename") {
		t.Errorf("rename = %v, want an error naming the missing posix-rename extension", err)
	}
	if fi, err := os.Stat(dest); err != nil || !fi.IsDir() {
		t.Errorf("stat %s = %v, %v; want the directory still standing", dest, fi, err)
	}
}
