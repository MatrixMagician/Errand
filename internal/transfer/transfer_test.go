package transfer

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"
)

func TestTempNameIsAHiddenSiblingOfTheDestination(t *testing.T) {
	pid := os.Getpid()
	for _, tc := range []struct{ remote, want string }{
		{"/tmp/dest/f.txt", fmt.Sprintf("/tmp/dest/.f.txt.errand-%d", pid)},
		{"/f", fmt.Sprintf("/.f.errand-%d", pid)},
		{"f", fmt.Sprintf(".f.errand-%d", pid)},
		{"a/b/../c", fmt.Sprintf("a/.c.errand-%d", pid)},
	} {
		got := tempName(tc.remote)
		if got != tc.want {
			t.Errorf("tempName(%q) = %q, want %q", tc.remote, got, tc.want)
		}
		if path.Dir(got) != path.Dir(path.Clean(tc.remote)) {
			t.Errorf("tempName(%q) = %q, not a sibling", tc.remote, got)
		}
		if got == path.Clean(tc.remote) || !strings.HasPrefix(path.Base(got), ".") {
			t.Errorf("tempName(%q) = %q, want a hidden name distinct from the destination", tc.remote, got)
		}
	}
}

func TestLocalTempNameIsAHiddenSiblingOfTheDestination(t *testing.T) {
	pid := os.Getpid()
	for _, tc := range []struct{ local, want string }{
		{"/tmp/dest/f.txt", fmt.Sprintf("/tmp/dest/.f.txt.errand-%d", pid)},
		{"/f", fmt.Sprintf("/.f.errand-%d", pid)},
		{"f", fmt.Sprintf(".f.errand-%d", pid)},
		{"a/b/../c", fmt.Sprintf("a/.c.errand-%d", pid)},
	} {
		got := localTempName(tc.local)
		if got != tc.want {
			t.Errorf("localTempName(%q) = %q, want %q", tc.local, got, tc.want)
		}
		if filepath.Dir(got) != filepath.Dir(filepath.Clean(tc.local)) {
			t.Errorf("localTempName(%q) = %q, not a sibling", tc.local, got)
		}
	}
}

// TestDownloadCutPartwayNeverReachesTheFinalName is the local half of the
// guarantee: bytes that stop arriving stay under the temporary name, which the
// caller unlinks, and the destination the operator asked for never appears.
func TestDownloadCutPartwayNeverReachesTheFinalName(t *testing.T) {
	dir := t.TempDir()
	local := filepath.Join(dir, "file")
	tmp := localTempName(local)
	src := io.MultiReader(strings.NewReader("half"), iotest.ErrReader(errors.New("cut")))

	n, err := download(src, tmp, local)
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
