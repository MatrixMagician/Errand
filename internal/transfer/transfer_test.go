package transfer

import (
	"fmt"
	"os"
	"path"
	"strings"
	"testing"
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
