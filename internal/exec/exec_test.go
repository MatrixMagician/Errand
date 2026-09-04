package exec

import (
	"errors"
	"strings"
	"testing"

	"github.com/MatrixMagician/Errand/internal/result"
)

func TestCounterIsExact(t *testing.T) {
	var sink strings.Builder
	c := &counter{w: &sink}
	for _, s := range []string{"", "one", "two\n", strings.Repeat("x", 5000)} {
		if _, err := c.Write([]byte(s)); err != nil {
			t.Fatal(err)
		}
	}
	if want := int64(sink.Len()); c.n.Load() != want {
		t.Errorf("counted %d bytes, wrote %d", c.n.Load(), want)
	}
	if c.n.Load() != 5007 {
		t.Errorf("counted %d, want 5007", c.n.Load())
	}
}

func TestFromWait(t *testing.T) {
	remote, err := fromWait("h", nil)
	if err != nil || remote == nil || remote.Exit != 0 {
		t.Errorf("clean exit: remote=%+v err=%v", remote, err)
	}
	remote, err = fromWait("h", errors.New("connection lost"))
	var phased *result.Error
	if remote != nil || !errors.As(err, &phased) || phased.Phase != result.Exec {
		t.Errorf("lost connection: remote=%+v err=%v", remote, err)
	}
}
