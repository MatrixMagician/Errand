package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/MatrixMagician/Errand/internal/result"
)

func runCLI(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestVersion(t *testing.T) {
	code, out, _ := runCLI(t, "version")
	if code != 0 || !strings.HasPrefix(out, "errand ") {
		t.Errorf("code=%d out=%q", code, out)
	}
}

func TestHostsMatchesGolden(t *testing.T) {
	t.Setenv("ERRAND_CONFIG", "testdata/fixture.toml")
	code, out, stderr := runCLI(t, "hosts")
	if code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
	want, err := os.ReadFile("testdata/hosts.golden")
	if err != nil {
		t.Fatal(err)
	}
	if out != string(want) {
		t.Errorf("hosts output differs from golden:\n--- got ---\n%s--- want ---\n%s", out, want)
	}
}

func TestExit250(t *testing.T) {
	t.Setenv("ERRAND_CONFIG", "testdata/fixture.toml")
	cases := map[string][]string{
		"no args":              nil,
		"unknown subcommand":   {"frobnicate"},
		"bad flag":             {"hosts", "--nope"},
		"bad flag on run":      {"run", "--nope", "web-prod", "--", "true"},
		"run missing host":     {"run"},
		"run missing command":  {"run", "web-prod"},
		"unparseable size":     {"run", "web-prod", "--max-output", "1GB", "--", "true"},
		"put not implemented":  {"put", "web-prod", "a", "b"},
		"get not implemented":  {"get", "web-prod", "a", "b"},
		"check takes no stdin": {"check", "web-prod", "--stdin"},
		"check takes no env":   {"check", "web-prod", "--env", "A=b"},
		"check takes no pty":   {"check", "web-prod", "--pty"},
		"check takes no cap":   {"check", "web-prod", "--max-output", "1KiB"},
		"check takes no args":  {"check", "web-prod", "uptime"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			code, _, stderr := runCLI(t, args...)
			if code != 250 || !strings.HasPrefix(stderr, "errand: ") {
				t.Errorf("code=%d stderr=%q", code, stderr)
			}
		})
	}
}

func TestUnknownAliasNamesAliasAndPath(t *testing.T) {
	t.Setenv("ERRAND_CONFIG", "testdata/fixture.toml")
	code, _, stderr := runCLI(t, "check", "ghost")
	if code != 250 || !strings.Contains(stderr, `"ghost"`) || !strings.Contains(stderr, "testdata/fixture.toml") {
		t.Errorf("code=%d stderr=%q", code, stderr)
	}
}

func TestMalformedConfig(t *testing.T) {
	p := t.TempDir() + "/bad.toml"
	if err := os.WriteFile(p, []byte("[hosts.a]\nhostname = \"x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ERRAND_CONFIG", p)
	code, _, stderr := runCLI(t, "hosts")
	if code != 250 || !strings.Contains(stderr, "line 2") {
		t.Errorf("code=%d stderr=%q", code, stderr)
	}
}

func TestHelpExitsZero(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"-h"}, {"help"}, {"run", "--help"}} {
		code, out, stderr := runCLI(t, args...)
		if code != 0 || !strings.Contains(out+stderr, "errand run") {
			t.Errorf("%v: code=%d out=%q stderr=%q", args, code, out, stderr)
		}
	}
}

func TestBudgetsCountConnectInsideTheTotal(t *testing.T) {
	cases := []struct {
		name           string
		total, connect time.Duration
	}{
		{"connect shorter", 5 * time.Second, time.Second},
		{"connect longer", 5 * time.Second, 10 * time.Second},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			run, dial, cancel := budgets(context.Background(), c.total, c.connect)
			defer cancel()
			total, ok := run.Deadline()
			if !ok {
				t.Fatal("the total budget has no deadline")
			}
			conn, ok := dial.Deadline()
			if !ok {
				t.Fatal("the connect budget has no deadline")
			}
			if conn.After(total) {
				t.Errorf("connect deadline %v is later than the total deadline %v", conn, total)
			}
			if want := min(c.total, c.connect); conn.Sub(time.Now().Add(want)).Abs() > time.Second {
				t.Errorf("connect deadline is %v away, want about %v", time.Until(conn), want)
			}
		})
	}
}

func TestBudgetsCauseIsTimeout(t *testing.T) {
	run, dial, cancel := budgets(context.Background(), time.Millisecond, time.Hour)
	defer cancel()
	<-run.Done()
	for _, ctx := range []context.Context{run, dial} {
		if !errors.Is(context.Cause(ctx), result.ErrTimeout) {
			t.Errorf("cause is %v, want a timeout", context.Cause(ctx))
		}
	}
}

func TestEnvFlag(t *testing.T) {
	var env envFlag
	for _, v := range []string{"FOO=bar", "EMPTY=", "WITH=an=equals"} {
		if err := env.Set(v); err != nil {
			t.Errorf("Set(%q): %v", v, err)
		}
	}
	if want := []string{"FOO=bar", "EMPTY=", "WITH=an=equals"}; !slices.Equal(env, want) {
		t.Errorf("env = %q, want %q", env, want)
	}
	err := env.Set("NOEQUALS")
	if err == nil || !strings.Contains(err.Error(), "KEY=VAL") {
		t.Errorf("Set(\"NOEQUALS\") = %v, want a KEY=VAL complaint", err)
	}
	if len(env) != 3 {
		t.Errorf("a rejected value was still collected: %q", env)
	}
}

func TestQuietSilencesOnlyErrandsOwnDiagnostics(t *testing.T) {
	var loud, quiet bytes.Buffer
	diagnostics(&loud, false)("saying %s", "something")
	diagnostics(&quiet, true)("saying %s", "something")
	if loud.String() != "errand: saying something\n" {
		t.Errorf("loud = %q", loud.String())
	}
	if quiet.Len() != 0 {
		t.Errorf("quiet = %q, want nothing", quiet.String())
	}
}

// TestCheckDeclaresTheSharedFlags pins the split registerFlags makes: the three
// flags that bound a connection are check's too, the ones that shape a command
// are not.
func TestCheckDeclaresTheSharedFlags(t *testing.T) {
	shared := []string{"timeout", "connect-timeout", "quiet"}
	runOnly := []string{"stdin", "pty", "env", "max-output"}
	for _, sub := range []string{"run", "check"} {
		fs := flag.NewFlagSet(sub, flag.ContinueOnError)
		registerFlags(fs, sub)
		for _, name := range shared {
			if fs.Lookup(name) == nil {
				t.Errorf("%s does not declare --%s", sub, name)
			}
		}
		for _, name := range runOnly {
			if got, want := fs.Lookup(name) != nil, sub == "run"; got != want {
				t.Errorf("%s declares --%s: %v, want %v", sub, name, got, want)
			}
		}
	}
}
