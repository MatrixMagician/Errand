package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"regexp"
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
		"get missing paths":    {"get", "web-prod"},
		"get missing local":    {"get", "web-prod", "a"},
		"get extra path":       {"get", "web-prod", "a", "b", "c"},
		"get takes no mode":    {"get", "web-prod", "--mode", "0644", "a", "b"},
		"get takes no cap":     {"get", "web-prod", "--max-output", "1KiB", "a", "b"},
		"get unparseable size": {"get", "web-prod", "--max-size", "1GB", "a", "b"},
		"put missing paths":    {"put", "web-prod"},
		"put missing remote":   {"put", "web-prod", "a"},
		"put extra path":       {"put", "web-prod", "a", "b", "c"},
		"put takes no stdin":   {"put", "web-prod", "--stdin", "a", "b"},
		"put takes no cap":     {"put", "web-prod", "--max-output", "1KiB", "a", "b"},
		"put unparseable size": {"put", "web-prod", "--max-size", "1GB", "a", "b"},
		"put unparseable mode": {"put", "web-prod", "--mode", "rwx", "a", "b"},
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

// TestSubcommandsDeclareTheirFlags pins the split registerFlags makes: the four
// flags that bound a connection belong to every subcommand that opens one, and
// each of the rest belongs to exactly the subcommands listed against it.
func TestSubcommandsDeclareTheirFlags(t *testing.T) {
	shared := []string{"timeout", "connect-timeout", "quiet", "json"}
	owners := map[string][]string{
		"stdin":      {"run"},
		"pty":        {"run"},
		"env":        {"run"},
		"max-output": {"run"},
		"mode":       {"put"},
		"max-size":   {"put", "get"},
	}
	for _, sub := range []string{"run", "put", "get", "check"} {
		fs := flag.NewFlagSet(sub, flag.ContinueOnError)
		registerFlags(fs, sub)
		for _, name := range shared {
			if fs.Lookup(name) == nil {
				t.Errorf("%s does not declare --%s", sub, name)
			}
		}
		for name, subs := range owners {
			if got, want := fs.Lookup(name) != nil, slices.Contains(subs, sub); got != want {
				t.Errorf("%s declares --%s: %v, want %v", sub, name, got, want)
			}
		}
	}
}

// TestJSONEnvelopeSurvivesPreConnectionFailures is the wiring --json needs most:
// a caller parsing stdout gets a verdict even when errand never got as far as
// dialling, and gets it whichever side of the host the flag was written on.
func TestJSONEnvelopeSurvivesPreConnectionFailures(t *testing.T) {
	t.Setenv("ERRAND_CONFIG", "testdata/fixture.toml")
	cases := []struct {
		name string
		args []string
		kind string
	}{
		{"before the host", []string{"run", "--json", "ghost", "--", "true"}, "config"},
		{"after the host", []string{"run", "ghost", "--json", "--", "true"}, "config"},
		{"a usage error", []string{"run", "web-prod", "--json"}, "usage"},
		{"check too", []string{"check", "--json", "ghost"}, "config"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, stdout, stderr := runCLI(t, c.args...)
			if code != 250 {
				t.Fatalf("code=%d, want 250; stderr=%q", code, stderr)
			}
			var env struct {
				V      int    `json:"v"`
				Status string `json:"status"`
				Exit   int    `json:"exit_code"`
				Error  *struct {
					Kind    string `json:"kind"`
					Message string `json:"message"`
				} `json:"error"`
			}
			if err := json.Unmarshal([]byte(stdout), &env); err != nil {
				t.Fatalf("stdout is not the envelope: %v\nstdout: %q", err, stdout)
			}
			if env.V != 1 || env.Status != "client_error" || env.Exit != 250 {
				t.Errorf("envelope = %+v, want v1 client_error 250", env)
			}
			if env.Error == nil || env.Error.Kind != c.kind || env.Error.Message == "" {
				t.Errorf("error = %+v, want kind %q with a message", env.Error, c.kind)
			}
		})
	}
}

func TestWithoutJSONNothingIsWrittenToStdout(t *testing.T) {
	t.Setenv("ERRAND_CONFIG", "testdata/fixture.toml")
	code, stdout, _ := runCLI(t, "run", "ghost", "--", "true")
	if code != 250 || stdout != "" {
		t.Errorf("code=%d stdout=%q, want 250 and nothing on stdout", code, stdout)
	}
}

func TestPutModeIsParsedAsOctal(t *testing.T) {
	for _, tc := range []struct {
		arg  string
		want os.FileMode
		bad  bool
	}{
		{arg: "", want: 0o644},
		{arg: "0755", want: 0o755},
		{arg: "755", want: 0o755},
		{arg: "600", want: 0o600},
		{arg: "0999", bad: true},
		{arg: "rwx", bad: true},
		{arg: "-1", bad: true},
	} {
		fs := flag.NewFlagSet("put", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		o := registerFlags(fs, "put")
		var args []string
		if tc.arg != "" {
			args = []string{"--mode", tc.arg}
		}
		err := fs.Parse(args)
		switch {
		case tc.bad && err == nil:
			t.Errorf("--mode %q parsed to %04o, want a usage error", tc.arg, o.mode)
		case !tc.bad && err != nil:
			t.Errorf("--mode %q: %v", tc.arg, err)
		case !tc.bad && o.mode != tc.want:
			t.Errorf("--mode %q = %04o, want %04o", tc.arg, o.mode, tc.want)
		}
	}
}

// TestReadmeFlagTablesMatchUsage keeps the README's flag tables and the usage
// text naming the same flags, in both directions.
func TestReadmeFlagTablesMatchUsage(t *testing.T) {
	readme, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	inReadme := map[string]bool{}
	for _, m := range regexp.MustCompile("(?m)^\\| `(--[a-z-]+)").FindAllStringSubmatch(string(readme), -1) {
		inReadme[m[1]] = true
		if !regexp.MustCompile(`(?m)^  ` + m[1] + `( |$)`).MatchString(usage) {
			t.Errorf("README documents %s, usage does not list it", m[1])
		}
	}
	if len(inReadme) == 0 {
		t.Fatal("no flag rows found in README")
	}
	for _, m := range regexp.MustCompile(`(?m)^  (--[a-z-]+)`).FindAllStringSubmatch(usage, -1) {
		if !inReadme[m[1]] {
			t.Errorf("usage lists %s, the README's flag tables do not", m[1])
		}
	}
}

func TestMaxSizeDefaultsTo64MiB(t *testing.T) {
	for _, sub := range []string{"put", "get"} {
		fs := flag.NewFlagSet(sub, flag.ContinueOnError)
		o := registerFlags(fs, sub)
		if err := fs.Parse(nil); err != nil || o.maxSize != 64<<20 {
			t.Errorf("%s: maxSize=%d err=%v, want %d", sub, o.maxSize, err, 64<<20)
		}
	}
}

// TestAllowFixedVerdicts pins the subcommands whose verdict does not depend on
// the Command allowlist: everything that only reads is Unattended, and put,
// the one write, never is.
func TestAllowFixedVerdicts(t *testing.T) {
	t.Setenv("ERRAND_CONFIG", "testdata/fixture.toml")
	cases := []struct {
		args   []string
		code   int
		stdout string
	}{
		{args: []string{"hosts"}},
		{args: []string{"version"}},
		{args: []string{"help"}},
		{args: []string{"check", "web-prod"}},
		{args: []string{"get", "web-prod", "a", "b"}},
		{args: []string{"put", "web-prod", "a", "b"}, code: 1, stdout: "put\n"},
	}
	for _, c := range cases {
		t.Run(strings.Join(c.args, " "), func(t *testing.T) {
			code, stdout, stderr := runCLI(t, append([]string{"allow"}, c.args...)...)
			if code != c.code || stdout != c.stdout {
				t.Errorf("code=%d stdout=%q, want %d and %q; stderr=%q", code, stdout, c.code, c.stdout, stderr)
			}
		})
	}
}

// TestAllowJudgesRunByItsCommand covers the one verdict the operator controls:
// the Host's list replaces the defaults', the separator is optional, and no
// flag on either side of the alias moves the answer.
func TestAllowJudgesRunByItsCommand(t *testing.T) {
	t.Setenv("ERRAND_CONFIG", "testdata/fixture.toml")
	cases := []struct {
		args   []string
		code   int
		stdout string
	}{
		{args: []string{"run", "lab", "--", "df", "-h"}},
		{args: []string{"run", "lab", "--", "uptime"}},
		{args: []string{"run", "lab", "--", "reboot"}, code: 1, stdout: "not on allowlist: reboot\n"},
		{args: []string{"run", "web-prod", "--", "df"}, code: 1, stdout: "not on allowlist: df\n"},
		{args: []string{"run", "web-prod", "--", "uptime"}},
		{args: []string{"run", "lab", "df", "-h"}},
		{args: []string{"run", "--json", "lab", "--quiet", "--timeout", "5s", "--stdin", "--env", "A=b", "--max-output", "1KiB", "--", "df", "-h"}},
		{args: []string{"run", "--json", "lab", "--", "reboot"}, code: 1, stdout: "not on allowlist: reboot\n"},
	}
	for _, c := range cases {
		t.Run(strings.Join(c.args, " "), func(t *testing.T) {
			code, stdout, stderr := runCLI(t, append([]string{"allow"}, c.args...)...)
			if code != c.code || stdout != c.stdout {
				t.Errorf("code=%d stdout=%q, want %d and %q; stderr=%q", code, stdout, c.code, c.stdout, stderr)
			}
		})
	}
}

func TestAllowEmptyListRefusesEverything(t *testing.T) {
	p := t.TempDir() + "/config.toml"
	body := "[defaults]\nallow_commands = [\"df\"]\n\n[hosts.h]\nhostname = \"h\"\nallow_commands = []\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ERRAND_CONFIG", p)
	code, stdout, stderr := runCLI(t, "allow", "run", "h", "--", "df")
	if code != 1 || stdout != "not on allowlist: df\n" {
		t.Errorf("code=%d stdout=%q, want 1 and the reason; stderr=%q", code, stdout, stderr)
	}
}

func TestAllowExit250(t *testing.T) {
	t.Setenv("ERRAND_CONFIG", "testdata/fixture.toml")
	cases := map[string][]string{
		"no subcommand":      {"allow"},
		"unknown subcommand": {"allow", "frobnicate"},
		"run missing host":   {"allow", "run"},
		"unknown alias":      {"allow", "run", "ghost", "--", "df"},
		"run missing":        {"allow", "run", "lab"},
		"bad flag on run":    {"allow", "run", "--nope", "lab", "--", "df"},
		"put missing remote": {"allow", "put", "lab", "a"},
		"get extra path":     {"allow", "get", "lab", "a", "b", "c"},
		"check takes no arg": {"allow", "check", "lab", "x"},
		"bad flag on hosts":  {"allow", "hosts", "--nope"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			code, _, stderr := runCLI(t, args...)
			if code != 250 || !strings.HasPrefix(stderr, "errand: ") {
				t.Errorf("code=%d stderr=%q", code, stderr)
			}
		})
	}
	// The judged subcommand's envelope is its own output, never the verdict's.
	if code, stdout, _ := runCLI(t, "allow", "run", "--json", "ghost", "--", "df"); code != 250 || stdout != "" {
		t.Errorf("code=%d stdout=%q, want 250 and nothing on stdout", code, stdout)
	}
}

// TestAllowIsSilentOnUnattended is what a harness reads: an Unattended verdict
// is the exit code and nothing else, on either stream.
func TestAllowIsSilentOnUnattended(t *testing.T) {
	t.Setenv("ERRAND_CONFIG", "testdata/fixture.toml")
	cases := [][]string{
		{"allow", "hosts"},
		{"allow", "version"},
		{"allow", "help"},
		{"allow", "check", "web-prod"},
		{"allow", "get", "web-prod", "a", "b"},
		{"allow", "run", "--json", "lab", "--", "df", "-h"},
	}
	for _, args := range cases {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			code, stdout, stderr := runCLI(t, args...)
			if code != 0 || stdout != "" || stderr != "" {
				t.Errorf("code=%d stdout=%q stderr=%q, want 0 and silence", code, stdout, stderr)
			}
		})
	}
}

func TestAllowLeavesTheAuditLogUntouched(t *testing.T) {
	t.Setenv("ERRAND_CONFIG", "testdata/fixture.toml")
	state := t.TempDir()
	t.Setenv("XDG_STATE_HOME", state)
	for _, args := range [][]string{
		{"allow", "run", "lab", "--", "df"},
		{"allow", "run", "lab", "--", "reboot"},
		{"allow", "put", "lab", "a", "b"},
	} {
		runCLI(t, args...)
	}
	entries, err := os.ReadDir(state)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("allow wrote %v into the state directory", entries)
	}
}
