package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	allowlist "github.com/MatrixMagician/Errand/internal/allow"
)

// errPut is put's verdict: every write to a Host is put to the human.
var errPut = errors.New("put")

// errGetOutsideCwd is get's verdict when its local destination does not
// resolve inside the current working directory (issue #47): get writes
// wherever it is told, so a destination outside cwd is put to the human the
// same as put.
var errGetOutsideCwd = errors.New("get outside cwd")

// allow answers whether the invocation in rest would be Unattended. It parses
// exactly as the judged subcommand would, so a usage or configuration error is
// reported the same way, but it never dials and never writes the audit log.
func allow(rest []string, stdout, stderr io.Writer) int {
	diag := diagnostics(stderr, false)
	if len(rest) == 0 {
		return failUsage(stderr, diag, errors.New("allow: missing <subcommand>"))
	}
	sub, args := rest[0], rest[1:]
	var inv *invocation
	switch sub {
	case "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	case "help", "version":
		return 0
	case "hosts", "run", "put", "get", "check":
		// The judged subcommand's own --json envelope and usage text are its
		// output, not this verdict's, so they are parsed and discarded.
		var code int
		if inv, code = parse(sub, args, io.Discard, stderr); inv == nil {
			return code
		}
	default:
		return failUsage(stderr, diag, fmt.Errorf("unknown subcommand %q", sub))
	}

	var verdict error
	switch inv.sub {
	case "put":
		verdict = errPut
	case "get":
		verdict = checkGetDestination(inv.fs.Arg(1))
	case "run":
		verdict = allowlist.Check(inv.host.AllowCommands, strings.Join(inv.fs.Args(), " "))
	}
	if verdict == nil {
		return 0
	}
	fmt.Fprintln(stdout, verdict)
	return 1
}

// checkGetDestination is get's verdict: nil when local resolves inside the
// current working directory, else errGetOutsideCwd. cwd and local's parent
// are both symlink-resolved before comparing, so a symlinked cwd (macOS's
// /tmp, a symlinked home) does not make an in-cwd get look like an escape,
// and a symlinked parent that escapes cwd does not stand in for a plain path
// outside it. Either resolution failing to run fails closed rather than
// falling back to an unresolved comparison, so the verdict never depends on
// local's parent existing yet, even though get is what creates it.
func checkGetDestination(local string) error {
	cwd, err := os.Getwd()
	if err != nil {
		return errGetOutsideCwd
	}
	cwd, err = filepath.EvalSymlinks(cwd)
	if err != nil {
		return errGetOutsideCwd
	}
	abs, err := filepath.Abs(local)
	if err != nil {
		return errGetOutsideCwd
	}
	resolved, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return errGetOutsideCwd
	}
	abs = filepath.Join(resolved, filepath.Base(abs))
	rel, err := filepath.Rel(cwd, abs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return errGetOutsideCwd
	}
	return nil
}
