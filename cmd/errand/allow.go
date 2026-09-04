package main

import (
	"errors"
	"fmt"
	"io"
	"strings"

	allowlist "github.com/MatrixMagician/Errand/internal/allow"
)

// errPut is put's verdict: every write to a Host is put to the human.
var errPut = errors.New("put")

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
	case "run":
		verdict = allowlist.Check(inv.host.AllowCommands, strings.Join(inv.fs.Args(), " "))
	}
	if verdict == nil {
		return 0
	}
	fmt.Fprintln(stdout, verdict)
	return 1
}
