// Command errand is a non-interactive SSH client for agentic use. See SPEC.md.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strings"
	"text/tabwriter"

	"github.com/MatrixMagician/Errand/internal/config"
)

// version is overridden at build time: -ldflags "-X main.version=v1.2.3".
var version = "dev"

// Exit codes reserved for client-side failures (SPEC §5.2).
const exitUsage = 250

const usage = `usage:
  errand run   <host> [flags] -- <command...>   execute a command
  errand put   <host> [flags] <local> <remote>  upload a file (SFTP)
  errand get   <host> [flags] <remote> <local>  download a file (SFTP)
  errand check <host> [flags]                   preflight: resolve, connect, authenticate
  errand hosts                                  list declared hosts and resolved parameters
  errand version                                print the version

<host> is an alias declared in the config file (default ~/.config/errand/config.toml,
overridable with ERRAND_CONFIG). Exit 250 on usage or configuration errors.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run dispatches args and returns the process exit code. Errand's own
// diagnostics go to stderr prefixed "errand: " (SPEC §5.1).
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, "errand: missing subcommand\n"+usage)
		return exitUsage
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	case "version":
		fmt.Fprintf(stdout, "errand %s\n", buildVersion())
		return 0
	}

	fs := flag.NewFlagSet("errand "+sub, flag.ContinueOnError)
	fs.SetOutput(io.Discard) // we print errors ourselves with the errand: prefix
	fs.Usage = func() {}     // printed by us: on -h below, never on a parse error
	switch sub {
	case "hosts", "run", "put", "get", "check":
	default:
		fmt.Fprintf(stderr, "errand: unknown subcommand %q\n%s", sub, usage)
		return exitUsage
	}
	if err := fs.Parse(rest); err != nil {
		if err == flag.ErrHelp {
			fmt.Fprint(stdout, usage)
			return 0
		}
		fmt.Fprintf(stderr, "errand: %s: %v\n", sub, err)
		return exitUsage
	}

	cfg, err := config.Load(config.DefaultPath())
	if err != nil {
		fmt.Fprintf(stderr, "errand: %v\n", err)
		return exitUsage
	}
	if sub == "hosts" {
		return hosts(cfg, stdout)
	}

	// run/put/get/check: resolve the alias now so the allowlist is enforced
	// even before the implementation lands (M2/M4).
	if fs.NArg() == 0 {
		fmt.Fprintf(stderr, "errand: %s: missing <host>\n", sub)
		return exitUsage
	}
	if _, err := cfg.Resolve(fs.Arg(0)); err != nil {
		fmt.Fprintf(stderr, "errand: %v\n", err)
		return exitUsage
	}
	fmt.Fprintf(stderr, "errand: %s: not implemented\n", sub)
	return exitUsage
}

func hosts(cfg *config.File, stdout io.Writer) int {
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ALIAS\tHOSTNAME\tPORT\tUSER\tTIMEOUT\tMAX_OUTPUT\tACCEPT_NEW\tHOST_KEY")
	for _, alias := range cfg.Aliases() {
		h, _ := cfg.Resolve(alias) // alias came from cfg.Aliases(), cannot be unknown
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\n",
			h.Alias, h.Hostname, h.Port, h.User, h.Timeout, h.MaxOutput, yesNo(h.AcceptNew), pinned(h.HostKey))
	}
	tw.Flush()
	return 0
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// pinned shows only the key type; the full key is in the config for anyone who needs it.
func pinned(key string) string {
	if key == "" {
		return "-"
	}
	return strings.Fields(key)[0] + " (pinned)"
}

func buildVersion() string {
	if version != "dev" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return version
}
