// Command errand is a non-interactive SSH client for agentic use. See SPEC.md.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/MatrixMagician/Errand/internal/client"
	"github.com/MatrixMagician/Errand/internal/config"
	"github.com/MatrixMagician/Errand/internal/exec"
	"github.com/MatrixMagician/Errand/internal/result"
)

// version is overridden at build time: -ldflags "-X main.version=v1.2.3".
var version = "dev"

const usage = `usage:
  errand run   <host> [flags] -- <command...>   execute a command
  errand put   <host> [flags] <local> <remote>  upload a file (SFTP)
  errand get   <host> [flags] <remote> <local>  download a file (SFTP)
  errand check <host> [flags]                   preflight: resolve, connect, authenticate
  errand hosts                                  list declared hosts and resolved parameters
  errand version                                print the version

flags for run:
  --stdin                                       stream local stdin to the remote command
  --timeout <dur>                               wall-clock limit for the whole invocation
  --connect-timeout <dur>                       limit for TCP, handshake and auth, within --timeout

<host> is an alias declared in the config file (default ~/.config/errand/config.toml,
overridable with ERRAND_CONFIG). Exit 250 on usage or configuration errors.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run dispatches args and returns the process exit code. Errand's own
// diagnostics go to stderr prefixed "errand: " (SPEC §5.1).
func run(args []string, stdout, stderr io.Writer) int {
	diag := diagnostics(stderr)
	if len(args) == 0 {
		return failUsage(stderr, diag, errors.New("missing subcommand"))
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	case "version":
		fmt.Fprintf(stdout, "errand %s\n", buildVersion())
		return 0
	case "hosts", "run", "put", "get", "check":
	default:
		return failUsage(stderr, diag, fmt.Errorf("unknown subcommand %q", sub))
	}

	fs := flag.NewFlagSet("errand "+sub, flag.ContinueOnError)
	fs.SetOutput(io.Discard) // we print errors ourselves with the errand: prefix
	fs.Usage = func() {}     // printed by us: on -h below, never on a parse error
	var stdin bool
	var timeout, connectTimeout time.Duration
	if sub == "run" {
		fs.BoolVar(&stdin, "stdin", false, "stream local stdin to the remote command")
		fs.DurationVar(&timeout, "timeout", 0, "wall-clock limit for the whole invocation")
		fs.DurationVar(&connectTimeout, "connect-timeout", defaultConnectTimeout, "limit for TCP, handshake and auth")
	}
	if err := fs.Parse(rest); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, usage)
			return 0
		}
		return fail(diag, result.Usage, "", fmt.Errorf("%s: %v", sub, err))
	}

	cfg, err := config.Load(config.DefaultPath())
	if err != nil {
		return fail(diag, result.Resolve, "", err)
	}
	if sub == "hosts" {
		return hosts(cfg, stdout, diag)
	}

	if fs.NArg() == 0 {
		return fail(diag, result.Usage, "", fmt.Errorf("%s: missing <host>", sub))
	}
	alias := fs.Arg(0)
	// Flags are also accepted after the host, so parse what follows it.
	if err := fs.Parse(fs.Args()[1:]); err != nil {
		return fail(diag, result.Usage, "", fmt.Errorf("%s: %v", sub, err))
	}
	h, err := cfg.Resolve(alias)
	if err != nil {
		return fail(diag, result.Resolve, alias, err)
	}
	if sub != "run" {
		return fail(diag, result.Usage, "", fmt.Errorf("%s: not implemented", sub))
	}

	command := strings.Join(fs.Args(), " ")
	if command == "" {
		return fail(diag, result.Usage, "", errors.New("run: missing <command>"))
	}
	var in io.Reader
	if stdin {
		in = os.Stdin
	}
	if !given(fs, "timeout") {
		timeout = h.Timeout
	}
	ctx, stop := interruptible(context.Background())
	defer stop()
	res := attempt(ctx, h, timeout, connectTimeout, diag, func(ctx context.Context, c *client.Conn) result.Result {
		return exec.Run(ctx, c, exec.Request{Command: command, Stdin: in, Stdout: stdout, Stderr: stderr})
	})
	res.Op = "run"
	return finish(res, diag)
}

// defaultConnectTimeout bounds TCP, handshake and auth (SPEC 4.1). Unlike
// --timeout it has no per-host setting, so the built-in is the only default.
const defaultConnectTimeout = 10 * time.Second

// given reports whether the flag was set on the command line, which is how
// "flag overrides configuration" is decided for a flag whose zero value is
// indistinguishable from an explicit one.
func given(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}

// budgets derives the two deadlines. The connect deadline is a child of the
// total one, so it can only ever be the earlier of the two: connect time is
// spent inside the invocation's budget, never on top of it.
func budgets(ctx context.Context, total, connect time.Duration) (context.Context, context.Context, func()) {
	run, cancelRun := context.WithTimeoutCause(ctx, total, result.ErrTimeout)
	dial, cancelDial := context.WithTimeoutCause(run, connect, result.ErrTimeout)
	return run, dial, func() { cancelDial(); cancelRun() }
}

// interruptible cancels ctx when errand itself is signalled, recording which
// signal so the exit code can be 128+n rather than a timeout's 254.
func interruptible(ctx context.Context) (context.Context, func()) {
	ctx, cancel := context.WithCancelCause(ctx)
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		if sig, ok := <-ch; ok {
			cancel(result.Interrupt{Signal: sig.(syscall.Signal)})
		}
	}()
	return ctx, func() {
		signal.Stop(ch)
		close(ch)
		cancel(context.Canceled)
	}
}

// attempt connects, runs body, and fills in what only the caller knows.
func attempt(ctx context.Context, h config.Host, timeout, connect time.Duration, diag client.Diag, body func(context.Context, *client.Conn) result.Result) result.Result {
	start := time.Now()
	target := fmt.Sprintf("%s@%s:%d", h.User, h.Hostname, h.Port)
	ctx, dctx, cancel := budgets(ctx, timeout, connect)
	defer cancel()
	conn, err := client.Dial(dctx, h, diag)
	if err != nil {
		return result.Result{Host: h.Alias, Target: target, Err: err, Elapsed: time.Since(start)}
	}
	defer func() { _ = conn.Close() }()

	res := body(ctx, conn)
	res.Host, res.Target = h.Alias, target
	res.Connect, res.Elapsed = conn.Connect, time.Since(start)
	return res
}

// finish is the single exit path: every outcome, including the ones that never
// reached a connection, is reported and scored here.
func finish(res result.Result, diag client.Diag) int {
	if d := res.Diagnostic(); d != "" {
		diag("%s", d)
	}
	return res.ExitCode()
}

func fail(diag client.Diag, phase result.Phase, host string, err error) int {
	return finish(result.Result{Host: host, Err: phase.Wrap(host, err)}, diag)
}

func failUsage(stderr io.Writer, diag client.Diag, err error) int {
	code := fail(diag, result.Usage, "", err)
	fmt.Fprint(stderr, usage)
	return code
}

func diagnostics(w io.Writer) client.Diag {
	return func(format string, args ...any) {
		fmt.Fprintf(w, "errand: "+format+"\n", args...)
	}
}

func hosts(cfg *config.File, stdout io.Writer, diag client.Diag) int {
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ALIAS\tHOSTNAME\tPORT\tUSER\tTIMEOUT\tMAX_OUTPUT\tACCEPT_NEW\tHOST_KEY")
	for _, alias := range cfg.Aliases() {
		h, _ := cfg.Resolve(alias) // alias came from cfg.Aliases(), cannot be unknown
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\n",
			h.Alias, h.Hostname, h.Port, h.User, h.Timeout, h.MaxOutput, yesNo(h.AcceptNew), pinned(h.HostKey))
	}
	if err := tw.Flush(); err != nil {
		return fail(diag, result.Usage, "", err)
	}
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
