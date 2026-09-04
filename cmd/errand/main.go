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

	"github.com/MatrixMagician/Errand/internal/audit"
	"github.com/MatrixMagician/Errand/internal/client"
	"github.com/MatrixMagician/Errand/internal/config"
	"github.com/MatrixMagician/Errand/internal/envelope"
	"github.com/MatrixMagician/Errand/internal/exec"
	"github.com/MatrixMagician/Errand/internal/result"
)

// version is overridden at build time: -ldflags "-X main.version=v1.2.3".
var version = "dev"

const usage = `usage:
  errand run   <host> [flags] -- <command...>   execute a command
  errand put   <host> [flags] <local> <remote>  upload a file (SFTP)
  errand get   <host> [flags] <remote> <local>  download a file (SFTP)
  errand check <host> [flags]                   preflight: connect, authenticate, run 'true'
  errand hosts                                  list declared hosts and resolved parameters
  errand version                                print the version

flags for run and check:
  --timeout <dur>                               wall-clock limit for the whole invocation
  --connect-timeout <dur>                       limit for TCP, handshake and auth, within --timeout
  --quiet                                       suppress errand's own diagnostics, never the remote's
  --json                                        write a JSON result envelope as the final line of stdout

flags for run only:
  --stdin                                       stream local stdin to the remote command
  --max-output <bytes>                          combined cap across stdout and stderr; 0 disables
  --env KEY=VAL                                 set a remote environment variable; repeatable
  --pty                                         request a PTY for tools that refuse to run without one

<host> is an alias declared in the config file (default ~/.config/errand/config.toml,
overridable with ERRAND_CONFIG). Exit 250 on usage or configuration errors.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run dispatches args and returns the process exit code. Errand's own
// diagnostics go to stderr prefixed "errand: " (SPEC §5.1).
func run(args []string, stdout, stderr io.Writer) int {
	diag := diagnostics(stderr, false)
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
	o := registerFlags(fs, sub)
	perr := fs.Parse(rest)
	// Even a failed parse may have seen --json already, and a caller who asked
	// for machine-readable output wants it for the failure too.
	env := jsonOutput(nil, o, stdout)
	if perr != nil {
		if errors.Is(perr, flag.ErrHelp) {
			fmt.Fprint(stdout, usage)
			return 0
		}
		return fail(diag, env, result.Usage, "", fmt.Errorf("%s: %v", sub, perr))
	}

	cfg, err := config.Load(config.DefaultPath())
	if err != nil {
		return fail(diag, env, result.Resolve, "", err)
	}
	if sub == "hosts" {
		return hosts(cfg, stdout, diag)
	}

	if fs.NArg() == 0 {
		return fail(diag, env, result.Usage, "", fmt.Errorf("%s: missing <host>", sub))
	}
	alias := fs.Arg(0)
	// Flags are also accepted after the host, so parse what follows it.
	perr = fs.Parse(fs.Args()[1:])
	env = jsonOutput(env, o, stdout)
	if perr != nil {
		return fail(diag, env, result.Usage, "", fmt.Errorf("%s: %v", sub, perr))
	}
	// Only now is --quiet known. Everything above it is a usage error, which
	// is the one diagnostic an operator needs whether they asked for it or not.
	diag = diagnostics(stderr, o.quiet)
	h, err := cfg.Resolve(alias)
	if err != nil {
		return fail(diag, env, result.Resolve, alias, err)
	}
	if sub != "run" && sub != "check" {
		return fail(diag, env, result.Usage, "", fmt.Errorf("%s: not implemented", sub))
	}

	var req exec.Request
	if sub == "run" {
		command := strings.Join(fs.Args(), " ")
		if command == "" {
			return fail(diag, env, result.Usage, "", errors.New("run: missing <command>"))
		}
		if !given(fs, "max-output") {
			o.maxOutput = int64(h.MaxOutput)
		}
		var in io.Reader
		if o.stdin {
			in = os.Stdin
		}
		// Remote stdout goes through the envelope writer so it knows where the
		// output ended; nothing is buffered and nothing is rewritten.
		out := stdout
		if env != nil {
			out = env
		}
		req = exec.Request{
			Command: command, Stdin: in, Stdout: out, Stderr: stderr,
			MaxOutput: o.maxOutput, Env: o.env, PTY: o.pty,
		}
	} else {
		if fs.NArg() > 0 {
			return fail(diag, env, result.Usage, "", fmt.Errorf("check: takes no command, got %q", fs.Arg(0)))
		}
		// check is run with the question narrowed to the connection: a command
		// every host has, and both streams discarded, so the only thing the
		// caller learns is whether errand could get there and back.
		req = exec.Request{Command: "true", Stdout: io.Discard, Stderr: io.Discard}
	}
	if !given(fs, "timeout") {
		o.timeout = h.Timeout
	}
	ctx, stop := interruptible(context.Background())
	defer stop()
	res := attempt(ctx, h, o.timeout, o.connectTimeout, diag, func(ctx context.Context, c *client.Conn) result.Result {
		return exec.Run(ctx, c, req)
	})
	res.Op = sub
	if sub == "check" && res.ExitCode() == 0 {
		diag("ok %s connect=%dms", res.Target, res.Connect.Milliseconds())
	}
	return finish(res, diag, env, auditPath(h))
}

// options are the flag values a subcommand accepts. registerFlags owns which
// subcommand declares which, so the flags run and check share are described in
// exactly one place.
type options struct {
	stdin, pty, quiet, json bool
	env                     envFlag
	timeout, connectTimeout time.Duration
	maxOutput               int64
}

func registerFlags(fs *flag.FlagSet, sub string) *options {
	var o options
	if sub != "run" && sub != "check" {
		return &o
	}
	fs.BoolVar(&o.quiet, "quiet", false, "suppress errand's own diagnostics")
	fs.BoolVar(&o.json, "json", false, "write a JSON result envelope as the final line of stdout")
	fs.DurationVar(&o.timeout, "timeout", 0, "wall-clock limit for the whole invocation")
	fs.DurationVar(&o.connectTimeout, "connect-timeout", defaultConnectTimeout, "limit for TCP, handshake and auth")
	if sub == "run" {
		fs.BoolVar(&o.stdin, "stdin", false, "stream local stdin to the remote command")
		fs.BoolVar(&o.pty, "pty", false, "request a PTY")
		fs.Var(&o.env, "env", "KEY=VAL to set on the remote command; repeatable")
		fs.Func("max-output", "combined cap across stdout and stderr; 0 disables", func(v string) error {
			var err error
			o.maxOutput, err = config.ParseSize(v)
			return err
		})
	}
	return &o
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
// reached a connection, is reported and scored here. An empty auditPath is an
// outcome with no host to record, such as a usage error raised before the
// alias resolved.
func finish(res result.Result, diag client.Diag, env *envelope.Writer, auditPath string) int {
	if d := res.Diagnostic(); d != "" {
		diag("%s", d)
	}
	if env != nil {
		if err := env.Emit(res); err != nil {
			diag("writing the JSON envelope: %v", err)
		}
	}
	if auditPath != "" {
		// The log is for the operator's forensics, so a full disk warns and
		// nothing more: it must not change what the caller sees (SPEC §10).
		if err := audit.Append(auditPath, time.Now(), res); err != nil {
			diag("audit: %v", err)
		}
	}
	return res.ExitCode()
}

// auditPath is where this host's operations are recorded: the configured path
// when [defaults] set one, else the built-in state file.
func auditPath(h config.Host) string {
	if h.AuditLog != "" {
		return h.AuditLog
	}
	return config.DefaultAuditLog()
}

// jsonOutput builds the envelope writer the first time --json is seen. The
// flag is accepted on either side of the host, and the writer that tracked
// where remote stdout ended has to be the one that emits, so an existing
// writer is kept rather than replaced.
func jsonOutput(have *envelope.Writer, o *options, stdout io.Writer) *envelope.Writer {
	if have != nil || !o.json {
		return have
	}
	return envelope.New(stdout)
}

func fail(diag client.Diag, env *envelope.Writer, phase result.Phase, host string, err error) int {
	return finish(result.Result{Host: host, Err: phase.Wrap(host, err)}, diag, env, "")
}

func failUsage(stderr io.Writer, diag client.Diag, err error) int {
	code := fail(diag, nil, result.Usage, "", err)
	fmt.Fprint(stderr, usage)
	return code
}

// diagnostics builds the sink for errand's own stderr lines. --quiet silences
// this sink only: the remote command's stderr is a stream, not a diagnostic,
// and never passes through here.
func diagnostics(w io.Writer, quiet bool) client.Diag {
	if quiet {
		return func(string, ...any) {}
	}
	return func(format string, args ...any) {
		fmt.Fprintf(w, "errand: "+format+"\n", args...)
	}
}

// envFlag collects repeated --env values. The KEY=VAL shape is checked here,
// at the boundary, so exec can split on the first "=" and trust the result.
type envFlag []string

func (e *envFlag) String() string { return strings.Join(*e, " ") }

func (e *envFlag) Set(v string) error {
	if _, _, ok := strings.Cut(v, "="); !ok {
		return fmt.Errorf("want KEY=VAL, got %q", v)
	}
	*e = append(*e, v)
	return nil
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
		return fail(diag, nil, result.Usage, "", err)
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
