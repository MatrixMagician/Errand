# Errand — a non-interactive SSH client for agentic use

**Working title:** Errand (binary: `errand`). Rename freely; nothing below depends on the name.

**Status:** Draft v0.1 — for milestone-by-milestone implementation by Claude Code.

---

## 1. Background and motivation

Claude Code frequently needs to run commands on remote machines: checking service state, pulling logs, restarting units, inspecting containers. The obvious tool — OpenSSH's `ssh` — was designed for humans at terminals, and its failure modes are hostile to an agent driving it through a shell:

- **It prompts.** Unknown host keys, key passphrases, and password fallback all block on a TTY. `BatchMode=yes` suppresses some of this but must be remembered on every invocation, and a suppressed prompt becomes an opaque failure.
- **Exit codes are ambiguous.** `ssh` returns 255 for every client-side failure — DNS, refused connection, auth rejection — which collides with a remote command legitimately exiting 255. An agent cannot distinguish "the command failed" from "I never ran the command".
- **Output is unbounded.** A careless `cat` of a multi-gigabyte log floods the agent's context window. There is no built-in cap or truncation.
- **No machine-readable envelope.** Duration, byte counts, timeout status, and the client/remote error distinction all have to be inferred from stderr prose.

Errand is a small, deliberately boring SSH client that fixes exactly these problems and nothing else. It is a command runner, not a terminal. The design principle throughout: **every invocation either completes deterministically or fails fast with a distinct, documented error — never blocks waiting for a human.**

## 2. Goals

1. Execute a single command on a named remote host, propagating stdin, stdout, stderr, and the remote exit code faithfully.
2. Never prompt for anything under any circumstances. All authentication material comes from the SSH agent or unencrypted-or-agent-loaded key files; anything else is an immediate, clearly reported failure.
3. Make client-side failures (connect, auth, host key, timeout) distinguishable from remote command failures, both via exit codes and via an optional JSON result envelope.
4. Enforce configurable timeouts (connect and overall command) and output caps by default.
5. Restrict execution to hosts explicitly declared in configuration, so an agent can only touch machines the operator has listed.
6. Provide basic SFTP `put`/`get` so the agent can ship scripts out and pull artefacts back.
7. Keep an append-only audit log of every command run.
8. Ship as a single static binary for Linux (amd64 and arm64).

## 3. Non-goals

- Interactive sessions, login shells, terminal emulation, or any TUI. `errand` is not a replacement for `ssh` at a keyboard.
- Password authentication, keyboard-interactive auth, or passphrase prompting.
- Port forwarding, SOCKS proxying, agent forwarding, or X11. None of these, ever — they widen the blast radius of a compromised or confused agent for no benefit to the command-runner use case.
- Acting as an SSH server, or any reverse-connection scheme.
- Windows support in v1. Linux and macOS clients only; remote targets are anything speaking SSH2.
- Parity with `ssh_config`. Errand reads a small, documented subset (§7) and ignores the rest loudly, not silently.

## 4. Command-line surface

```
errand run   <host> [flags] -- <command...>     # execute a command
errand put   <host> [flags] <local> <remote>    # upload a file (SFTP)
errand get   <host> [flags] <remote> <local>    # download a file (SFTP)
errand check <host> [flags]                     # preflight: resolve, connect, authenticate, run 'true'
errand hosts                                    # list declared hosts and their resolved parameters
errand version
```

`<host>` is always an alias declared in configuration (§7), never a raw `user@hostname`. This is a safety property, not a convenience: the set of machines the agent can reach is exactly the set the operator wrote down.

The `--` separator before the command is mandatory in documentation and examples (so agent-generated flags can never be swallowed by `errand` itself), but `errand` should also tolerate its absence when the first non-flag argument is unambiguous.

The remote command is passed as a single string to the server's exec channel, exactly as `ssh` does. When multiple arguments are given after `--`, join them with single spaces without re-quoting, and document clearly that shell-sensitive commands should be passed as one quoted argument. Example:

```
errand run web-prod -- 'journalctl -u nginx --since "-15 min" | tail -n 200'
```

### 4.1 Flags for `run`

| Flag | Default | Meaning |
|---|---|---|
| `--timeout <dur>` | `120s` | Wall-clock limit for the whole invocation, connect included. On expiry: best-effort SIGKILL via an SSH signal request, close the session, exit 254. |
| `--connect-timeout <dur>` | `10s` | TCP + handshake + auth limit, counted within `--timeout`. |
| `--max-output <bytes>` | `1MiB` | Combined cap across stdout and stderr. On breach, stop reading, truncate, kill the remote command as for a timeout, and mark the result truncated. `0` disables. |
| `--stdin` | off | Stream local stdin to the remote command. Off by default so a forgotten pipe can never make the remote command hang waiting for input. |
| `--pty` | off | Request a PTY. Rarely wanted by an agent (it merges stderr into stdout and invites control sequences); available for the odd tool that refuses to run without one. |
| `--env KEY=VAL` | — | Repeatable. Sent as SSH env requests; document that servers only accept names matching their `AcceptEnv` policy. |
| `--json` | off | Emit the JSON envelope (§6) instead of raw passthrough. |
| `--quiet` | off | Suppress stderr diagnostics from `errand` itself (never the remote command's stderr). |

Durations use Go syntax (`90s`, `5m`). Sizes accept `KiB`/`MiB` suffixes.

Per-host defaults for `timeout` and `max-output` can be set in configuration; flags override configuration, which overrides built-in defaults.

## 5. Behavioural contract

This section is the heart of the tool. Implementation choices elsewhere are negotiable; this contract is not.

### 5.1 Streams

In default (non-JSON) mode, remote stdout goes to local stdout and remote stderr to local stderr, unmerged, unbuffered beyond small pipe buffers, streamed as it arrives. Errand's own diagnostics go to stderr, each line prefixed `errand: `, so they are mechanically separable from remote stderr.

### 5.2 Exit codes

When the remote command ran to completion, `errand` exits with the remote exit code, whatever it was — including 255, and including 250–254 if the remote used them. When the remote was terminated by a signal, exit with `128 + signal` in the Unix tradition and say so on stderr.

Client-side failures use a reserved band at the top of the range:

| Code | Meaning |
|---|---|
| 250 | Usage error, unknown host alias, or configuration error |
| 251 | Host key verification failed (unknown, or — always fatal — changed) |
| 252 | Authentication failed |
| 253 | Network failure: DNS, refused, unreachable, handshake, or connection lost mid-command |
| 254 | Timeout (`--timeout` or `--connect-timeout`) or output cap breached |

The band can collide with a remote command that genuinely exits 250–254; that is unavoidable in eight bits and is precisely why JSON mode exists. Document the collision; in JSON mode there is no ambiguity at all.

### 5.3 Timeouts and cancellation

`--timeout` is a hard wall for the whole invocation. On expiry, send an SSH `signal` channel request (KILL) as a courtesy — many servers honour it, some historic OpenSSH versions do not — then close the channel and connection regardless, and exit 254 promptly. Never wait indefinitely for a graceful remote shutdown. SIGINT/SIGTERM received by `errand` itself are treated identically to a timeout, except the exit code is `128 + signal` and the envelope records `"cancelled"`.

### 5.4 Output caps

The cap applies to the sum of stdout and stderr bytes. Everything up to the cap is delivered normally; on breach, `errand` stops reading, tears the session down as for a timeout, prints `errand: output truncated at <n> bytes` to stderr, and — in default mode — still exits with the remote's code if one was received before teardown, else 254. In JSON mode `truncated: true` is set. The cap exists to protect the agent's context window; the default of 1 MiB is generous for that purpose and deliberately small for anything else.

### 5.5 Determinism

No colour, no progress bars, no spinners, no locale-dependent output from `errand` itself. Timestamps in diagnostics and logs are RFC 3339 UTC.

## 6. JSON mode

With `--json`, raw streams are still delivered — stdout and stderr passthrough happens exactly as in §5.1 — but on completion a single JSON object is written as the **final line of stdout**, prefixed by nothing and followed by a newline:

```json
{"v":1,"host":"web-prod","command":"systemctl is-active nginx",
 "status":"ok","exit_code":3,"signal":null,
 "duration_ms":412,"connect_ms":96,
 "stdout_bytes":7,"stderr_bytes":0,"truncated":false,
 "error":null}
```

`status` is one of `ok` (command ran; `exit_code` is authoritative), `client_error` (never ran; `error.kind` is one of `usage`, `config`, `hostkey`, `auth`, `network`), `timeout`, `cancelled`, `truncated`. When `status` is not `ok`, `error` is `{"kind":"...","message":"..."}` and the process exit code follows §5.2.

An alternative design — capturing streams into the JSON object itself — is rejected: it double-buffers arbitrarily large output and breaks streaming. The trailing-envelope design lets a caller pipe stdout through `tail -n 1 | jq` when it only wants the verdict, or read everything when it wants the lot. Note the one sharp edge and document it: a remote command whose last stdout line is not newline-terminated would abut the envelope, so `errand` always writes a leading newline before the envelope if the last remote byte seen was not `\n`.

## 7. Configuration and host resolution

Configuration lives in a single TOML file, default `~/.config/errand/config.toml`, overridable with `ERRAND_CONFIG`. TOML rather than `ssh_config` because the file doubles as an allowlist and carries Errand-specific policy that has no `ssh_config` equivalent; a bespoke file makes it obvious that declaring a host here is a deliberate grant of access.

```toml
[defaults]
user            = "oliverh"
timeout         = "120s"
max_output      = "1MiB"
known_hosts     = "~/.ssh/known_hosts"     # may list several files
identity_files  = ["~/.ssh/id_ed25519"]    # tried after the agent

[hosts.web-prod]
hostname   = "web1.example.net"
port       = 22
user       = "deploy"
timeout    = "60s"

[hosts.lab]
hostname   = "10.20.0.5"
accept_new = true          # TOFU permitted for this host only (§8)

[hosts.db-restore]
hostname   = "db2.example.net"
host_key   = "ssh-ed25519 AAAAC3NzaC1lZDI1..."   # pinned; known_hosts not consulted
```

Resolution is: alias → `[hosts.<alias>]` table → fill gaps from `[defaults]` → fill remaining gaps from built-ins (port 22, user = local username). An alias not present in the file is exit 250, full stop. There is deliberately no `--raw user@host` escape hatch: if a host is worth reaching, it is worth a three-line stanza, and the absence of the escape hatch is what makes the allowlist claim in §2 true.

`errand hosts` prints the resolved table (alias, hostname, port, user, per-host policy) so the agent can discover what it is allowed to touch without reading the TOML.

## 8. Authentication and host keys

**Authentication order:** every identity offered by the SSH agent at `SSH_AUTH_SOCK` first, then each configured `identity_files` entry. A key file that turns out to be passphrase-encrypted is skipped with a stderr note naming the file — never prompted for. If nothing succeeds, exit 252 with the server's auth methods listed in the diagnostic.

**Host keys:** verified against `known_hosts` (OpenSSH format, hashed entries supported), or against the per-host `host_key` pin when one is configured — a pin overrides and ignores `known_hosts` entirely.

- Unknown key, no `accept_new`: exit 251, printing the key type, SHA256 fingerprint, and the exact `known_hosts` line the operator can add.
- Unknown key, `accept_new = true` for that host: append to the first configured `known_hosts` file, note it on stderr, proceed. TOFU is per-host and off by default; there is no global flag and no CLI flag, so an agent can never talk itself into trusting a new key on a host the operator didn't mark.
- **Changed key: always exit 251.** No flag, no config option, no override. The operator edits `known_hosts` by hand or nothing happens. This is the one place the tool is allowed to be obstinate.

Preferred host key algorithms, KEX, and ciphers follow the Go `x/crypto/ssh` defaults, which are conservative and maintained; do not expose tuning knobs in v1.

## 9. File transfer

`put` and `get` use SFTP over the same connection, auth, and host key machinery. Semantics are deliberately minimal: single file, no globbing, no recursion, no resume. `put` writes to a temporary name in the destination directory and renames into place so a partial upload never masquerades as a complete file; `get` does the same locally. `--mode 0755` on `put` sets the remote permission bits (default 0644). Timeouts and the audit log apply exactly as for `run`; `--max-output` does not apply, but a `--max-size` (default 64 MiB) does, checked against the source file's stat before transfer begins. Directories, recursion, and glob support are explicitly deferred — an agent that needs them can tar on one side and untar on the other, which also compresses.

## 10. Audit log

Every `run`, `put`, and `get` appends one JSON line to `~/.local/state/errand/audit.jsonl` (overridable in `[defaults]`): timestamp, host alias, resolved `user@hostname:port`, the command string or transfer paths, status, exit code, duration, and byte counts. Command *output* is never logged — the log records what was done, not what was seen, so it stays small and cannot leak secrets that transited stdout. Failure to write the audit log is a stderr warning, not a fatal error; the log is for the operator's forensics, and a full disk should not brick remote execution. Log rotation is out of scope (point `logrotate` at it).

## 11. Connection handling

v1 opens one connection per invocation. That is an honest cost — roughly 100–300 ms of handshake per command on a LAN, more over the internet — accepted to keep the tool stateless and daemon-free. Two mitigations ship in v1:

- TCP keepalive plus an SSH-level `keepalive@openssh.com` global request every 30 s while a command runs, so long-running commands survive stateful firewalls.
- `errand check <host>` as a cheap preflight the agent can call once per session before committing to a plan.

A multiplexing mode (a small background holder process per host, ControlMaster-style, with an idle timeout) is sketched as Milestone 5 and should only be built if per-command latency proves to be a real problem in practice. Do not build it speculatively; a daemon triples the surface area of a tool whose whole virtue is having almost none.

ProxyJump-style bastion hops are likewise deferred (Milestone 5): the `x/crypto/ssh` client can dial through a first connection with `NewClientConn` over a forwarded TCP channel, and the configuration shape (`via = "bastion"` on a host stanza, one level deep, no chains in v1) should be reserved now so it slots in without breaking the file format.

## 12. Implementation notes

**Language: Go** (1.24+, `CGO_ENABLED=0`), for the single static binary and because the entire problem is covered by mature, first-party-adjacent libraries:

- `golang.org/x/crypto/ssh` — client, exec channel, signal requests, keepalives.
- `golang.org/x/crypto/ssh/agent` — agent auth over `SSH_AUTH_SOCK`.
- `golang.org/x/crypto/ssh/knownhosts` — known_hosts verification (wrap it: its error values distinguish "unknown" from "mismatch", which §8 depends on).
- `github.com/pkg/sftp` — transfers.
- `github.com/BurntSushi/toml` — configuration.
- Standard library `flag` or `spf13/cobra` for the CLI; cobra is acceptable given the subcommand shape, but keep the dependency tree shallow and vendor nothing else.

Structure: `cmd/errand/main.go` thin; packages `internal/config` (parse + resolve + validate), `internal/client` (dial, auth, hostkeys, keepalive), `internal/exec` (run semantics: streams, caps, timeouts, exit mapping), `internal/transfer` (sftp), `internal/audit`, `internal/envelope` (JSON result). The behavioural contract in §5 should be enforced in `internal/exec` with no knowledge of the CLI, so it is testable headlessly.

Every error surfaced to the user must be wrapped with the host alias and phase (`resolve`, `connect`, `hostkey`, `auth`, `exec`, `transfer`) — the phase is what drives both the exit code mapping and `error.kind`.

## 13. Milestones

Each milestone ends with the binary building, tests green, and the listed acceptance checks passing by hand.

**M1 — Skeleton and configuration.** CLI scaffold, TOML parsing, defaults merging, `errand hosts`, `errand version`. Acceptance: malformed TOML and unknown aliases produce exit 250 with pointed messages; `hosts` output matches a fixture config.

**M2 — Core execution.** Dial, agent + key file auth, known_hosts verification with pinning and per-host TOFU, `run` with streams, stdin flag, exit code propagation, both timeouts, output caps, the diagnostics prefix. This is the largest milestone and the point at which the tool is already useful. Acceptance: the full §5 contract exercised against a containerised sshd, including unknown/changed host key, wrong key auth, `exit 7`, `exit 255`, a signal-killed remote, a deliberate hang cut down by `--timeout`, and a `yes`-driven output cap breach.

**M3 — JSON envelope and audit log.** `--json` per §6, audit per §10, `check` subcommand. Acceptance: envelope is the final stdout line in success, failure, timeout, and truncation cases; `jq` parses it in all of them; audit lines accumulate with correct statuses.

**M4 — SFTP.** `put`/`get` per §9 with temp-and-rename, `--mode`, `--max-size`. Acceptance: round-trip a file with a checksum compare; interrupt a `put` mid-transfer and verify no partial file exists under the final name.

**M5 (optional, only on demonstrated need) — Multiplexing and bastion hops.** Per §11.

## 14. Testing strategy

Unit-test config resolution, exit code mapping, envelope serialisation, and the output cap accounting in isolation. The substance, though, is integration tests against a real sshd: a test harness that starts an OpenSSH server container (`linuxserver/openssh-server` or a minimal Debian image with `sshd` and a baked-in test key), generates an ephemeral host key and client key pair per run, writes a throwaway config and known_hosts into a temp dir, and drives the built binary as a subprocess — asserting on exit codes, stream separation (a remote command writing distinguishable bytes to each stream), and envelope contents. Auth-failure, hostkey-mismatch, and TOFU cases each get their own container state. CI (GitHub Actions) runs the suite on Linux; the container harness keeps everything self-contained with no external SSH dependency.

## 15. Open questions

1. Should `--env` exist in v1 at all, given that most sshd deployments reject unlisted names via `AcceptEnv` and the failure is silent on some servers? Cutting it simplifies the surface; keeping it helps the `TERM`/locale odd cases. Default position: keep, document the caveat.
2. macOS client support is assumed free with Go cross-compilation — confirm the agent socket and known_hosts paths need no special-casing beyond `$HOME` expansion.
3. Is 1 MiB the right default output cap for agent use, or should the default be lower (256 KiB) with the expectation that the agent raises it deliberately when it means to?
