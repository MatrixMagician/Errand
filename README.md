# Errand

Errand is a non-interactive SSH client for agents. It runs one command on a host you declared in a config file, streams the output, and exits with the remote command's exit code. It never prompts, it caps output, it times out, and with `--json` it reports the outcome as one machine-readable line.

Fenced `sh` blocks whose first line is `# harness` are run by the test suite against a throwaway sshd (`go test ./cmd/errand -run Readme`), so they work as written. The harness stands in for `web-prod` and starts the transfer examples in a directory that holds `restart.sh`.

## Install

With a Go toolchain:

```sh
go install github.com/MatrixMagician/Errand/cmd/errand@latest
```

Without one, download a static binary from the `ci` workflow on the repository's Actions page. Each run uploads `errand-linux-amd64`, `errand-linux-arm64`, `errand-darwin-amd64`, and `errand-darwin-arm64` as artifacts. Put the binary on your `PATH` as `errand`.

Check what you have:

```sh
errand version
```

## Quick start

Write `~/.config/errand/config.toml`. Every host the agent may reach gets a stanza. A host without one does not exist as far as `errand` is concerned.

```toml
[defaults]
user           = "deploy"
identity_files = ["~/.ssh/id_ed25519"]

[hosts.web-prod]
hostname = "web1.example.net"
```

Confirm you can get there and back:

```sh
# harness
errand check web-prod
```

On success `errand` prints `errand: ok deploy@web1.example.net:22 connect=96ms` to stderr and exits 0. On failure it exits with the same code `run` would, so a preflight that passes means a run will connect.

Run something:

```sh
# harness
errand run web-prod -- uname -a
```

## Command line

```
errand run   <host> [flags] -- <command...>
errand put   <host> [flags] <local> <remote>
errand get   <host> [flags] <remote> <local>
errand check <host> [flags]
errand allow <subcommand> [args...]
errand hosts
errand version
```

`<host>` is always an alias from the config file, never `user@hostname`. Flags go before or after the alias, but before the command or the paths. `errand --help` and `errand <subcommand> --help` print the same usage text as this section.

`errand allow` takes the tail of any `errand` invocation and answers whether a harness may run it without asking a human: exit 0 and nothing on stdout when the command is on the host's `allow_commands` list, exit 1 and a one-line reason on stdout when it is not, exit 250 for the usage and configuration errors the judged subcommand would raise. `hosts`, `version`, `help`, `check`, and `get` always pass; `put` never does; `run` is judged by its command. `run`, `put`, and `get` never consult the list themselves (ADR-0003).

```sh
# harness
errand allow run web-prod -- uptime
errand allow run web-prod -- 'df -h | head -n 2'  # exit 1
errand allow run web-prod -- systemctl status nginx
errand allow run web-prod -- systemctl restart nginx  # exit 1
errand allow run web-prod -- 'ls / > /tmp/listing'  # exit 1
errand allow run web-prod -- sudo df -h  # exit 1
errand allow put web-prod restart.sh /tmp/restart.sh  # exit 1
errand allow check web-prod
```

The list behind those lines is `["uname", "ls", "df", "uptime", "systemctl status"]`, so the failing lines print, in order, `not on allowlist: head` because a pipeline passes only when every segment is listed, then `not on allowlist: systemctl restart`, `redirection`, `sudo`, and `put`.

### Write `--` before the command

Put `--` between the flags and the remote command. Everything after `--` goes to the remote, so a flag the command needs can never be swallowed by `errand`. The separator is optional when the first word after the alias is not a flag, but the examples here always write it.

`errand` joins the words after `--` with single spaces and sends the result to the remote shell without re-quoting. Pass a shell-sensitive command as one single-quoted argument:

```sh
errand run web-prod -- 'journalctl -u nginx --since "-15 min" | tail -n 200'
```

```sh
# harness
errand run web-prod -- 'ls /etc | head -n 3'
```

### Flags for `run`

| Flag | Default | Meaning |
|---|---|---|
| `--timeout <dur>` | `120s`, or the host's `timeout` | Wall-clock limit for the whole invocation, connect included. Exit 254 on expiry. |
| `--connect-timeout <dur>` | `10s` | Limit for TCP, the handshake, and authentication, counted within `--timeout`. |
| `--max-output <bytes>` | `1MiB`, or the host's `max_output` | Combined cap across stdout and stderr. `0` disables it. |
| `--stdin` | off | Stream local stdin to the remote command. |
| `--pty` | off | Request a PTY, for tools that refuse to run without one. Merges stderr into stdout. |
| `--env KEY=VAL` | none | Set a remote environment variable. Repeatable. See [`--env` and `AcceptEnv`](#--env-and-acceptenv). |
| `--json` | off | Write the JSON envelope as the final line of stdout. |
| `--quiet` | off | Silence `errand`'s own stderr lines. Never the remote's stderr. |

### Flags for `put` and `get`

| Flag | Default | Meaning |
|---|---|---|
| `--max-size <bytes>` | `64MiB` | Reject a larger source file before the transfer starts. `0` disables it. |
| `--mode <octal>` | `0644` | `put` only. Permission bits for the remote file. |
| `--timeout <dur>` | `120s`, or the host's `timeout` | As for `run`. |
| `--connect-timeout <dur>` | `10s` | As for `run`. |
| `--json` | off | As for `run`. |
| `--quiet` | off | As for `run`. |

`check` takes `--timeout`, `--connect-timeout`, `--json`, and `--quiet`. `hosts` and `version` take no flags.

Durations use Go syntax: `90s`, `5m`, `1h30m`. Sizes are a decimal integer with an optional `KiB` or `MiB` suffix: `512`, `64KiB`, `1MiB`. Any other suffix is a usage error.

`--timeout 0` is not "no limit". A zero budget expires at once and the invocation exits 254 before it connects. To run without a limit, set a long one.

```sh
# harness
errand run web-prod --timeout 0 -- true  # exit 254
```

`--quiet` silences every line `errand` writes itself, including the usage errors it raises after the flags are parsed, such as an unknown alias or a missing command. Errors in the flags themselves are printed regardless, because they are the one thing a caller needs to see to fix the invocation.

## Exit codes

When the remote command ran to completion, `errand` exits with its exit code, whatever it was, 255 and 250 to 254 included. When a signal killed the remote command, `errand` exits `128 + signal` and says so on stderr. Failures that happened on the client side use a reserved band at the top of the range:

| Code | Meaning |
|---|---|
| 250 | Usage error, unknown alias, or configuration error. Also a transfer source that is missing, a directory, or over `--max-size`. |
| 251 | Host key verification failed: unknown, changed, or not matching the configured pin. |
| 252 | Authentication failed. |
| 253 | Network failure: DNS, connection refused, handshake, connection lost mid-command, or an SFTP error such as a missing remote file. |
| 254 | `--timeout` or `--connect-timeout` expired, or the output cap was breached before the remote exited. |

`SIGINT` or `SIGTERM` sent to `errand` itself exits `128 + signal` (130 or 143) after tearing the session down.

The band exists so an agent can tell "the command failed" from "the command never ran". Plain `ssh` returns 255 for both. The band can collide with a remote command that genuinely exits 250 to 254. Eight bits leave no room to avoid that, which is why `--json` exists: the envelope's `status` says whether the command ran, and `exit_code` is only the remote's when it did.

```sh
# harness
errand run web-prod -- 'exit 7'  # exit 7
errand run web-prod --timeout 1s -- 'sleep 30'  # exit 254
errand run web-prod --max-output 1KiB -- yes  # exit 254
```

## Configuration

`errand` reads one TOML file. The default path is `~/.config/errand/config.toml`. Set `ERRAND_CONFIG` to read another file. Unknown keys and malformed TOML are configuration errors, exit 250, with the file and line named.

```toml
[defaults]
user           = "oliverh"
timeout        = "120s"
max_output     = "1MiB"
known_hosts    = "~/.ssh/known_hosts"
identity_files = ["~/.ssh/id_ed25519"]
audit_log      = "~/.local/state/errand/audit.jsonl"

[hosts.web-prod]
hostname = "web1.example.net"
port     = 22
user     = "deploy"
timeout  = "60s"

[hosts.lab]
hostname   = "10.20.0.5"
accept_new = true

[hosts.db-restore]
hostname = "db2.example.net"
host_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI..."
```

### `[defaults]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `user` | string | the local `$USER` | Login name for hosts that do not set their own. |
| `timeout` | duration | `120s` | `--timeout` for hosts that do not set their own. |
| `max_output` | size | `1MiB` | `--max-output` for hosts that do not set their own. |
| `allow_commands` | list of strings | none | Commands an agent may run Unattended, for hosts that do not set their own list. |
| `known_hosts` | string or list of strings | none | Files to verify host keys against, in OpenSSH format. Files that do not exist are skipped. With no readable file, every host key is unknown. |
| `identity_files` | string or list of strings | none | Private key files to try after the SSH agent, in order. |
| `audit_log` | string | `$XDG_STATE_HOME/errand/audit.jsonl`, else `~/.local/state/errand/audit.jsonl` | Where operations are recorded. |

### `[hosts.<alias>]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `hostname` | string | required | Name or address to connect to. |
| `port` | integer | `22` | TCP port, 1 to 65535. |
| `user` | string | `[defaults] user` | Login name. |
| `timeout` | duration | `[defaults] timeout` | `--timeout` for this host. |
| `max_output` | size | `[defaults] max_output` | `--max-output` for this host. |
| `allow_commands` | list of strings | `[defaults] allow_commands` | Replaces the default list for this host. `[]` allows nothing. |
| `accept_new` | bool | `false` | Record an unknown host key on first contact and proceed. See [Host keys](#host-keys). |
| `host_key` | string | none | Pinned public key in `authorized_keys` format. When set, `known_hosts` is not consulted for this host. |
| `via` | string | none | Reserved for bastion hops. Setting it is a configuration error in this version. |

A leading `~` in any path expands to your home directory. Each setting resolves in this order: the flag on the command line, then `[hosts.<alias>]`, then `[defaults]`, then the built-in default. `--connect-timeout`, `--max-size`, and `--mode` have no config keys.

`errand hosts` prints every alias with its resolved values, so an agent can discover what it may reach without reading the file:

```sh
# harness
errand hosts
```

```
ALIAS       HOSTNAME          PORT  USER     TIMEOUT  MAX_OUTPUT  ACCEPT_NEW  HOST_KEY
db-restore  db2.example.net   22    oliverh  2m0s     1MiB        no          ssh-ed25519 (pinned)
lab         10.20.0.5         22    oliverh  2m0s     1MiB        yes         -
web-prod    web1.example.net  22    deploy   1m0s     1MiB        no          -
```

## Host keys

`errand` verifies the server's key against the `known_hosts` files, hashed entries included, or against the host's `host_key` pin when one is set. The decision is per host and there is no flag to change it, so an agent cannot talk itself into trusting a key the operator did not.

**Unknown key, no `accept_new`.** Exit 251. The message carries the key type, the SHA256 fingerprint, and the exact `known_hosts` line to add:

```
errand: web-prod: hostkey: unknown host key for web1.example.net (ssh-ed25519 SHA256:8kq...); add to known_hosts: web1.example.net ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI...
```

To trust it, paste everything after `add to known_hosts: ` as one line into the first file listed under `known_hosts`, then run again.

**Unknown key, `accept_new = true` on that host.** `errand` appends the line to the first configured `known_hosts` file (or `~/.ssh/known_hosts` when none is configured), prints `errand: added host key for web1.example.net to /home/you/.ssh/known_hosts (accept_new)`, and proceeds. The next run finds the key and prints nothing.

**Changed key.** Exit 251, always, `accept_new` or not. The message names the file and line that disagree and both fingerprints. There is no flag and no config key that overrides this. Edit `known_hosts` by hand or the host stays unreachable.

**Pinned key.** With `host_key` set, only that key is accepted. A server offering any other key is exit 251 with both fingerprints in the message. A malformed pin is a configuration error, exit 250.

## Authentication

`errand` offers every identity in the SSH agent at `SSH_AUTH_SOCK` first, then each `identity_files` entry in order. It never prompts. A key file that is passphrase-protected, unreadable, or not a key is skipped with a note such as `errand: skipping /home/you/.ssh/id_rsa: passphrase-protected`, and the next identity is tried. Load an encrypted key into the agent to use it.

When nothing is accepted, `errand` exits 252 with a message such as `errand: web-prod: auth: ssh: unable to authenticate, attempted methods [none publickey], no supported methods remain`. Password and keyboard-interactive authentication are not supported.

## `--env` and `AcceptEnv`

`--env KEY=VAL` sends an SSH environment request before the command starts. The server accepts only names matching its `AcceptEnv` policy, and OpenSSH refuses silently: the variable is missing on the remote and the command runs anyway. A stock Debian or Ubuntu `sshd_config` accepts `LANG` and `LC_*` and nothing else. When you need a value the server refuses, put it in the command:

```sh
# harness
errand run web-prod -- 'FOO=bar; echo "$FOO"'
```

## `--json`

With `--json`, stdout and stderr stream through exactly as without it. When the invocation ends, one JSON object is written as the final line of stdout. A caller that wants only the verdict reads that line:

```sh
# harness
errand run web-prod --json -- 'df -h /' | tail -n 1 | jq -r .status
```

The envelope:

```json
{"v":1,"host":"web-prod","command":"systemctl is-active nginx","status":"ok","exit_code":3,"signal":null,"duration_ms":412,"connect_ms":96,"stdout_bytes":7,"stderr_bytes":0,"truncated":false,"error":null}
```

| Field | Meaning |
|---|---|
| `v` | Envelope version, `1`. |
| `host` | The alias. |
| `command` | The command string. For `put` and `get`, the source and destination paths separated by a space. For `check`, `true`. |
| `status` | `ok`, `client_error`, `timeout`, `cancelled`, or `truncated`. |
| `exit_code` | The process exit code. The remote's own when `status` is `ok`. |
| `signal` | Signal name without the `SIG` prefix when the remote was killed by one, else `null`. |
| `duration_ms` | Whole invocation, connect included. |
| `connect_ms` | TCP, handshake, and authentication. |
| `stdout_bytes`, `stderr_bytes` | Bytes delivered on each stream. For transfers, `stdout_bytes` is the bytes moved. |
| `truncated` | `true` when the output cap was breached. |
| `error` | `null` when `status` is `ok`, else `{"kind":..., "message":...}`. |

`error.kind` is `usage`, `config`, `hostkey`, `auth`, or `network` when `status` is `client_error`. For `timeout`, `cancelled`, and `truncated` it repeats the status, so a caller can always read `error.kind` when `status` is not `ok`.

The envelope is written whenever `--json` was given, even for a usage error or an unknown alias, so a caller parsing stdout always gets a verdict. When the remote's last stdout byte was not a newline, `errand` writes one before the envelope so the final line stays parseable. `stdout_bytes` counts only the remote's bytes, not that newline.

## Audit log

Every `run`, `check`, `put`, and `get` that resolved an alias appends one JSON line to the audit log. The path is `[defaults] audit_log`, else `$XDG_STATE_HOME/errand/audit.jsonl`, else `~/.local/state/errand/audit.jsonl`. The file is created `0600` in a `0700` directory.

```json
{"ts":"2026-09-04T10:15:02Z","op":"run","host":"web-prod","target":"deploy@web1.example.net:22","command":"systemctl is-active nginx","status":"ok","exit_code":3,"duration_ms":412,"connect_ms":96,"stdout_bytes":7,"stderr_bytes":0,"truncated":false}
```

`kind` and `error` appear only when `status` is not `ok`. Timestamps are RFC 3339 UTC.

The log records what was done, never what was seen. The command string is logged. Output is not, so a secret that transited stdout cannot reach the log. Failure to write the log is a warning on stderr, `errand: audit: ...`, and the exit code is unchanged. Rotation is yours: point `logrotate` at the file.

## File transfer

`put` and `get` move one file over SFTP on the same connection, host key, and authentication machinery as `run`. No globbing, no recursion, no resume.

```sh
# harness
errand put web-prod --mode 0755 restart.sh /tmp/restart.sh
errand run web-prod -- /tmp/restart.sh
errand get web-prod /tmp/restart.sh restart.copy
```

`put` writes to `.<name>.errand-<pid>` in the destination directory and renames it into place, so a partial upload never appears under the final name. `get` does the same in the local destination directory. A timeout or an interrupt removes the temporary file when the connection can still carry the request. The final name never appears either way.

`--max-size` is checked against the source file before any bytes move. A source over the limit, a missing local source, a local directory as `put`'s source, or a missing local destination directory for `get` is a usage error, exit 250. A remote directory as `get`'s source is an SFTP error, exit 253. `put` sets the remote permission bits from `--mode`. `get` writes the local file `0644` before your umask, whatever the remote bits were.

To move a directory tree, tar on one side and untar on the other. That also compresses:

```sh
errand run web-prod -- 'tar -C /var/log/nginx -czf - .' > nginx-logs.tgz
```

## Timeouts and output caps

`--timeout` is a hard wall for the whole invocation, connect included. On expiry `errand` sends the remote a `KILL` signal request as a courtesy, closes the session and the connection, and exits 254. It never waits for the remote to finish gracefully. Against a server that has stopped answering, it still exits within a few seconds. `--connect-timeout` bounds the connect phase inside the same budget.

`--max-output` caps the sum of stdout and stderr bytes. Everything up to the cap is delivered. On breach `errand` stops reading, tears the session down as for a timeout, and prints `errand: output truncated at 1048576 bytes`. If the remote's exit status arrived in the moment before teardown, `errand` exits with it. Otherwise it exits 254. With `--json`, `status` is `truncated` and `truncated` is `true` in both cases. The default of 1 MiB protects an agent's context window. Raise it deliberately when you mean to read more.

While a command runs, `errand` sends TCP and SSH keepalives every 30 seconds so long commands survive stateful firewalls.
