---
name: errand
description: Run commands and move files on a remote host through errand, never through ssh, scp, sftp, or rsync. Use this whenever a task mentions SSH, a server, a remote host, a box, another machine, a host alias, logs or files that live somewhere else, or checking whether a service is up on another machine, even when the request says "ssh into" or names a hostname.
---

# Errand

`errand` is the only way from this machine to another one. `ssh`, `scp`, `sftp`, and `rsync` are denied here.

## First, find out what you may reach

Run `errand hosts`. It prints every alias with its resolved user, port, timeout, and output cap. Use the alias and nothing else, never `user@hostname`. An alias that is not in the list does not exist. Say so instead of guessing a hostname.

## Run a command

```
errand run <alias> --json -- '<command>'
```

Write `--` before the command, every time. Pass the remote command as one single-quoted argument, so pipes, quotes, and `$` reach the remote shell untouched and nothing on this machine rewrites them.

With `--json`, the last line of stdout is the result. Read `status` before `exit_code`. `ok` means the command ran to completion and `exit_code` is its own. `client_error`, `timeout`, `cancelled`, and `truncated` mean it did not, and `error.kind` says why. An `exit_code` of 250 to 254 without `--json` is ambiguous, which is why you pass `--json`.

## What prompts and what does not

The operator keeps a list of commands you may run on each host without asking. A listed `errand run` executes at once. Everything else stops at a permission prompt the operator answers: any command not on the list, anything with `sudo`, anything with a redirection, and every `errand put`. Do the listed work in a batch, then ask for the rest one deliberate action at a time.

To know in advance whether a command will prompt, ask errand:

```
errand allow run <alias> -- '<command>'
```

Exit 0 means it runs without a prompt. Exit 1 prints the reason on stdout, such as `not on allowlist: systemctl restart`, `sudo`, or `redirection`.

## Files

Output is capped, 1 MiB by default, and a capped run reports `truncated`. For anything longer than a screen, download it instead of printing it:

```
errand get <alias> <remote-path> <local-path>
```

`errand put <alias> <local-path> <remote-path>` uploads a file. It always prompts.

## Not yours to do

Installing errand, writing its config, declaring hosts, and managing keys are the operator's work. When a host or a key is missing, stop and say exactly what is missing.
