# ADR-0003: Errand evaluates the command allowlist; the harness enforces it

**Status:** accepted (2026-09-04)

## Context

An agent harness such as Claude Code should approve Errand runs on its own when the command is one the operator has listed, and put everything else to the human. The operator wants to be able to say yes to a `systemctl restart` at the prompt, so the outcome of a failed check is *ask*, not *refuse*. Errand itself can only run or not run; it has no way to ask.

## Options considered

| Option | Why not |
|---|---|
| Errand enforces the list inside `run` and refuses anything not listed | Loses "ask": a command the human approved at the prompt would still be refused, unless an override flag exists, and an agent can pass the override flag |
| A self-contained harness hook script with its own allowlist file | Re-implements Errand's flag parsing and config resolution in a second language, and drifts when a flag changes |
| Errand evaluates, harness enforces | Chosen |

## Decision

The allowlist lives in Errand's config (`allow_commands`, resolved per host like every other key) and Errand exposes the verdict through a subcommand that exits 0 when the invocation is unattended and non-zero when it is not. `run`, `put`, and `get` never consult the list. A harness hook calls the subcommand and turns exit 0 into an automatic approval; every other outcome falls through to the harness's normal permission prompt.

The list is an allowlist matched on the first word of every pipeline segment, with word-prefix entries so `systemctl status` can be listed without admitting `systemctl restart`. Redirections, `sudo`, env-var prefixes, `;`, `&&`, `||`, and substitutions all fail the check. A denylist was rejected because an agent that can write shell routes around one.

## Consequences

- Errand stays usable without any harness; the list is advisory to whoever asks.
- The hook is a thin adapter and any harness with a pre-execution hook can reuse the subcommand.
- The default list is empty, so with nothing configured every command asks.
- Remote-side hardening (`command=` keys, restricted shells) is documented as optional and is the only gate a confused agent cannot route around.
