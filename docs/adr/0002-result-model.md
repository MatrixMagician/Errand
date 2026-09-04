# ADR-0002: One result model with a derived verdict

**Status:** accepted (2026-09-04)

## Context

Five packages have to agree on what an operation meant: `client` and `exec` produce failures, `cmd/errand` picks the process exit code (SPEC §5.2), `envelope` writes `status` and `error.kind` (SPEC §6), and `audit` records the same fields again (SPEC §10). SPEC §5.4 adds a case where a truncated run still exits with the remote's code, and §6 requires an error object whenever the status is not `ok`. If each package answers this on its own, they will drift.

## Options considered

| Option | Why not |
|---|---|
| A stored `Status` field each producer sets | Policy leaks into every producer, and `ok` with a non-nil error becomes representable |
| Private fields with a constructor per outcome | Same guarantee, but two types and five constructors instead of one struct |
| Facts in a struct, verdict derived on read | Chosen |
| `exec` behind a `RemoteSession` interface | One real implementation and an adapter layer, when the tests already have a real sshd |
| `exec` on `*ssh.Session` directly | Chosen |

## Decision

`result.Result` carries only facts: what ran, what the remote reported (`*Remote`), what went wrong (`Err`), and how much came back. One unexported `verdict()` derives status, kind and exit code with a fixed precedence: timeout, interrupt, truncation, phase failure, remote exit. Stop causes are errors in `Err` rather than a separate reason enum, so there is one field to check instead of three whose mutual exclusion needs documenting. `Phase` and its `byPhase` table are the only place the 250–254 band is written.

## Consequences

| | |
|---|---|
| Producers | `client` and `exec` wrap errors with a phase and never choose an exit code |
| Zero value | A `Result` nobody filled in fails closed to `client_error`/`network`/253 |
| Envelope and audit | Projections of the same verdict, so they cannot disagree with the exit code |
| `error.kind` | Mirrors the status for timeout, cancelled and truncated, as §6 needs an error there |
| Cost | Every read recomputes the verdict; it is a switch over a handful of errors |
