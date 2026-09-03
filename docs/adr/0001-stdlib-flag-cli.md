# ADR-0001: Standard-library `flag` for the CLI, not cobra

**Status:** accepted (2026-09-03)

## Context

SPEC §12 allows either `flag` or `spf13/cobra` and asks to keep the dependency tree shallow. The CLI has six fixed subcommands, each with a handful of flags, and no nesting.

## Decision

Use `flag` with one `FlagSet` per subcommand and a hand-written usage string. Exit 250 on any parse error per SPEC §5.2.

## Consequences

- Only one third-party dependency in M1 (`BurntSushi/toml`).
- Usage text is maintained by hand in `cmd/errand/main.go`; keep it in sync with SPEC §4.
- Revisit only if subcommand nesting or shell completion becomes a requirement.
