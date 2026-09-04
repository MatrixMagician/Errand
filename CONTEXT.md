# Errand

A non-interactive SSH client that runs one command on a declared host on behalf of an agent, and reports what happened in a form the agent can act on.

## Language

**Host**:
A remote machine the operator has declared in the config file under an alias. Errand refuses anything not declared.
_Avoid_: server, target, `user@hostname`

**Alias**:
The name a Host is declared under. It is the only way to refer to a Host on the command line.

**Command allowlist**:
The operator's list of commands an agent may run on a Host without a human approving. A command passes the allowlist only when every pipeline segment starts with a listed entry and the command uses no redirection, no `sudo`, and no other shell control operator.
_Avoid_: non-destructive, read-only, safe, denylist

**Unattended**:
A run that the harness approves on its own because the command passed the Command allowlist. Everything else, including `put` and anything with `sudo`, is put to the human.
_Avoid_: auto-approved, allowed

**Operation**:
One `run`, `put`, `get`, or `check` against a Host. The unit the audit log records.
