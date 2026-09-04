#!/usr/bin/env python3
"""Claude Code PreToolUse hook that turns an `errand allow` exit 0 into an allow
decision. It reads the hook event on stdin and, when the Bash command is exactly
one simple command invoking errand, asks `errand allow` whether the invocation
would be Unattended. Exit 0 becomes a Claude Code allow decision and every other
outcome prints nothing, so the Operation reaches Claude Code's normal permission
prompt (ADR-0003). The hook never emits deny or ask.
"""

import json
import os
import shutil
import subprocess
import sys

# Wider than Bash needs: a glob, tilde, brace, comment, or history character
# that Bash would leave alone in some positions is refused in every position,
# because the prompt is the safe outcome and each construct can be loosened
# later on its own.
REFUSED = set("|&;<>()\n`$*?[~{#!")

ESCAPABLE_IN_DOUBLE = set('$"\\`')


def simple_command(command: str) -> list[str] | None:
    if "\n" in command:
        return None
    words: list[str] = []
    word: list[str] = []
    started = False
    quote = None
    i, n = 0, len(command)
    while i < n:
        c = command[i]
        i += 1
        if quote == "'":
            if c == "'":
                quote = None
            else:
                word.append(c)
        elif quote == '"':
            if c == '"':
                quote = None
            elif c == "\\" and i < n and command[i] in ESCAPABLE_IN_DOUBLE:
                word.append(command[i])
                i += 1
            elif c in '$`':
                return None
            else:
                word.append(c)
        elif c == "\\":
            if i == n:
                return None
            word.append(command[i])
            i += 1
            started = True
        elif c in "'\"":
            quote = c
            started = True
        elif c in " \t":
            if started:
                words.append("".join(word))
                word, started = [], False
        elif c in REFUSED:
            return None
        else:
            word.append(c)
            started = True
    if quote is not None:
        return None
    if started:
        words.append("".join(word))
    return words or None


def main() -> int:
    try:
        event = json.load(sys.stdin)
    except ValueError:
        return 0
    if not isinstance(event, dict) or event.get("tool_name") != "Bash":
        return 0
    tool_input = event.get("tool_input")
    if not isinstance(tool_input, dict):
        return 0
    command = tool_input.get("command")
    if not isinstance(command, str):
        return 0

    words = simple_command(command)
    if words is None or os.path.basename(words[0]) != "errand":
        return 0
    errand = shutil.which("errand")
    if errand is None:
        return 0
    try:
        done = subprocess.run(
            [errand, "allow", *words[1:]],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return 0
    if done.returncode != 0:
        return 0

    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
            "permissionDecisionReason": "errand allow: " + " ".join(words[1:]),
        }
    }))
    return 0


if __name__ == "__main__":
    sys.exit(main())
