package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MatrixMagician/Errand/internal/sshtest"
)

const hookScript = "../../contrib/claude-code/errand-allow-hook.py"

// hookEvent is the slice of Claude Code's PreToolUse payload the hook reads.
type hookEvent struct {
	ToolName  string        `json:"tool_name"`
	ToolInput hookToolInput `json:"tool_input"`
}

type hookToolInput struct {
	Command string `json:"command"`
}

// TestHookApprovesOnlyUnattendedErrandCommands proves the contrib hook forwards
// to errand allow exactly the argv Bash would build from the command string,
// and stays silent for anything Bash would treat as more than one simple
// command. A change in the hook's JSON format, in the Python version, or in the
// scanner shows up here.
func TestHookApprovesOnlyUnattendedErrandCommands(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not on PATH; the hook test needs it")
	}
	cfg := sshtest.WriteFile(t, t.TempDir(), "config.toml", `[defaults]
allow_commands = ["df", "uptime", "systemctl status"]

[hosts.h]
hostname = "127.0.0.1"
`)
	bin := sshtest.Binary(t)
	env := append(os.Environ(),
		"PATH="+filepath.Dir(bin)+string(os.PathListSeparator)+os.Getenv("PATH"),
		"ERRAND_CONFIG="+cfg,
		"SSH_AUTH_SOCK=",
	)

	run := func(t *testing.T, env []string, stdin string) string {
		t.Helper()
		cmd := exec.Command(python, hookScript)
		cmd.Env = env
		cmd.Stdin = strings.NewReader(stdin)
		var stdout, stderr strings.Builder
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		if err := cmd.Run(); err != nil && cmd.ProcessState == nil {
			t.Fatalf("run hook: %v (stderr %s)", err, stderr.String())
		}
		if code := cmd.ProcessState.ExitCode(); code != 0 {
			t.Fatalf("exit code = %d, want 0 (stderr %s)", code, stderr.String())
		}
		return stdout.String()
	}

	assertAllowed := func(t *testing.T, stdout string) {
		t.Helper()
		var decision struct {
			Out struct {
				Event   string `json:"hookEventName"`
				Verdict string `json:"permissionDecision"`
				Reason  string `json:"permissionDecisionReason"`
			} `json:"hookSpecificOutput"`
		}
		if err := json.Unmarshal([]byte(stdout), &decision); err != nil {
			t.Fatalf("decode %q: %v", stdout, err)
		}
		if decision.Out.Event != "PreToolUse" {
			t.Errorf("hookEventName = %q, want PreToolUse", decision.Out.Event)
		}
		if decision.Out.Verdict != "allow" {
			t.Errorf("permissionDecision = %q, want allow", decision.Out.Verdict)
		}
		if !strings.HasPrefix(decision.Out.Reason, "errand allow: ") {
			t.Errorf("permissionDecisionReason = %q, want the errand allow: prefix", decision.Out.Reason)
		}
	}

	cases := []struct {
		name    string
		tool    string
		command string
		allowed bool
	}{
		{name: "listed command", command: "errand run h -- df -h", allowed: true},
		{name: "quoted pipe is one argument", command: "errand run h -- 'df -h | df'", allowed: true},
		{name: "json flag before the alias", command: "errand run h --json -- uptime", allowed: true},
		{name: "prefix entry", command: "errand run h --json -- systemctl status nginx", allowed: true},
		{name: "hosts", command: "errand hosts", allowed: true},
		{name: "check", command: "errand check h", allowed: true},
		{name: "get", command: "errand get h /etc/hostname hostname.copy", allowed: true},
		{name: "absolute path to errand", command: bin + " hosts", allowed: true},

		{name: "unlisted command", command: "errand run h -- reboot"},
		{name: "sudo", command: "errand run h -- sudo df"},
		{name: "put is always put to the human", command: "errand put h a b"},
		{name: "quoted pipe with an unlisted segment", command: "errand run h -- 'df -h | reboot'"},
		{name: "unquoted pipe into a local command", command: "errand run h -- df -h | jq ."},
		{name: "compound command", command: "cd /tmp && errand run h -- df -h"},
		{name: "unquoted expansion", command: "errand run h -- df $HOME"},
		{name: "double-quoted expansion", command: `errand run h -- "df $HOME"`},
		{name: "trailing control operator", command: "errand run h -- df -h; reboot"},
		{name: "newline anywhere", command: "errand run h -- 'df -h\nreboot'"},
		{name: "unknown alias", command: "errand run nope -- df -h"},
		{name: "unknown flag", command: "errand run --nope h -- df -h"},
		{name: "not errand", command: "git status"},
		{name: "env prefix", command: "ERRAND_CONFIG=/dev/null errand hosts"},
		{name: "not the Bash tool", tool: "Read", command: "errand hosts"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tool := tc.tool
			if tool == "" {
				tool = "Bash"
			}
			stdin, err := json.Marshal(hookEvent{ToolName: tool, ToolInput: hookToolInput{Command: tc.command}})
			if err != nil {
				t.Fatalf("marshal event: %v", err)
			}
			stdout := run(t, env, string(stdin))
			if !tc.allowed {
				if stdout != "" {
					t.Fatalf("stdout = %q, want empty", stdout)
				}
				return
			}
			assertAllowed(t, stdout)
		})
	}

	t.Run("stdin is not json", func(t *testing.T) {
		if stdout := run(t, env, "not json"); stdout != "" {
			t.Fatalf("stdout = %q, want empty", stdout)
		}
	})

	t.Run("errand not on PATH", func(t *testing.T) {
		bare := append(os.Environ(), "PATH="+t.TempDir(), "ERRAND_CONFIG="+cfg, "SSH_AUTH_SOCK=")
		stdin, err := json.Marshal(hookEvent{ToolName: "Bash", ToolInput: hookToolInput{Command: "errand hosts"}})
		if err != nil {
			t.Fatalf("marshal event: %v", err)
		}
		if stdout := run(t, bare, string(stdin)); stdout != "" {
			t.Fatalf("stdout = %q, want empty", stdout)
		}
	})
}
