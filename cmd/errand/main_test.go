package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func exec(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestVersion(t *testing.T) {
	code, out, _ := exec(t, "version")
	if code != 0 || !strings.HasPrefix(out, "errand ") {
		t.Errorf("code=%d out=%q", code, out)
	}
}

func TestHostsMatchesGolden(t *testing.T) {
	t.Setenv("ERRAND_CONFIG", "testdata/fixture.toml")
	code, out, stderr := exec(t, "hosts")
	if code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
	want, err := os.ReadFile("testdata/hosts.golden")
	if err != nil {
		t.Fatal(err)
	}
	if out != string(want) {
		t.Errorf("hosts output differs from golden:\n--- got ---\n%s--- want ---\n%s", out, want)
	}
}

func TestExit250(t *testing.T) {
	t.Setenv("ERRAND_CONFIG", "testdata/fixture.toml")
	cases := map[string][]string{
		"no args":               nil,
		"unknown subcommand":    {"frobnicate"},
		"bad flag":              {"hosts", "--nope"},
		"bad flag on run":       {"run", "--nope", "web-prod", "--", "true"},
		"run not implemented":   {"run", "web-prod", "--", "true"},
		"put not implemented":   {"put", "web-prod", "a", "b"},
		"get not implemented":   {"get", "web-prod", "a", "b"},
		"check not implemented": {"check", "web-prod"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			code, _, stderr := exec(t, args...)
			if code != 250 || !strings.HasPrefix(stderr, "errand: ") {
				t.Errorf("code=%d stderr=%q", code, stderr)
			}
		})
	}
}

func TestUnknownAliasNamesAliasAndPath(t *testing.T) {
	t.Setenv("ERRAND_CONFIG", "testdata/fixture.toml")
	code, _, stderr := exec(t, "check", "ghost")
	if code != 250 || !strings.Contains(stderr, `"ghost"`) || !strings.Contains(stderr, "testdata/fixture.toml") {
		t.Errorf("code=%d stderr=%q", code, stderr)
	}
}

func TestMalformedConfig(t *testing.T) {
	p := t.TempDir() + "/bad.toml"
	os.WriteFile(p, []byte("[hosts.a]\nhostname = \"x\n"), 0o600)
	t.Setenv("ERRAND_CONFIG", p)
	code, _, stderr := exec(t, "hosts")
	if code != 250 || !strings.Contains(stderr, "line 2") {
		t.Errorf("code=%d stderr=%q", code, stderr)
	}
}

func TestHelpExitsZero(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"-h"}, {"help"}, {"run", "--help"}} {
		code, out, stderr := exec(t, args...)
		if code != 0 || !strings.Contains(out+stderr, "errand run") {
			t.Errorf("%v: code=%d out=%q stderr=%q", args, code, out, stderr)
		}
	}
}
