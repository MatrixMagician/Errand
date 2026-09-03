package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestResolvePrecedence(t *testing.T) {
	t.Setenv("HOME", "/home/tester")
	cfg, err := Load("testdata/fixture.toml")
	if err != nil {
		t.Fatal(err)
	}

	// host over defaults
	h, err := cfg.Resolve("web-prod")
	if err != nil {
		t.Fatal(err)
	}
	want := Host{
		Alias: "web-prod", Hostname: "web1.example.net", Port: 2222, User: "deploy",
		Timeout: 60 * time.Second, MaxOutput: 1 << 20,
		KnownHosts: []string{"/home/tester/.ssh/known_hosts"}, IdentityFiles: []string{"/home/tester/.ssh/id_ed25519"},
	}
	if !reflect.DeepEqual(h, want) {
		t.Errorf("web-prod:\n got %+v\nwant %+v", h, want)
	}

	// defaults over built-ins, host-only policy
	h, err = cfg.Resolve("lab")
	if err != nil {
		t.Fatal(err)
	}
	if h.Port != 22 || h.User != "oliverh" || h.Timeout != 120*time.Second || h.MaxOutput != 256<<10 || !h.AcceptNew {
		t.Errorf("lab: %+v", h)
	}

	// pinned key passes through untouched
	h, err = cfg.Resolve("db-restore")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h.HostKey, "ssh-ed25519 ") {
		t.Errorf("db-restore host_key = %q", h.HostKey)
	}
}

func TestBuiltinsWithoutDefaults(t *testing.T) {
	cfg, err := Load(write(t, "[hosts.a]\nhostname = \"a.example\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	h, err := cfg.Resolve("a")
	if err != nil {
		t.Fatal(err)
	}
	if h.Port != 22 || h.User != localUser() || h.Timeout != 120*time.Second || h.MaxOutput != 1<<20 {
		t.Errorf("built-ins not applied: %+v", h)
	}
}

func TestUnknownAlias(t *testing.T) {
	p := write(t, "[hosts.a]\nhostname = \"a.example\"\n")
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	_, err = cfg.Resolve("nope")
	if err == nil || !strings.Contains(err.Error(), `"nope"`) || !strings.Contains(err.Error(), p) {
		t.Errorf("want alias and path in error, got %v", err)
	}
}

func TestMalformedTOMLReportsPosition(t *testing.T) {
	p := write(t, "[hosts.a]\nhostname = \"unterminated\n")
	_, err := Load(p)
	if err == nil || !strings.Contains(err.Error(), "line 2") || !strings.Contains(err.Error(), p) {
		t.Errorf("want parse location and path, got %v", err)
	}
}

func TestRejects(t *testing.T) {
	cases := map[string]string{
		"via reserved":     "[hosts.a]\nhostname = \"a\"\nvia = \"bastion\"\n",
		"unknown key":      "[hosts.a]\nhostname = \"a\"\nacept_new = true\n",
		"missing hostname": "[hosts.a]\nport = 22\n",
		"bad port":         "[hosts.a]\nhostname = \"a\"\nport = 70000\n",
		"bad duration":     "[hosts.a]\nhostname = \"a\"\ntimeout = \"soon\"\n",
		"bad size":         "[hosts.a]\nhostname = \"a\"\nmax_output = \"1GB\"\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(write(t, body)); err == nil {
				t.Error("expected error")
			} else if !strings.Contains(err.Error(), "hosts.a") && !strings.Contains(err.Error(), "line") {
				t.Errorf("error should point at the stanza or line: %v", err)
			}
		})
	}
	if _, err := Load(write(t, "[hosts.a]\nhostname = \"a\"\nvia = \"b\"\n")); err == nil || !strings.Contains(err.Error(), "not supported in v1") {
		t.Errorf("via message: %v", err)
	}
}

func TestMissingFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "absent.toml")
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), p) {
		t.Errorf("want path in error, got %v", err)
	}
}

func TestKnownHostsStringOrList(t *testing.T) {
	cfg, err := Load(write(t, "[defaults]\nknown_hosts = [\"/a\", \"/b\"]\n[hosts.h]\nhostname = \"h\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	h, _ := cfg.Resolve("h")
	if len(h.KnownHosts) != 2 || h.KnownHosts[1] != "/b" {
		t.Errorf("known_hosts list: %v", h.KnownHosts)
	}
}

func TestParseSize(t *testing.T) {
	good := map[string]int64{"0": 0, "512": 512, "4KiB": 4096, "1MiB": 1 << 20, "1 MiB": 1 << 20, "2mib": 2 << 20}
	for in, want := range good {
		got, err := ParseSize(in)
		if err != nil || got != want {
			t.Errorf("ParseSize(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"", "-1", "1GB", "KiB", "1.5MiB", "1MB"} {
		if _, err := ParseSize(in); err == nil {
			t.Errorf("ParseSize(%q) should fail", in)
		}
	}
	if s := Size(1 << 20).String(); s != "1MiB" {
		t.Errorf("String() = %q", s)
	}
	if s := Size(1536).String(); s != "1536" {
		t.Errorf("String() = %q", s)
	}
}

func TestParseDuration(t *testing.T) {
	var d Duration
	if err := d.UnmarshalText([]byte("90s")); err != nil || time.Duration(d) != 90*time.Second {
		t.Errorf("got %v, %v", d, err)
	}
	for _, in := range []string{"", "90", "-5s", "later"} {
		if err := d.UnmarshalText([]byte(in)); err == nil {
			t.Errorf("%q should fail", in)
		}
	}
}

func TestExpandHome(t *testing.T) {
	t.Setenv("HOME", "/home/tester")
	cases := map[string]string{
		"~/.ssh/known_hosts": "/home/tester/.ssh/known_hosts",
		"~":                  "/home/tester",
		"/abs/~/x":           "/abs/~/x",
		"~bob/x":             "~bob/x",
		"":                   "",
	}
	for in, want := range cases {
		if got := ExpandHome(in); got != want {
			t.Errorf("ExpandHome(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDefaultPath(t *testing.T) {
	t.Setenv("HOME", "/home/tester")
	t.Setenv("ERRAND_CONFIG", "")
	if p := DefaultPath(); p != "/home/tester/.config/errand/config.toml" {
		t.Errorf("DefaultPath() = %q", p)
	}
	t.Setenv("ERRAND_CONFIG", "/etc/errand.toml")
	if p := DefaultPath(); p != "/etc/errand.toml" {
		t.Errorf("DefaultPath() = %q", p)
	}
}
