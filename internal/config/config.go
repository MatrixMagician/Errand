// Package config parses the errand TOML file and resolves host aliases
// (SPEC §7). Resolution order: [hosts.<alias>] → [defaults] → built-ins.
package config

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// Built-in defaults (SPEC §4.1, §7).
const (
	DefaultPort      = 22
	DefaultTimeout   = 120 * time.Second
	DefaultMaxOutput = Size(1 << 20)
)

// DefaultPath returns $ERRAND_CONFIG, or ~/.config/errand/config.toml.
func DefaultPath() string {
	if p := os.Getenv("ERRAND_CONFIG"); p != "" {
		return p
	}
	return ExpandHome("~/.config/errand/config.toml")
}

// DefaultAuditLog returns $XDG_STATE_HOME/errand/audit.jsonl, or
// ~/.local/state/errand/audit.jsonl. It is where runs are recorded when
// [defaults] declares no audit_log (SPEC §10).
func DefaultAuditLog() string {
	if d := os.Getenv("XDG_STATE_HOME"); d != "" {
		return filepath.Join(d, "errand", "audit.jsonl")
	}
	return ExpandHome("~/.local/state/errand/audit.jsonl")
}

// ExpandHome replaces a leading "~" or "~/" with $HOME. "~user" forms are left alone.
func ExpandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, p[1:])
		}
	}
	return p
}

// Duration is a time.Duration parsed from Go syntax ("90s", "5m").
type Duration time.Duration

func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	if err != nil {
		return fmt.Errorf("duration %q: want Go syntax such as 90s or 5m", b)
	}
	if v < 0 {
		return fmt.Errorf("duration %q: must not be negative", b)
	}
	*d = Duration(v)
	return nil
}

// Size is a byte count parsed from a decimal integer with an optional KiB/MiB suffix.
type Size int64

func (s *Size) UnmarshalText(b []byte) error {
	v, err := ParseSize(string(b))
	if err != nil {
		return err
	}
	*s = Size(v)
	return nil
}

// String renders whole MiB/KiB multiples with a suffix, otherwise plain bytes.
func (s Size) String() string {
	switch {
	case s > 0 && s%(1<<20) == 0:
		return strconv.FormatInt(int64(s)>>20, 10) + "MiB"
	case s > 0 && s%(1<<10) == 0:
		return strconv.FormatInt(int64(s)>>10, 10) + "KiB"
	}
	return strconv.FormatInt(int64(s), 10)
}

// ParseSize parses "512", "4KiB", "1MiB" (suffix case-insensitive, optional space).
func ParseSize(s string) (int64, error) {
	orig := s
	s = strings.ToLower(strings.TrimSpace(s))
	mult := int64(1)
	for suffix, m := range map[string]int64{"kib": 1 << 10, "mib": 1 << 20} {
		if strings.HasSuffix(s, suffix) {
			mult, s = m, strings.TrimSpace(strings.TrimSuffix(s, suffix))
			break
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 || s == "" {
		return 0, fmt.Errorf("size %q: want a non-negative integer with optional KiB/MiB suffix", orig)
	}
	return n * mult, nil
}

// paths accepts either a single string or an array of strings in TOML.
type paths []string

func (p *paths) UnmarshalTOML(v any) error {
	switch x := v.(type) {
	case string:
		*p = []string{x}
	case []any:
		for _, e := range x {
			s, ok := e.(string)
			if !ok {
				return errors.New("want a string or a list of strings")
			}
			*p = append(*p, s)
		}
	default:
		return errors.New("want a string or a list of strings")
	}
	return nil
}

type defaults struct {
	User          string    `toml:"user"`
	Timeout       *Duration `toml:"timeout"`
	MaxOutput     *Size     `toml:"max_output"`
	KnownHosts    paths     `toml:"known_hosts"`
	IdentityFiles paths     `toml:"identity_files"`
	AuditLog      string    `toml:"audit_log"`
	AllowCommands []string  `toml:"allow_commands"`
}

type stanza struct {
	Hostname      string    `toml:"hostname"`
	Port          int       `toml:"port"`
	User          string    `toml:"user"`
	Timeout       *Duration `toml:"timeout"`
	MaxOutput     *Size     `toml:"max_output"`
	AcceptNew     bool      `toml:"accept_new"`
	HostKey       string    `toml:"host_key"`
	AllowCommands []string  `toml:"allow_commands"`
	Via           string    `toml:"via"` // reserved for bastion hops (SPEC §11); rejected in v1
}

// File is a parsed and validated configuration.
type File struct {
	Path     string
	defaults defaults
	hosts    map[string]stanza
}

// Host is a fully resolved target.
type Host struct {
	Alias         string
	Hostname      string
	Port          int
	User          string
	Timeout       time.Duration
	MaxOutput     Size
	AllowCommands []string // Command allowlist (ADR-0003); a host's list replaces the defaults', so [] allows nothing
	AcceptNew     bool
	HostKey       string // pinned public key in authorized_keys format; empty means use KnownHosts
	KnownHosts    []string
	IdentityFiles []string
	AuditLog      string
}

// Load reads and validates the TOML file at path.
func Load(path string) (*File, error) {
	var raw struct {
		Defaults defaults          `toml:"defaults"`
		Hosts    map[string]stanza `toml:"hosts"`
	}
	md, err := toml.DecodeFile(path, &raw)
	if err != nil {
		var pe toml.ParseError
		if errors.As(err, &pe) {
			return nil, fmt.Errorf("config %s: line %d: %s", path, pe.Position.Line, pe.Message)
		}
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	if u := md.Undecoded(); len(u) > 0 {
		return nil, fmt.Errorf("config %s: unknown key %q", path, u[0].String())
	}
	for alias, h := range raw.Hosts {
		switch {
		case h.Via != "":
			return nil, fmt.Errorf("config %s: hosts.%s: \"via\" is reserved and not supported in v1", path, alias)
		case h.Hostname == "":
			return nil, fmt.Errorf("config %s: hosts.%s: hostname is required", path, alias)
		case h.Port < 0 || h.Port > 65535:
			return nil, fmt.Errorf("config %s: hosts.%s: port %d out of range 1-65535", path, alias, h.Port)
		}
	}
	return &File{Path: path, defaults: raw.Defaults, hosts: raw.Hosts}, nil
}

// Aliases returns the declared aliases, sorted.
func (f *File) Aliases() []string {
	out := make([]string, 0, len(f.hosts))
	for a := range f.hosts {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

// Resolve applies host → defaults → built-ins for alias.
func (f *File) Resolve(alias string) (Host, error) {
	s, ok := f.hosts[alias]
	if !ok {
		return Host{}, fmt.Errorf("unknown host alias %q: not declared in %s", alias, f.Path)
	}
	d := f.defaults
	h := Host{
		Alias: alias, Hostname: s.Hostname, Port: s.Port, User: s.User,
		Timeout: DefaultTimeout, MaxOutput: DefaultMaxOutput,
		AcceptNew: s.AcceptNew, HostKey: s.HostKey,
		KnownHosts: expandAll(d.KnownHosts), IdentityFiles: expandAll(d.IdentityFiles),
		AuditLog: ExpandHome(d.AuditLog), AllowCommands: d.AllowCommands,
	}
	if h.Port == 0 {
		h.Port = DefaultPort
	}
	if h.User == "" {
		h.User = d.User
	}
	if h.User == "" {
		h.User = localUser()
	}
	if t := firstSet(s.Timeout, d.Timeout); t != nil {
		h.Timeout = time.Duration(*t)
	}
	if m := firstSet(s.MaxOutput, d.MaxOutput); m != nil {
		h.MaxOutput = *m
	}
	if s.AllowCommands != nil {
		h.AllowCommands = s.AllowCommands
	}
	return h, nil
}

func firstSet[T any](ps ...*T) *T {
	for _, p := range ps {
		if p != nil {
			return p
		}
	}
	return nil
}

func expandAll(ps []string) []string {
	if len(ps) == 0 {
		return nil
	}
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = ExpandHome(p)
	}
	return out
}

func localUser() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return ""
}
