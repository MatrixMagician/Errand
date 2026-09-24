// Package allow evaluates the Command allowlist (ADR-0003): whether a remote
// command may run Unattended. It only ever answers. run never consults it.
package allow

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

var (
	errRedirection  = errors.New("redirection")
	errControl      = errors.New("control operator")
	errSubstitution = errors.New("substitution")
	errSudo         = errors.New("sudo")
	errEnvPrefix    = errors.New("env prefix")
	errUnparseable  = errors.New("unparseable")
)

// Check returns nil when command passes list, else the reason it does not,
// worded as the one line errand allow prints. Any reason makes the command
// ask, so a bad construct is reported before the segments scanned before it
// are judged: sudo cat > x and reboot > x both say redirection.
func Check(list []string, command string) error {
	segments, err := scan(command)
	if err != nil {
		return err
	}
	for _, words := range segments {
		if verdict := judge(list, words); verdict != nil {
			return verdict
		}
	}
	return nil
}

// scan tokenises command into pipeline segments the way the remote shell
// would. It walks bytes rather than runes because every special character here
// is ASCII, so the bytes of a multibyte UTF-8 sequence fall through the literal
// branch unchanged. A backtick or $( inside double quotes is still a
// substitution, because the remote shell expands both there.
func scan(command string) ([][]string, error) {
	const (
		none   byte = 0
		single byte = '\''
		double byte = '"'
	)
	var (
		quote    byte
		word     strings.Builder
		open     bool
		segment  []string
		segments [][]string
	)
	closeWord := func() {
		if open {
			segment = append(segment, word.String())
			word.Reset()
			open = false
		}
	}

	n := len(command)
	for i := 0; i < n; i++ {
		c := command[i]
		switch quote {
		case single:
			if c == single {
				quote = none
				continue
			}
			word.WriteByte(c)
			open = true
			continue
		case double:
			switch {
			case c == double:
				quote = none
			case c == '`':
				return nil, errSubstitution
			case c == '$' && i+1 < n && command[i+1] == '(':
				return nil, errSubstitution
			case c == '\\' && i+1 < n && strings.IndexByte("$\"\\`\n", command[i+1]) >= 0:
				word.WriteByte(command[i+1])
				open = true
				i++
			default:
				word.WriteByte(c)
				open = true
			}
			continue
		}
		switch {
		case c == '\\':
			if i+1 >= n {
				return nil, errUnparseable
			}
			word.WriteByte(command[i+1])
			open = true
			i++
		case c == single || c == double:
			quote = c
			open = true
		case c == ' ' || c == '\t':
			closeWord()
		case c == '\n' || c == ';' || c == '&':
			return nil, errControl
		case c == '|' && i+1 < n && command[i+1] == '|':
			return nil, errControl
		case c == '|':
			closeWord()
			segments = append(segments, segment)
			segment = nil
		case c == '>' || c == '<':
			return nil, errRedirection
		case c == '`':
			return nil, errSubstitution
		case c == '$' && i+1 < n && command[i+1] == '(':
			return nil, errSubstitution
		default:
			word.WriteByte(c)
			open = true
		}
	}
	if quote != none {
		return nil, errUnparseable
	}
	closeWord()
	segments = append(segments, segment)
	return segments, nil
}

// judge is a pure function over one pipeline segment, with no state and no
// I/O, so Check can run it against every segment scan collected regardless of
// how the scan ended.
func judge(list []string, words []string) error {
	if len(words) == 0 {
		return errUnparseable
	}
	// sudo alone is still caught by its basename, so /usr/bin/sudo is refused
	// the same as sudo. The allowlist match below is exact on both sides: a
	// path in the command or the entry means that path, not whatever file
	// happens to share its last element.
	if words[0][strings.LastIndex(words[0], "/")+1:] == "sudo" {
		return errSudo
	}
	if strings.Contains(words[0], "=") {
		return errEnvPrefix
	}
	n := 1
	for _, e := range list {
		fields := strings.Fields(e)
		if len(fields) == 0 || fields[0] != words[0] {
			continue
		}
		if len(fields) <= len(words) && slices.Equal(fields[1:], words[1:len(fields)]) {
			return nil
		}
		n = max(n, len(fields))
	}
	leading := words[:min(n, len(words))]
	return fmt.Errorf("not on allowlist: %s", strings.Join(leading, " "))
}
