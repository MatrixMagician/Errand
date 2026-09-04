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
// worded as the one line errand allow prints. A segment's own verdict outranks
// the construct that ended the scan, so sudo cat > x says sudo and reboot > x
// says not on allowlist: reboot.
func Check(list []string, command string) error {
	segments, err := scan(command)
	for _, words := range segments {
		if verdict := judge(list, words); verdict != nil {
			return verdict
		}
	}
	return err
}

// scan tokenises command into pipeline segments the way the remote shell
// would. It walks bytes rather than runes because every special character here
// is ASCII, so the bytes of a multibyte UTF-8 sequence fall through the literal
// branch unchanged. A backtick or $( inside double quotes is still a
// substitution, because the remote shell expands both there. On a failing
// construct it still returns every segment completed so far, plus the segment
// being built when the construct was hit, so Check can judge what is already
// known before reporting it.
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
	fail := func(err error) ([][]string, error) {
		closeWord()
		if len(segment) > 0 {
			segments = append(segments, segment)
		}
		return segments, err
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
				return fail(errSubstitution)
			case c == '$' && i+1 < n && command[i+1] == '(':
				return fail(errSubstitution)
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
				return fail(errUnparseable)
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
			return fail(errControl)
		case c == '|' && i+1 < n && command[i+1] == '|':
			return fail(errControl)
		case c == '|':
			closeWord()
			segments = append(segments, segment)
			segment = nil
		case c == '>' || c == '<':
			return fail(errRedirection)
		case c == '`':
			return fail(errSubstitution)
		case c == '$' && i+1 < n && command[i+1] == '(':
			return fail(errSubstitution)
		default:
			word.WriteByte(c)
			open = true
		}
	}
	if quote != none {
		return fail(errUnparseable)
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
	first := words[0][strings.LastIndex(words[0], "/")+1:]
	if first == "sudo" {
		return errSudo
	}
	if strings.Contains(words[0], "=") {
		return errEnvPrefix
	}
	n := 1
	for _, e := range list {
		fields := strings.Fields(e)
		if len(fields) == 0 || fields[0] != first {
			continue
		}
		if len(fields) <= len(words) && slices.Equal(fields[1:], words[1:len(fields)]) {
			return nil
		}
		n = max(n, len(fields))
	}
	leading := slices.Clone(words[:min(n, len(words))])
	leading[0] = first
	return fmt.Errorf("not on allowlist: %s", strings.Join(leading, " "))
}
