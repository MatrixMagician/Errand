// Package allow evaluates the Command allowlist (ADR-0003): whether a remote
// command may run Unattended. It only ever answers. run never consults it.
package allow

import (
	"fmt"
	"slices"
	"strings"
)

// Check returns nil when command passes list, else the reason it does not,
// worded as the one line errand allow prints.
func Check(list []string, command string) error {
	var first string
	if fields := strings.Fields(command); len(fields) > 0 {
		first = fields[0]
	}
	if first != "" && slices.Contains(list, first) {
		return nil
	}
	return fmt.Errorf("not on allowlist: %s", first)
}
