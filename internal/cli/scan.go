package cli

import (
	"fmt"
	"io"
)

const scanUsage = `usage: jarx scan

Scans what Claude Code and Codex can see and reach on this machine.

flags:
  -h, --help  show this help
`

func runScan(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("scan")
	if code, ok := parse(fs, args, scanUsage, stdout, stderr); !ok {
		return code
	}
	if fs.NArg() > 0 {
		return usageError(stderr, fmt.Sprintf("unexpected argument %q", fs.Arg(0)), scanUsage)
	}

	_, _ = fmt.Fprintln(stdout, "jarx scan: nothing to scan yet")
	return exitOK
}
