//go:build !windows

package platform

import (
	"os"

	"golang.org/x/sys/unix"
)

// termOS asks the terminal about f. A terminal answers TIOCGWINSZ; a pipe
// or a file doesn't. Unix terminals take ANSI escapes as they are.
func termOS(f *os.File) termFacts {
	ws, err := unix.IoctlGetWinsize(int(f.Fd()), unix.TIOCGWINSZ)
	if err != nil {
		return termFacts{}
	}
	return termFacts{tty: true, width: int(ws.Col), vt: true}
}
