package platform

import (
	"os"

	"golang.org/x/sys/windows"
)

// codePageUTF8 is the Windows code page for UTF-8.
const codePageUTF8 = 65001

// termOS asks the Windows console about f. It turns on VT processing so
// ANSI colors work; on a console too old for that, colors stay off.
func termOS(f *os.File) termFacts {
	h := windows.Handle(f.Fd())
	var mode uint32
	if windows.GetConsoleMode(h, &mode) != nil {
		return termFacts{} // not a console: piped or redirected
	}
	facts := termFacts{tty: true}
	var info windows.ConsoleScreenBufferInfo
	if windows.GetConsoleScreenBufferInfo(h, &info) == nil {
		facts.width = int(info.Window.Right-info.Window.Left) + 1
	}
	facts.vt = mode&windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0 ||
		windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING) == nil
	if cp, err := windows.GetConsoleOutputCP(); err == nil && cp == codePageUTF8 {
		facts.utf8 = true
	}
	return facts
}
