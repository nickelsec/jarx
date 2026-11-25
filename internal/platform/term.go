package platform

import (
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
)

// DefaultWidth is the width jarx lays out for when it can't ask the
// terminal, like when output is piped.
const DefaultWidth = 80

// Term is what jarx knows about where its output goes. It's about the
// process's own terminal, so it reads the real environment even with
// --home.
type Term struct {
	TTY     bool // output is a terminal, not a pipe or a file
	Width   int  // columns to lay out for
	Color   bool // ANSI colors are on
	Unicode bool // box drawing chars show; else jarx uses ASCII
}

// termFacts is what the OS said, before jarx decides anything.
type termFacts struct {
	tty   bool
	width int  // 0 when the terminal won't say
	vt    bool // ANSI escapes work (on Windows, VT processing is on)
	utf8  bool // the Windows console's output code page is UTF-8
	goos  string
	env   func(string) (string, bool)
}

// DetectTerm looks at w, usually stdout. Anything that isn't a terminal,
// like a pipe, a file or a buffer, gets ASCII, no color and COLUMNS or the
// default width.
func DetectTerm(w io.Writer) Term {
	var facts termFacts
	if f, ok := w.(*os.File); ok {
		facts = termOS(f)
	}
	facts.goos = runtime.GOOS
	facts.env = os.LookupEnv
	return decideTerm(facts)
}

// decideTerm turns what the OS said into what jarx does.
//
//   - Color needs a terminal that takes ANSI escapes, no NO_COLOR (a set,
//     non-empty value, per no-color.org) and TERM not "dumb".
//   - Box drawing chars need a terminal that shows UTF-8: on Windows the
//     console's output code page, elsewhere the locale. Piped output is
//     always ASCII, since Windows PowerShell 5.1 re-encodes a program's
//     output and mangles them.
//   - Width is the terminal's, then COLUMNS, then DefaultWidth.
func decideTerm(f termFacts) Term {
	get := func(k string) string {
		v, _ := f.env(k)
		return v
	}
	dumb := get("TERM") == "dumb"
	t := Term{TTY: f.tty, Width: termWidth(f.width, get)}
	t.Color = f.tty && f.vt && !dumb && get("NO_COLOR") == ""
	t.Unicode = f.tty && !dumb && (f.goos == "windows" && f.utf8 || f.goos != "windows" && utf8Locale(get))
	return t
}

// termWidth is the terminal's width, then COLUMNS, then DefaultWidth.
func termWidth(width int, get func(string) string) int {
	if width > 0 {
		return width
	}
	if n, err := strconv.Atoi(get("COLUMNS")); err == nil && n > 0 {
		return n
	}
	return DefaultWidth
}

// utf8Locale reports whether the locale is UTF-8. LC_ALL wins, then
// LC_CTYPE, then LANG, as in POSIX.
func utf8Locale(get func(string) string) bool {
	for _, k := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		if v := get(k); v != "" {
			v = strings.ToLower(v)
			return strings.Contains(v, "utf-8") || strings.Contains(v, "utf8")
		}
	}
	return false
}

// IsTerminal reports whether r is a terminal, like stdin typed into by a
// person. jarx only asks questions when both stdin and stdout are one.
func IsTerminal(r io.Reader) bool {
	f, ok := r.(*os.File)
	return ok && isTTY(f)
}
