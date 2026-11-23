package report

import (
	"bytes"
	"io"
	"strings"

	"github.com/nickelsec/jarx/internal/model"
)

// wrapWriter takes the inventory's lines, which are written whole, and
// makes them fit: the home dir becomes ~, and a line wider than the
// terminal breaks at a space onto lines indented under it.
type wrapWriter struct {
	w     io.Writer
	width int
	home  string
	buf   []byte
}

func (ww *wrapWriter) Write(b []byte) (int, error) {
	ww.buf = append(ww.buf, b...)
	for {
		i := bytes.IndexByte(ww.buf, '\n')
		if i < 0 {
			return len(b), nil
		}
		ww.writeLine(string(ww.buf[:i]))
		ww.buf = ww.buf[i+1:]
	}
}

func (ww *wrapWriter) flush() {
	if len(ww.buf) > 0 {
		ww.writeLine(string(ww.buf))
		ww.buf = nil
	}
}

// hangIndent is how much further than its line a wrapped line starts.
const hangIndent = 4

func (ww *wrapWriter) writeLine(l string) {
	if ww.home != "" {
		for _, sep := range []string{`\`, "/"} {
			l = replaceFold(l, ww.home+sep, "~"+sep)
		}
	}
	lead := len(l) - len(strings.TrimLeft(l, " "))
	// Wrapped lines hang a little past the line's own indent, but never
	// past half the width, so a deep line still has room.
	hang := strings.Repeat(" ", min(lead+hangIndent, ww.width/2)) //nolint:mnd // half
	first := true
	room := func() int {
		if first {
			return ww.width
		}
		return ww.width - cells(hang) // continuation lines carry the indent
	}
	for cells(l) > room() {
		cut := cutAt(l, room())
		ww.out(first, hang, strings.TrimRight(l[:cut], " "))
		l = strings.TrimLeft(l[cut:], " ")
		first = false
	}
	ww.out(first, hang, l)
}

func (ww *wrapWriter) out(first bool, hang, s string) {
	if !first {
		s = hang + s
	}
	_, _ = ww.w.Write([]byte(s + "\n"))
}

// cutAt is the byte offset to break l at so the first part fits in room
// columns: after the last space that fits, or right at the edge when no
// space does.
func cutAt(l string, room int) int {
	used, lastSpace, edge := 0, -1, len(l)
	for i, r := range l {
		c := runeCells(r)
		if used+c > room {
			edge = i
			break
		}
		used += c
		if r == ' ' {
			lastSpace = i
		}
	}
	if lastSpace > 0 && edge < len(l) {
		return lastSpace + 1
	}
	return max(edge, 1)
}

// Wrapped runs f with output wrapped to the terminal and the home dir shown
// as ~, for the --all inventory, whose lines are long.
func (p *Printer) Wrapped(home model.Path, f func()) {
	ww := &wrapWriter{w: p.Out.w, width: p.Style.width(), home: home.Text().String()}
	old := p.Out.w
	p.Out.w = ww
	defer func() {
		ww.flush()
		p.Out.w = old
	}()
	f()
}
