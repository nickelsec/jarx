package report

import (
	"strings"
	"unicode"
)

// Style is how the terminal output looks. The zero Style is what piped
// output gets: ASCII, no color, the default width (see width).
type Style struct {
	Width   int  // columns; 0 means the default
	Color   bool // ANSI colors, the basic 16 only
	Unicode bool // box drawing chars; else ASCII
}

// defaultWidth is the width for a zero Style, matching what jarx assumes
// for piped output.
const defaultWidth = 80

func (st Style) width() int {
	if st.Width > 0 {
		return st.Width
	}
	return defaultWidth
}

// glyphs are the tree and list characters for a style.
type glyphs struct {
	mid, last, bar, space, dot, ell string
}

func (st Style) glyphs() glyphs {
	if st.Unicode {
		return glyphs{mid: "├─ ", last: "└─ ", bar: "│  ", space: wideGap, dot: "·", ell: "…"}
	}
	return glyphs{mid: "+- ", last: `\- `, bar: "|  ", space: wideGap, dot: "-", ell: "..."}
}

// tone is a color. Only jarx picks one: text from files is escaped before
// it's put in a segment, so it can never carry its own color codes.
type tone int

const (
	plain tone = iota
	dim
	red
	brightRed
	yellow
	cyan
	green
	bold
)

func (t tone) code() string {
	switch t {
	case dim:
		return "\x1b[90m"
	case red:
		return "\x1b[31m"
	case brightRed:
		return "\x1b[1;91m"
	case yellow:
		return "\x1b[33m"
	case cyan:
		return "\x1b[36m"
	case green:
		return "\x1b[32m"
	case bold:
		return "\x1b[1m"
	case plain:
	}
	return ""
}

const reset = "\x1b[0m"

// seg is a run of text in one tone. Its text is already escaped.
type seg struct {
	text string
	tone tone
}

// line is one output line.
type line []seg

func (l line) cells() int {
	n := 0
	for _, s := range l {
		n += cells(s.text)
	}
	return n
}

func (l line) plain() string {
	var b strings.Builder
	for _, s := range l {
		b.WriteString(s.text)
	}
	return b.String()
}

// cells is how many terminal columns s takes: two for wide East Asian chars
// and emoji, none for combining marks, one for the rest.
func cells(s string) int {
	n := 0
	for _, r := range s {
		n += runeCells(r)
	}
	return n
}

// wideRunes are the ranges terminals draw two columns wide: Hangul Jamo,
// CJK, Hangul syllables, compatibility forms, fullwidth forms, emoji and
// the supplementary ideographs.
//
//nolint:gochecknoglobals // fixed table, read only
var wideRunes = []struct{ lo, hi rune }{
	{0x1100, 0x115F}, {0x2E80, 0xA4CF}, {0xAC00, 0xD7A3},
	{0xF900, 0xFAFF}, {0xFE30, 0xFE4F}, {0xFF00, 0xFF60},
	{0xFFE0, 0xFFE6}, {0x1F300, 0x1FAFF}, {0x20000, 0x3FFFD},
}

// zeroWidthSpace takes no column, like a combining mark.
const zeroWidthSpace = '\u200B'

func runeCells(r rune) int {
	if unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Me, r) || r == zeroWidthSpace {
		return 0
	}
	for _, w := range wideRunes {
		if r >= w.lo && r <= w.hi {
			return 2 //nolint:mnd // a wide char is two columns
		}
	}
	return 1
}

// fit cuts l to width columns, ending in an ellipsis when it cuts, so a
// line never wraps.
func (st Style) fit(l line, width int) line {
	if l.cells() <= width {
		return l
	}
	ell := st.glyphs().ell
	room := width - cells(ell)
	out := make(line, 0, len(l))
	for _, s := range l {
		if room <= 0 {
			break
		}
		if c := cells(s.text); c <= room {
			out = append(out, s)
			room -= c
			continue
		}
		var b strings.Builder
		for _, r := range s.text {
			if runeCells(r) > room {
				break
			}
			b.WriteRune(r)
			room -= runeCells(r)
		}
		out = append(out, seg{text: b.String(), tone: s.tone})
		break
	}
	return append(out, seg{text: ell, tone: dim})
}

// node is one tree entry: a first line and lines that continue it.
type node []line

// emit writes one line, cut to the width, with colors when they're on.
func (p *Printer) emit(l line) {
	l = p.Style.fit(l, p.Style.width())
	var b strings.Builder
	for _, s := range l {
		if p.Style.Color && s.tone != plain && s.text != "" {
			b.WriteString(s.tone.code())
			b.WriteString(s.text)
			b.WriteString(reset)
			continue
		}
		b.WriteString(s.text)
	}
	_, _ = p.Out.w.Write([]byte(strings.TrimRight(b.String(), " ") + "\n"))
}

// tree writes nodes under the current heading, each line cut to the width.
func (p *Printer) tree(nodes []node) { p.drawTree(nodes, false) }

// spacedTree is tree with a line of just the tree bar between nodes, so
// entries of more than one line stand apart.
func (p *Printer) spacedTree(nodes []node) { p.drawTree(nodes, true) }

func (p *Printer) drawTree(nodes []node, spaced bool) {
	g := p.Style.glyphs()
	for i, n := range nodes {
		if spaced && i > 0 {
			p.emit(line{{text: g.bar}})
		}
		first, rest := g.mid, g.bar
		if i == len(nodes)-1 {
			first, rest = g.last, g.space
		}
		for j, l := range n {
			prefix := rest
			if j == 0 {
				prefix = first
			}
			p.emit(append(line{{text: prefix}}, l...))
		}
	}
}

// Layout sizes, in columns.
const (
	branchCells = 3 // a tree branch, like "├─ "
	minGap      = 2 // the least space between two columns
)

// wideGap is the space between two parts of a line that aren't a list.
const wideGap = "   "
