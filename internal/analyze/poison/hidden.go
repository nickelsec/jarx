package poison

import (
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/nickelsec/jarx/internal/finding"
)

const (
	zwsp, wordJoiner  = 0x200B, 0x2060
	zwnj, zwj         = 0x200C, 0x200D
	tagFirst, tagLast = 0xE0000, 0xE007F
	tagCancel         = 0xE007F
	blackFlag         = 0x1F3F4 // starts an emoji tag sequence, like a region flag
	bom               = 0xFEFF
	esc               = 0x1B
	commentCut        = 80 // runes of a comment shown in evidence
)

func isBidi(r rune) bool { return (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) }

func asciiWord(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9'
}

// zeroWidthAt reports whether the rune at i (of size n) is a zero-width
// char that hides something. ZWJ and ZWNJ only count between ASCII letters
// or digits, since emoji and some scripts need them. A BOM only counts
// past the start.
func zeroWidthAt(t string, i, n int, r rune) bool {
	switch r {
	case zwsp, wordJoiner:
		return true
	case bom:
		return i > 0
	case zwnj, zwj:
		return i > 0 && i+n < len(t) && asciiWord(t[i-1]) && asciiWord(t[i+n])
	}
	return false
}

// charKind sorts the hidden chars hiddenChars reports.
type charKind int

const (
	plainChar charKind = iota
	bidiChar
	zeroWidthChar
	terminalChar
)

func kindAt(t string, i int, r rune) charKind {
	switch {
	case isBidi(r):
		return bidiChar
	case zeroWidthAt(t, i, utf8.RuneLen(r), r):
		return zeroWidthChar
	case r == esc, r == '\r' && (i+1 >= len(t) || t[i+1] != '\n'):
		return terminalChar // a lone carriage return overwrites the line on screen
	}
	return plainChar
}

// hiddenChars finds bidi controls, zero-width chars and terminal control
// sequences. Each rule reports once per text, at the first one.
func hiddenChars(t string) []hit {
	counts, first := map[charKind]int{}, map[charKind]int{}
	for i, r := range t {
		if k := kindAt(t, i, r); k != plainChar {
			if counts[k] == 0 {
				first[k] = i
			}
			counts[k]++
		}
	}
	var out []hit
	for _, k := range []struct {
		kind charKind
		rule finding.Rule
		what string
	}{
		{bidiChar, bidi(), "bidi control character"},
		{zeroWidthChar, zeroWidth(), "zero-width character"},
		{terminalChar, terminal(), "terminal control character"},
	} {
		if n := counts[k.kind]; n > 0 {
			out = append(out, hit{k.rule, lineAt(t, first[k.kind]), count(n, k.what)})
		}
	}
	return out
}

func count(n int, what string) string {
	if n == 1 {
		return "1 " + what
	}
	return strconv.Itoa(n) + " " + what + "s"
}

// tagHidden finds runs of tag characters and shows the ASCII they spell.
// An emoji tag sequence (a black flag, tags, then a cancel tag) is a flag
// like England's, not hidden text.
func tagHidden(t string) []hit {
	var out []hit
	var b strings.Builder
	start, prev := -1, rune(0)
	flush := func(last rune) {
		if start < 0 {
			return
		}
		emoji := prev == blackFlag && last == tagCancel
		if !emoji {
			spelled := b.String()
			line := lineAt(t, start)
			out = append(out, hit{tagChars(), line, "tag characters spell: \"" + excerpt(spelled) + "\""})
			out = append(out, hiddenContent(spelled, line, "in tag characters")...)
		}
		start = -1
		b.Reset()
	}
	var last rune
	for i, r := range t {
		if r >= tagFirst && r <= tagLast {
			if start < 0 {
				start = i
			}
			if c := r - tagFirst; c >= 0x20 && c < 0x7F {
				b.WriteRune(c)
			}
			last = r
			continue
		}
		flush(last)
		prev = r
	}
	flush(last)
	return out
}

// zeroWidthHidden finds text aimed at the agent that zero-width chars split
// up, so it only reads as words once they're gone.
func zeroWidthHidden(visible string) []hit {
	var b strings.Builder
	split := false
	for i, r := range visible {
		if zeroWidthAt(visible, i, utf8.RuneLen(r), r) {
			split = true
			continue
		}
		b.WriteRune(r)
	}
	if !split {
		return nil
	}
	joined := b.String()
	plain := map[string]bool{}
	for _, m := range aimedMatches(visible) {
		plain[strings.ToLower(m.text)] = true
	}
	var out []hit
	for _, m := range aimedMatches(joined) {
		if !plain[strings.ToLower(m.text)] {
			out = append(out, hit{hiddenAimed(), lineAt(joined, m.at), "split by zero-width characters: \"" + excerpt(m.text) + "\""})
		}
	}
	return out
}

// hiddenContent runs the content rules on text a person can't see. A hit
// is the high hidden rule, never the visible one.
func hiddenContent(hidden string, line int, where string) []hit {
	aims, paths := aimedMatches(hidden), sensitiveMatches(hidden)
	out := make([]hit, 0, len(aims)+len(paths))
	for _, m := range aims {
		out = append(out, hit{hiddenAimed(), line, where + ": \"" + excerpt(m.text) + "\""})
	}
	for _, m := range paths {
		out = append(out, hit{hiddenAimed(), line, where + ", a pointer to " + m.text})
	}
	return out
}

// comments finds HTML comments in markdown. It returns the text with every
// comment blanked out (newlines kept, so lines still line up) and a hit for
// each comment the agent reads. Comments in fenced code blocks and code
// spans show up as code, so they aren't hidden. With stripsBlock, a comment
// that starts a line is dropped before the agent sees it, so it's skipped.
func comments(t string, stripsBlock bool) (string, []hit) {
	c := &commentScan{t: t, blank: []byte(t), stripsBlock: stripsBlock}
	fence := ""
	for off, partial := 0, false; off < len(t); {
		line := lineFrom(t, off)
		if !partial {
			if f, ok := fenceToggle(line, fence); ok {
				fence, off = f, off+len(line)
				continue
			}
		}
		if fence != "" {
			off += len(line)
			continue
		}
		off, partial = c.scanLine(off, line)
	}
	return string(c.blank), c.out
}

const (
	commentOpen  = "<!--"
	commentClose = "-->"
	// maxIndent is how far a line can be indented and still start a block
	// (CommonMark).
	maxIndent = 3
)

type commentScan struct {
	t           string
	blank       []byte
	stripsBlock bool
	out         []hit
}

// scanLine finds comments that open on one line, from lineStart. It returns
// where to go on and whether that's mid-line, after a comment that ran past
// this line.
func (c *commentScan) scanLine(lineStart int, line string) (int, bool) {
	spans := codeSpans(line)
	for search := 0; search < len(line); {
		j := strings.Index(line[search:], commentOpen)
		if j < 0 {
			break
		}
		j += search
		if inSpan(spans, j) {
			search = j + len(commentOpen)
			continue
		}
		block := j <= maxIndent && strings.TrimSpace(line[:j]) == ""
		stop := c.take(lineStart+j, block)
		if stop > lineStart+len(line) {
			return stop, true
		}
		search = stop - lineStart
	}
	return lineStart + len(line), false
}

// take blanks out the comment at start and reports it unless the agent
// never gets it. It returns the offset just past the comment.
func (c *commentScan) take(start int, block bool) int {
	stop := len(c.t)
	if end := strings.Index(c.t[start+len(commentOpen):], commentClose); end >= 0 {
		stop = start + len(commentOpen) + end + len(commentClose)
	}
	for k := start; k < stop; k++ {
		if c.blank[k] != '\n' {
			c.blank[k] = ' '
		}
	}
	if block && c.stripsBlock {
		return stop
	}
	content := strings.TrimSuffix(strings.TrimPrefix(c.t[start:stop], commentOpen), commentClose)
	line := lineAt(c.t, start)
	kind := "an inline comment"
	if block {
		kind = "a comment"
	}
	c.out = append(c.out, hit{comment(), line, kind + ": \"" + excerpt(content) + "\""})
	c.out = append(c.out, hiddenContent(content, line, "in "+kind)...)
	c.out = append(c.out, hiddenExfil(content, line, "in "+kind)...)
	return stop
}

// lineFrom is the rest of the line at off, with its newline.
func lineFrom(t string, off int) string {
	if i := strings.IndexByte(t[off:], '\n'); i >= 0 {
		return t[off : off+i+1]
	}
	return t[off:]
}

// fenceToggle reports whether line opens or closes a fenced code block,
// and the fence that's open after it.
func fenceToggle(line, open string) (string, bool) {
	trimmed := strings.TrimLeft(line, " ")
	if len(line)-len(trimmed) > maxIndent {
		return open, false
	}
	f := fenceOf(trimmed)
	switch {
	case f == "":
		return open, false
	case open == "":
		return f, true
	case f[0] == open[0] && len(f) >= len(open):
		return "", true
	}
	return open, false
}

// minFence is the shortest ``` or ~~~ run that makes a fence.
const minFence = 3

// fenceOf is the ``` or ~~~ run that opens or closes a fenced block, or "".
func fenceOf(s string) string {
	for _, c := range []string{"`", "~"} {
		n := 0
		for n < len(s) && s[n] == c[0] {
			n++
		}
		if n >= minFence {
			return s[:n]
		}
	}
	return ""
}

// codeSpans are the [start, end) byte ranges of `code` spans on one line.
func codeSpans(line string) [][2]int {
	var out [][2]int
	for i := 0; i < len(line); {
		if line[i] != '`' {
			i++
			continue
		}
		n := 0
		for i+n < len(line) && line[i+n] == '`' {
			n++
		}
		closing := strings.Index(line[i+n:], strings.Repeat("`", n))
		if closing < 0 {
			break
		}
		end := i + n + closing + n
		out = append(out, [2]int{i, end})
		i = end
	}
	return out
}

func inSpan(spans [][2]int, at int) bool {
	for _, s := range spans {
		if at >= s[0] && at < s[1] {
			return true
		}
	}
	return false
}
