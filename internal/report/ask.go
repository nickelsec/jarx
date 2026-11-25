package report

import (
	"strconv"
	"strings"

	"github.com/nickelsec/jarx/internal/redact"
)

// The pieces of a question, laid out as the Questions part of the
// Terminal output section in docs/design.md says. The command asking
// reads the answers; report only writes.

// Layout of a question, in columns.
const (
	hintIndent    = 5 // hints line up with the question after "1/3  "
	commandIndent = 8 // commands line up with a note's text
	commandLabel  = 10
)

// promptMark is where the answer goes. It's ASCII on every terminal.
const promptMark = "  >  "

// Intro prints a heading and a tree of one-line entries.
func (p *Printer) Intro(heading redact.Text, lines []redact.Text) {
	p.emit(line{{text: escape(heading.String()), tone: bold}})
	nodes := make([]node, 0, len(lines))
	for _, l := range lines {
		nodes = append(nodes, node{line{{text: escape(l.String())}}})
	}
	p.tree(nodes)
}

// Question prints step n of total, its title, its default in brackets when
// there is one, and its hints.
func (p *Printer) Question(step, total int, title, def redact.Text, hints []redact.Text) {
	l := line{
		{text: strconv.Itoa(step) + "/" + strconv.Itoa(total) + "  "},
		{text: escape(title.String()), tone: bold},
	}
	if !def.IsZero() {
		l = append(l, seg{text: "  [" + escape(def.String()) + "]", tone: dim})
	}
	p.emit(l)
	p.hints(hints)
}

// YesNo prints a yes or no question with its default in capitals, and its
// hints.
func (p *Printer) YesNo(question redact.Text, defYes bool, hints []redact.Text) {
	choice := "  [y/N]"
	if defYes {
		choice = "  [Y/n]"
	}
	p.emit(line{{text: escape(question.String()), tone: bold}, {text: choice, tone: dim}})
	p.hints(hints)
}

func (p *Printer) hints(hints []redact.Text) {
	indent := strings.Repeat(" ", hintIndent)
	for _, h := range hints {
		for _, w := range wrapWords(escape(h.String()), p.Style.width()-hintIndent) {
			p.emit(line{{text: indent}, {text: w, tone: dim}})
		}
	}
}

// Prompt writes the answer mark, with no new line after it.
func (p *Printer) Prompt() { _, _ = p.Out.w.Write([]byte(promptMark)) }

// AnswerOK says an answer is fine, on a branch under it, with an optional
// dim note after it.
func (p *Printer) AnswerOK(msg, note redact.Text) {
	l := line{{text: p.answerIndent() + p.Style.glyphs().last}, {text: "ok", tone: green}, {text: "  " + escape(msg.String())}}
	if !note.IsZero() {
		l = append(l, seg{text: "  " + escape(note.String()), tone: dim})
	}
	p.emit(l)
}

// AnswerNote says something about an answer, like why it can't be used, on
// a branch under it. Long notes wrap at spaces.
func (p *Printer) AnswerNote(msg redact.Text) {
	g := p.Style.glyphs()
	room := p.Style.width() - hintIndent - branchCells
	for i, w := range wrapWords(escape(msg.String()), room) {
		prefix := g.space
		if i == 0 {
			prefix = g.last
		}
		p.emit(line{{text: p.answerIndent() + prefix}, {text: w}})
	}
}

func (p *Printer) answerIndent() string { return strings.Repeat(" ", hintIndent) }

// Command is one command to copy, with a label like the shell it's for.
type Command struct {
	Label, Text redact.Text
}

// Commands prints commands to copy under a note. They're never cut, even
// past the width, since a cut command doesn't work.
func (p *Printer) Commands(cmds []Command) {
	indent := strings.Repeat(" ", commandIndent)
	for _, c := range cmds {
		_, _ = p.Out.w.Write([]byte(indent + pad(escape(c.Label.String()), commandLabel) + "  " + escape(c.Text.String()) + "\n"))
	}
}

// Say prints one plain line.
func (p *Printer) Say(msg redact.Text) { p.emit(line{{text: escape(msg.String())}}) }

// Hint prints one dim line.
func (p *Printer) Hint(msg redact.Text) { p.emit(line{{text: escape(msg.String()), tone: dim}}) }

// Sep is the list separator with its spaces, for jarx's own words.
func (p *Printer) Sep() string { return p.sep() }

// Blank prints an empty line, between blocks and questions.
func (p *Printer) Blank() { p.blank() }
