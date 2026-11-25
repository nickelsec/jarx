package report

import (
	"strconv"
	"strings"

	"github.com/nickelsec/jarx/internal/redact"
)

// Count is a number of something, with its singular and plural words.
type Count struct {
	N         int
	One, Many string
}

// LLMPreviewView is what jarx scan --llm would send, shown before it asks.
type LLMPreviewView struct {
	Send     int
	Kinds    []Count // what's sent by kind; zero counts are left out
	Tokens   int     // rough
	Cached   int     // answered last time, not sent
	Failed   int     // failed last time, sent again
	New      int     // never sent, or changed since
	Skipped  int     // skipped in the dashboard, not sent
	Parallel int     // sent this many at a time
	Host     redact.Text
	Model    redact.Text
	KeyEnv   redact.Text
}

// LLMPreview prints what the LLM review would send, and where, as a block.
func (p *Printer) LLMPreview(v LLMPreviewView) {
	p.emit(line{{text: "llm review", tone: bold}})
	artifacts := plural(v.Send, "artifact", "artifacts")
	tokens := "~" + thousands(v.Tokens) + " tokens"
	const lastRun = "last run"
	width := max(cells(artifacts), cells(tokens), cells(lastRun)) + minGap
	var kinds []string
	for _, k := range v.Kinds {
		if k.N > 0 {
			kinds = append(kinds, plural(k.N, k.One, k.Many))
		}
	}
	nodes := []node{
		{line{{text: own(pad(artifacts, width))}, {text: own(strings.Join(kinds, p.sep()))}}},
		{line{{text: own(pad(tokens, width))}, {text: own("sent " + strconv.Itoa(v.Parallel) + " at a time"), tone: dim}}},
	}
	if v.Cached > 0 || v.Failed > 0 {
		var last []string
		if v.Cached > 0 {
			last = append(last, strconv.Itoa(v.Cached)+" cached, not sent")
		}
		if v.Failed > 0 {
			last = append(last, strconv.Itoa(v.Failed)+" failed, sent again")
		}
		if v.New > 0 {
			last = append(last, strconv.Itoa(v.New)+" new")
		}
		nodes = append(nodes, node{line{{text: own(pad(lastRun, width))}, {text: own(strings.Join(last, p.sep()))}}})
	}
	if v.Skipped > 0 {
		nodes = append(nodes, node{line{{text: own(pad("skipped", width))}, {text: own(strconv.Itoa(v.Skipped) + " not sent, you skipped them")}}})
	}
	p.tree(append(nodes,
		node{line{
			{text: own(pad("to", width))},
			{text: escape(v.Host.String())},
			{text: own(p.sep())},
			{text: escape(v.Model.String())},
			{text: own(p.sep() + "key from ")},
			{text: escape(v.KeyEnv.String())},
		}},
		node{line{{text: own("secrets masked before sending" + p.sep() + "history never sent"), tone: dim}}},
	))
}

// thousands writes n with a comma between each group of three digits.
func thousands(n int) string {
	s := strconv.Itoa(n)
	for i := len(s) - 3; i > 0; i -= 3 { //nolint:mnd // groups of three
		s = s[:i] + "," + s[i:]
	}
	return s
}
