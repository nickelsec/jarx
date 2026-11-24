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
	Send   int
	Kinds  []Count // what's sent by kind; zero counts are left out
	Tokens int     // rough
	Cached int     // answered from the cache, not sent
	Host   redact.Text
	Model  redact.Text
	KeyEnv redact.Text
}

// LLMPreview prints what the LLM review would send, and where, as a block.
func (p *Printer) LLMPreview(v LLMPreviewView) {
	p.emit(line{{text: "llm review", tone: bold}})
	artifacts := plural(v.Send, "artifact", "artifacts")
	tokens := "~" + thousands(v.Tokens) + " tokens"
	width := max(cells(artifacts), cells(tokens)) + minGap
	var kinds []string
	for _, k := range v.Kinds {
		if k.N > 0 {
			kinds = append(kinds, plural(k.N, k.One, k.Many))
		}
	}
	tokenLine := line{{text: own(tokens)}}
	if v.Cached > 0 {
		tokenLine = line{{text: own(pad(tokens, width))}, {text: own(strconv.Itoa(v.Cached) + " more cached, not sent again"), tone: dim}}
	}
	p.tree([]node{
		{line{{text: own(pad(artifacts, width))}, {text: own(strings.Join(kinds, p.sep()))}}},
		{tokenLine},
		{line{
			{text: own(pad("to", width))},
			{text: escape(v.Host.String())},
			{text: own(p.sep())},
			{text: escape(v.Model.String())},
			{text: own(p.sep() + "key from ")},
			{text: escape(v.KeyEnv.String())},
		}},
		{line{{text: own("secrets masked before sending" + p.sep() + "history never sent"), tone: dim}}},
	})
}

// thousands writes n with a comma between each group of three digits.
func thousands(n int) string {
	s := strconv.Itoa(n)
	for i := len(s) - 3; i > 0; i -= 3 { //nolint:mnd // groups of three
		s = s[:i] + "," + s[i:]
	}
	return s
}
