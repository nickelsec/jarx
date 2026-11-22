// Package report is the only package that writes jarx's output. Lint bans
// fmt.Print*, fmt.Fprint*, os.Stdout, os.Stderr, print, println, log and
// log/slog everywhere else.
//
// Values only go in as redact.Text. The format string has the unexported
// type format, so callers can pass a string literal or an untyped constant,
// but never a string variable: a raw string can't sneak in as the format.
package report

import (
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/redact"
)

// format is a printf format. Only untyped constants convert to it
// implicitly, and other packages can't name it to convert explicitly.
type format string

// Stream is one output stream, stdout or stderr.
type Stream struct {
	w io.Writer
}

// Printf writes to the stream.
func (s *Stream) Printf(f format, args ...redact.Text) {
	vals := make([]any, len(args))
	for i, a := range args {
		vals[i] = a.String()
	}
	_, _ = fmt.Fprintf(s.w, string(f), vals...)
}

// Printer writes jarx's output.
type Printer struct {
	Out *Stream
	Err *Stream

	scrub *redact.Scrubber
}

// New returns a Printer that writes to out and errw. scrub masks error text
// in Error.
func New(out, errw io.Writer, scrub *redact.Scrubber) *Printer {
	return &Printer{Out: &Stream{w: out}, Err: &Stream{w: errw}, scrub: scrub}
}

// Error writes "jarx: <err>" to stderr. The error text is scrubbed first,
// since a parser error can quote the line it failed on.
func (p *Printer) Error(err error) {
	text, _ := p.scrub.Scrub(err.Error())
	p.Err.Printf("jarx: %s\n", text)
}

// Projects lists every project with the agents that know it and, unless it's
// fine, its status.
func (p *Printer) Projects(ps []model.Project) {
	p.Out.Printf("projects (%s)\n", p.text(strconv.Itoa(len(ps))))
	for _, proj := range ps {
		detail := ""
		switch {
		case proj.Status != model.ProjectOK:
			detail = "  " + string(proj.Status)
		case proj.Walk != "":
			detail = "  " + plural(len(proj.Files), "file", "files") + " (" + string(proj.Walk) + ")"
		}
		p.Out.Printf("  %s  %s%s\n", proj.Path.Text(), p.text(agents(proj)), p.text(detail))
	}
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}

// agents names each agent once, in the order its records came, with its
// trust decision when there is one.
func agents(proj model.Project) string {
	trust := map[model.Agent]model.TrustLevel{}
	for _, t := range proj.Trust {
		trust[t.Origin.Agent] = t.Level
	}
	var names []string
	seen := map[model.Agent]bool{}
	for _, o := range proj.Origins {
		if seen[o.Agent] {
			continue
		}
		seen[o.Agent] = true
		name := string(o.Agent)
		if level, ok := trust[o.Agent]; ok {
			name += " (" + string(level) + ")"
		}
		names = append(names, name)
	}
	return strings.Join(names, ", ")
}

// Findings lists findings worst first, with the rule's title from rules.
func (p *Printer) Findings(fs []finding.Finding, rules *finding.Registry) {
	sorted := slices.Clone(fs)
	finding.Sort(sorted)
	p.Out.Printf("findings (%s)\n", p.text(strconv.Itoa(len(sorted))))
	for _, f := range sorted {
		where := f.Origin.File.Text().String()
		if f.Origin.Line > 0 {
			where += ":" + strconv.Itoa(f.Origin.Line)
		}
		detail := ""
		if rule, ok := rules.Lookup(f.RuleID); ok {
			detail = "  " + rule.Title
			if !f.Evidence.IsZero() {
				detail += ": " + f.Evidence.String()
			}
		}
		p.Out.Printf("  %s  %s  %s%s\n", p.text(f.Severity.String()), p.text(f.RuleID), p.text(where), p.text(detail))
	}
}

// text wraps one of jarx's own values (an agent name, a status, a rule ID, a
// count) as Text, through the scrubber like everything else. It's
// unexported, so other packages still can't turn a string into output.
func (p *Printer) text(s string) redact.Text {
	t, _ := p.scrub.Scrub(s)
	return t
}
