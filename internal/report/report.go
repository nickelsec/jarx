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
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

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
		vals[i] = escape(a.String())
	}
	_, _ = fmt.Fprintf(s.w, string(f), vals...)
}

// escape makes control characters in a value visible, so text from a file
// or a file name can't move the cursor, recolor, fake a new line, or flip
// how the line reads. C0 and C1 controls and DEL become \xNN or \uNNNN, and
// so do the Unicode bidi controls. Newlines in the format itself are left
// alone; only values are escaped.
func escape(s string) string {
	if !strings.ContainsFunc(s, unsafeRune) {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case !unsafeRune(r):
			b.WriteRune(r)
		case r < utf8.RuneSelf:
			fmt.Fprintf(&b, `\x%02x`, r)
		default:
			fmt.Fprintf(&b, `\u%04x`, r)
		}
	}
	return b.String()
}

// The Unicode bidi controls: marks, embeddings and overrides, isolates.
const (
	arabicLetterMark = 0x061c
	leftToRightMark  = 0x200e
	rightToLeftMark  = 0x200f
	firstEmbedding   = 0x202a // LRE, RLE, PDF, LRO, RLO
	lastEmbedding    = 0x202e
	firstIsolate     = 0x2066 // LRI, RLI, FSI, PDI
	lastIsolate      = 0x2069
)

func unsafeRune(r rune) bool {
	switch {
	case unicode.IsControl(r): // C0, DEL and C1
		return true
	case r == arabicLetterMark, r == leftToRightMark, r == rightToLeftMark:
		return true
	case r >= firstEmbedding && r <= lastEmbedding, r >= firstIsolate && r <= lastIsolate:
		return true
	}
	return false
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
		for _, perm := range proj.Permissions {
			p.permissions(perm)
		}
		p.instructions(proj)
		p.extensions(proj)
	}
}

// Instructions lists instruction texts not tied to one project, like auto
// memory folders.
func (p *Printer) Instructions(is []model.Instruction) {
	p.Out.Printf("instructions not tied to a project (%s)\n", p.text(strconv.Itoa(len(is))))
	for _, in := range is {
		kind := string(in.Origin.Agent) + " " + string(in.Kind)
		p.Out.Printf("  %s  %s  %s\n", p.text(kind), in.Path.Text(), p.text(instructionDetail(in, "")))
	}
}

// Unknown lists settings keys an adapter didn't recognize, with the file
// each came from.
func (p *Printer) Unknown(us []model.Unknown) {
	p.Out.Printf("unknown settings (%s)\n", p.text(strconv.Itoa(len(us))))
	for _, u := range us {
		p.Out.Printf("  %s  %s %s  %s\n", u.Key, p.text(string(u.Origin.Agent)), p.text(string(u.Origin.Scope)), u.Origin.File.Text())
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

// instructions lists a project's instruction texts per agent, with paths
// inside the project shown relative to it.
func (p *Printer) instructions(proj model.Project) {
	var agentsSeen []model.Agent
	for _, in := range proj.Instructions {
		if !slices.Contains(agentsSeen, in.Origin.Agent) {
			agentsSeen = append(agentsSeen, in.Origin.Agent)
		}
	}
	root := proj.Path.Raw()
	for _, a := range agentsSeen {
		p.Out.Printf("    %s instructions\n", p.text(string(a)))
		for _, in := range proj.Instructions {
			if in.Origin.Agent != a {
				continue
			}
			p.Out.Printf("      %s  %s  %s\n", p.text(string(in.Kind)), p.shortPath(root, in.Path), p.text(instructionDetail(in, root)))
		}
	}
}

// instructionDetail is the scope, when it loads, who imported it, whether
// jarx read it, and why it's not in effect.
func instructionDetail(in model.Instruction, root string) string {
	parts := []string{string(in.Origin.Scope), string(in.Load)}
	if !in.ImportedBy.IsZero() {
		parts = append(parts, "via "+relPath(root, in.ImportedBy))
	}
	if in.Read != model.ReadOK {
		parts = append(parts, string(in.Read))
	}
	detail := strings.Join(parts, ", ")
	if !in.Origin.InEffect {
		detail += "  not in effect: " + in.Origin.Why.String()
	}
	return detail
}

// shortPath shows path relative to root when it's inside it.
func (p *Printer) shortPath(root string, path model.Path) redact.Text {
	if rel := relPath(root, path); rel != path.Text().String() {
		return p.text(rel)
	}
	return path.Text()
}

// relPath is path's masked text, relative to root when it's inside it.
func relPath(root string, path model.Path) string {
	if root != "" {
		if rel, err := filepath.Rel(root, path.Raw()); err == nil && filepath.IsLocal(rel) {
			return filepath.ToSlash(rel)
		}
	}
	return path.Text().String()
}

// permissions lists one agent's modes, rules and extra dirs for a project,
// each with its scope and, when it doesn't apply, why.
func (p *Printer) permissions(perm model.Permissions) {
	p.Out.Printf("    %s permissions\n", p.text(string(perm.Agent)))
	row := func(kind string, value redact.Text, o model.Origin) {
		why := ""
		if !o.InEffect {
			why = "  not in effect: " + o.Why.String()
		}
		p.Out.Printf("      %-5s  %s  %s%s\n", p.text(kind), value, p.text(string(o.Scope)), p.text(why))
	}
	for _, l := range perm.DefaultMode.Layers {
		row("mode", l.Value, l.Origin)
	}
	for _, o := range perm.Options {
		for _, l := range o.Setting.Layers {
			p.Out.Printf("      %s = %s  %s%s\n", o.Key, l.Value, p.text(string(l.Origin.Scope)), p.text(notInEffect(l.Origin)))
		}
	}
	for _, r := range perm.Rules {
		row(string(r.Action), r.Rule, r.Origin)
	}
	for _, d := range perm.AdditionalDirectories {
		row("dir", d.Value, d.Origin)
	}
}

// text wraps one of jarx's own values (an agent name, a status, a rule ID, a
// count) as Text, through the scrubber like everything else. It's
// unexported, so other packages still can't turn a string into output.
func (p *Printer) text(s string) redact.Text {
	t, _ := p.scrub.Scrub(s)
	return t
}
