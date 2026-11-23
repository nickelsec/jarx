// Package poison runs text rules over every text an agent reads: hidden or
// tricky characters, comments a rendered view hides, text aimed at the
// agent, sensitive paths, exfil shapes and risky hook commands. It only
// reads the scrubbed text, so a secret never reaches its evidence.
package poison

import (
	"slices"
	"strconv"
	"strings"

	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/redact"
)

func rule(id string, sev finding.Severity, title, detail, fix string) finding.Rule {
	return finding.Rule{ID: id, Severity: sev, Title: title, Detail: detail, Fix: fix}
}

// The rules, by number.
func tagChars() finding.Rule {
	return rule("JARX-POISON-001", finding.High, "invisible tag characters hide text", "invisible tag characters spell out text the agent reads but you can't see",
		"delete the tag characters; check who added them and what the text asks for")
}

func bidi() finding.Rule {
	return rule("JARX-POISON-002", finding.Medium, "bidi controls reorder the text", "bidi control characters make the text read differently than it looks",
		"delete the bidi controls, or check the text in an editor that shows them")
}

func zeroWidth() finding.Rule {
	return rule("JARX-POISON-003", finding.Info, "zero-width characters in the text", "zero-width characters hide inside the text",
		"delete them unless they're part of an emoji or a script that needs them")
}

func terminal() finding.Rule {
	return rule("JARX-POISON-004", finding.Medium, "terminal escapes can rewrite the text", "terminal control sequences can hide or rewrite text when it's printed",
		"delete the escape sequences and carriage returns")
}

func comment() finding.Rule {
	return rule("JARX-POISON-005", finding.Info, "an HTML comment is hidden from view", "an HTML comment the agent reads is hidden in the rendered view",
		"read the comment; move notes for the agent into plain text so people see them too")
}

func aimed() finding.Rule {
	return rule("JARX-POISON-006", finding.Medium, "text tells the agent to override or hide", "text tells the agent to override its instructions or keep things from you",
		"remove the line, and check who added it")
}

func hiddenAimed() finding.Rule {
	return rule("JARX-POISON-007", finding.High, "hidden text aimed at the agent", "hidden text tells the agent something you can't see in the file",
		"remove the hidden text and treat the file as tampered with")
}

func exfil() finding.Rule {
	return rule("JARX-POISON-008", finding.Medium, "text downloads and runs, or sends data", "text has the agent download and run code, or send data somewhere",
		"remove it, or pin the download and check what it sends")
}

func sensitivePath() finding.Rule {
	return rule("JARX-POISON-009", finding.Info, "points the agent at a credential file", "text points the agent at a credential or key file",
		"check why the agent needs that file; deny reads of it if it doesn't")
}

func hookNetwork() finding.Rule {
	return rule("JARX-POISON-010", finding.Info, "a hook makes network calls", "a hook makes network calls each time it runs",
		"check where it sends data and what it includes")
}

func hookDownloadRun() finding.Rule {
	return rule("JARX-POISON-011", finding.High, "a hook downloads and runs code", "a hook downloads code and runs it each time it fires",
		"replace it with a pinned, checked script in the repo")
}

func hookStartup() finding.Rule {
	return rule("JARX-POISON-012", finding.High, "a hook writes to a startup file", "a hook writes to a shell startup file or another place that runs at login",
		"remove the write; a hook shouldn't change what runs outside the agent")
}

func hookTemp() finding.Rule {
	return rule("JARX-POISON-013", finding.Medium, "a hook runs a program from a temp dir", "a hook runs a program from a temp dir, where anyone on the machine can swap it",
		"move the program into the repo or a dir only you can write")
}

// Rules is every rule this analyzer can raise.
func Rules() []finding.Rule {
	return []finding.Rule{
		tagChars(), bidi(), zeroWidth(), terminal(), comment(), aimed(), hiddenAimed(),
		exfil(), sensitivePath(), hookNetwork(), hookDownloadRun(), hookStartup(), hookTemp(), lyingAnnotation(), shadowedTool(),
	}
}

// source is one text the agent reads.
type source struct {
	origin model.Origin
	text   string
	// markdown means comments and code blocks matter, and stripsBlock means
	// the agent never gets block-level comments (CLAUDE.md files).
	markdown, stripsBlock bool
	// hook is a hook command or script; hookType and script say which.
	hook     bool
	hookType string
	script   bool
	// project is the project dir the text belongs to, or "".
	project string
	// where names the text when the file alone doesn't, like a tool an MCP
	// server offers; its findings have no line.
	where string
}

// hit is one thing a rule found, at a line, with what to show.
type hit struct {
	rule   finding.Rule
	line   int
	detail string
}

// Analyze runs every rule over the projects' texts and the instructions not
// tied to a project. A file several projects share is reported once.
func Analyze(s *redact.Scrubber, projects []model.Project, global []model.Instruction) []finding.Finding {
	sources := make([]source, 0, len(global))
	for _, p := range projects {
		sources = append(sources, projectSources(p)...)
	}
	for _, in := range global {
		sources = append(sources, instructionSource(in))
	}

	seen := map[string]bool{}
	out := mcpFindings(s, projects)
	var groups []*group
	byKey := map[string]*group{}
	for _, src := range sources {
		for _, h := range check(src) {
			if src.where != "" {
				// A server's text has no lines, so every hit of one rule on one
				// tool is one finding that lists what it matched.
				key := strings.Join([]string{src.origin.File.Raw(), src.where, h.rule.ID}, "\x00")
				if g := byKey[key]; g != nil {
					g.add(h.detail)
				} else {
					g := &group{rule: h.rule, origin: src.origin, where: src.where}
					g.add(h.detail)
					byKey[key] = g
					groups = append(groups, g)
				}
				continue
			}
			key := strings.Join([]string{src.origin.File.Raw(), h.rule.ID, strconv.Itoa(h.line), h.detail}, "\x00")
			if seen[key] {
				continue
			}
			seen[key] = true
			o := src.origin
			o.Line = h.line
			out = append(out, h.rule.New(o, evidence(s, o, h.detail)))
		}
	}
	for _, g := range groups {
		o := g.origin
		o.Line = 0
		out = append(out, g.rule.New(o, evidence(s, o, g.where+": "+strings.Join(g.details, "; "))))
	}
	return out
}

// group is one rule's hits on one server text.
type group struct {
	rule    finding.Rule
	origin  model.Origin
	where   string
	details []string
}

func (g *group) add(d string) {
	if !slices.Contains(g.details, d) {
		g.details = append(g.details, d)
	}
}

// evidence is a hit's detail, with why it isn't loaded now when it isn't.
func evidence(s *redact.Scrubber, o model.Origin, detail string) redact.Text {
	if !o.InEffect && !o.Why.IsZero() {
		detail += "; not loaded now: " + o.Why.String()
	}
	ev, _ := s.Scrub(detail)
	return ev
}

func projectSources(p model.Project) []source {
	out := make([]source, 0, len(p.Instructions)+2*len(p.Skills)+2*len(p.Hooks))
	for _, in := range p.Instructions {
		out = append(out, instructionSource(in))
	}
	for _, sk := range p.Skills {
		out = append(out,
			source{origin: sk.Origin, text: sk.Text.String(), markdown: true},
			source{origin: sk.Origin, text: sk.Hooks.String(), hook: true, hookType: "command"},
		)
	}
	dir := p.Path.Raw()
	for _, h := range p.Hooks {
		out = append(out, source{origin: h.Origin, text: h.Run.String(), hook: true, hookType: h.Type.String(), project: dir})
		if !h.ScriptText.IsZero() {
			o := h.Origin
			o.File = h.Script
			out = append(out, source{origin: o, text: h.ScriptText.String(), hook: true, hookType: "command", script: true, project: dir})
		}
	}
	return append(out, serverSources(p)...)
}

// instructionSource marks CLAUDE.md files, the only ones the docs say have
// their block-level comments stripped before Claude gets them.
func instructionSource(in model.Instruction) source {
	strips := in.Origin.Agent == model.AgentClaude && in.Kind == model.InstructionFile &&
		strings.EqualFold(baseName(in.Path.Raw()), "CLAUDE.md")
	return source{origin: in.Origin, text: in.Text.String(), markdown: true, stripsBlock: strips}
}

func baseName(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// check runs every rule that applies to src.
func check(src source) []hit {
	if src.text == "" {
		return nil
	}
	t := src.text
	var hits []hit
	hits = append(hits, hiddenChars(t)...)

	visible := t
	if src.markdown {
		var cs []hit
		visible, cs = comments(t, src.stripsBlock)
		hits = append(hits, cs...)
	}
	hits = append(hits, tagHidden(t)...)
	hits = append(hits, zeroWidthHidden(visible)...)
	hits = append(hits, aimedAt(visible)...)
	hits = append(hits, sensitive(visible)...)
	hits = append(hits, exfilShapes(visible, src.hook)...)
	if src.hook {
		hits = append(hits, hookRules(src)...)
	}
	return hits
}

// lineAt is the 1-based line of byte offset off in t.
func lineAt(t string, off int) int { return strings.Count(t[:off], "\n") + 1 }

// excerpt is s on one line, cut to about commentCut runes.
func excerpt(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > commentCut {
		return string(r[:commentCut]) + "..."
	}
	return s
}
