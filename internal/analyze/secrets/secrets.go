// Package secrets turns what the scrubber masked into findings. It never
// sees a value: it works from the kinds and fingerprints each redact.Text
// keeps.
package secrets

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/redact"
)

// Seen is a secret in text the agent loads into its context.
func Seen() finding.Rule {
	return finding.Rule{
		ID:       "JARX-SECRET-001",
		Severity: finding.High,
		Title:    "a secret is in text the agent loads",
		Detail:   "a secret is in text the agent loads, so it's already in the agent's context",
		Fix:      "take it out of the file and rotate it, since the agent has already had it",
	}
}

// PlainText is a secret written into a config file or a hook.
func PlainText() finding.Rule {
	return finding.Rule{
		ID:       "JARX-SECRET-002",
		Severity: finding.Medium,
		Title:    "a secret is in a config file or hook",
		Detail:   "a secret is written in plain text in a config file or hook",
		Fix:      "move it to an env var or a secret store, and rotate it if the file was shared or committed",
	}
}

// Placeholder is a match that looks like a placeholder. It's still masked,
// but it's likely not a real secret, so it's info wherever it is.
func Placeholder() finding.Rule {
	return finding.Rule{
		ID:       "JARX-SECRET-003",
		Severity: finding.Info,
		Title:    "looks like a placeholder secret",
		Detail:   "a value that looks like a placeholder sits where a secret would go",
		Fix:      "check that it isn't real. If it is, treat it like JARX-SECRET-001 or 002",
	}
}

// Rules is every rule this analyzer can raise.
func Rules() []finding.Rule { return []finding.Rule{Seen(), PlainText(), Placeholder()} }

// place is one text that can hold secrets.
type place struct {
	origin model.Origin
	text   redact.Text
	sees   bool // the agent loads it into its context
}

// hit is one secret in one file.
type hit struct {
	place

	found redact.Found
}

// Analyze reports every secret the scrubber masked in the projects' texts
// and in the instructions not tied to a project. A file shared by projects,
// like the user settings, is reported once, and so is a secret that shows
// up twice in one file (a settings hook is in both the hook and the file).
func Analyze(s *redact.Scrubber, projects []model.Project, global []model.Instruction) []finding.Finding {
	places := make([]place, 0, len(global))
	for _, p := range projects {
		places = append(places, projectPlaces(p)...)
	}
	for _, in := range global {
		places = append(places, instructionPlace(in))
	}

	hits := dedupe(places)
	files := map[string]map[string]bool{} // fingerprint to the files it's in
	for _, h := range hits {
		if fp := h.found.Fingerprint; fp != "" {
			if files[fp] == nil {
				files[fp] = map[string]bool{}
			}
			files[fp][h.origin.File.Raw()] = true
		}
	}

	out := make([]finding.Finding, 0, len(hits))
	for _, h := range hits {
		others := 0
		if fp := h.found.Fingerprint; fp != "" {
			others = len(files[fp]) - 1
		}
		rule := PlainText()
		switch {
		case h.found.LikelyPlaceholder:
			rule = Placeholder()
		case h.sees:
			rule = Seen()
		}
		ev, _ := s.Scrub(evidence(h, others))
		out = append(out, rule.New(h.origin, ev))
	}
	return out
}

func projectPlaces(p model.Project) []place {
	out := make([]place, 0, len(p.Instructions)+2*len(p.Skills)+len(p.Configs)+2*len(p.Hooks))
	for _, in := range p.Instructions {
		out = append(out, instructionPlace(in))
	}
	for _, sk := range p.Skills {
		out = append(out,
			place{origin: sk.Origin, text: sk.Text, sees: sk.Origin.InEffect},
			place{origin: sk.Origin, text: sk.Hooks},
		)
	}
	for _, c := range p.Configs {
		out = append(out, place{origin: c.Origin, text: c.Text})
	}
	for _, h := range p.Hooks {
		out = append(out, place{origin: h.Origin, text: h.Run})
		script := h.Origin
		script.File, script.Line = h.Script, 0
		out = append(out, place{origin: script, text: h.ScriptText})
	}
	return out
}

func instructionPlace(in model.Instruction) place {
	return place{origin: in.Origin, text: in.Text, sees: in.Origin.InEffect}
}

// dedupe keeps the first hit of each secret in each file. Without a
// fingerprint jarx can't tell two secrets apart, so each place's own
// order stands in for it.
func dedupe(places []place) []hit {
	seen := map[string]bool{}
	var out []hit
	for pi, p := range places {
		for i, f := range p.text.Secrets() {
			id := f.Fingerprint
			if id == "" {
				id = fmt.Sprintf("place %d, secret %d", pi, i)
			}
			key := p.origin.File.Raw() + "\x00" + f.Kind + "\x00" + id
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, hit{place: p, found: f})
		}
	}
	return out
}

func evidence(h hit, others int) string {
	var b strings.Builder
	b.WriteString(h.found.Kind)
	if h.found.Fingerprint != "" {
		b.WriteString(", fingerprint " + h.found.Fingerprint)
	}
	if h.sees {
		b.WriteString(", in text the agent sees")
	} else {
		b.WriteString(", written in the file")
	}
	if h.found.LikelyPlaceholder {
		b.WriteString(", looks like a placeholder")
	}
	switch {
	case others == 1:
		b.WriteString(", also in 1 other file")
	case others > 1:
		b.WriteString(", also in " + strconv.Itoa(others) + " other files")
	}
	return b.String()
}
