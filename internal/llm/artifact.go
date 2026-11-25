package llm

import (
	"strings"
	"unicode/utf8"

	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/redact"
)

// Kind is what kind of artifact is sent for review.
type Kind string

// The artifact kinds the PRD lists. Memory and session history are never
// sent: both are built from past sessions.
const (
	KindTool         Kind = "tool"
	KindSkill        Kind = "skill"
	KindInstructions Kind = "instructions"
	KindHook         Kind = "hook"
)

// MaxArtifactBytes is how much of one artifact is sent. A longer one is
// cut, and the quote check only looks at what was sent.
const MaxArtifactBytes = 64 << 10

// Artifact is one thing the review sends, already masked.
type Artifact struct {
	Kind   Kind
	Name   redact.Text // a short label, like a skill's name or a file
	Text   redact.Text // what's sent
	Cut    bool        // Text was cut to MaxArtifactBytes
	Origin model.Origin
}

// label is how a finding names the artifact, like "skill lint".
func (a Artifact) label() string { return string(a.Kind) + " " + a.Name.String() }

// Collect picks what the agents load from each project: instruction files
// (not memory), skills, hook commands with their scripts, and the tools of
// servers that listed them. Only what's in effect and was read is taken,
// and the same artifact in two projects is taken once. s rebuilds a cut
// text, which scrubbing again leaves as it was.
func Collect(s *redact.Scrubber, projects []model.Project) []Artifact {
	c := collector{s: s, seen: map[string]bool{}}
	for _, p := range projects {
		c.instructions(p.Instructions)
		c.skills(p.Skills)
		c.hooks(p.Hooks)
		c.tools(p.Servers)
	}
	return c.out
}

func (c *collector) instructions(ins []model.Instruction) {
	for _, in := range ins {
		if in.Read == model.ReadOK && in.Origin.InEffect && !isMemory(in.Kind) {
			c.add(KindInstructions, in.Path.Text().String(), in.Text.String(), in.Origin)
		}
	}
}

func (c *collector) skills(sks []model.Skill) {
	for _, sk := range sks {
		if sk.Read == model.ReadOK && sk.Origin.InEffect {
			c.add(KindSkill, sk.Name.String(), sk.Text.String(), sk.Origin)
		}
	}
}

func (c *collector) hooks(hs []model.Hook) {
	for _, h := range hs {
		if h.Origin.InEffect {
			c.add(KindHook, hookName(h), hookText(h), h.Origin)
		}
	}
}

// tools takes the tools of servers that listed them, so only servers the
// agent would start.
func (c *collector) tools(srvs []model.Server) {
	for _, srv := range srvs {
		if srv.Status != model.StatusListed {
			continue
		}
		for _, o := range srv.Offers {
			if o.Kind == model.OfferTool {
				c.add(KindTool, o.Name.String()+" of "+srv.Name.String(), o.Text.String(), srv.Origin)
			}
		}
	}
}

func isMemory(k model.InstructionKind) bool {
	return k == model.InstructionMemory || k == model.InstructionAgentMemory
}

func hookName(h model.Hook) string {
	name := h.Event.String()
	if !h.Matcher.IsZero() {
		name += " " + h.Matcher.String()
	}
	return name
}

// hookText is what a hook runs, and the script it runs when jarx read one.
func hookText(h model.Hook) string {
	if h.Run.IsZero() {
		return ""
	}
	text := h.Type.String() + ": " + h.Run.String()
	if h.ScriptRead == model.ReadOK && !h.ScriptText.IsZero() {
		text += "\n\nscript " + h.Script.Text().String() + ":\n" + h.ScriptText.String()
	}
	return text
}

type collector struct {
	s    *redact.Scrubber
	seen map[string]bool
	out  []Artifact
}

// add takes an artifact from masked text. Scrubbing it again only wraps it
// as Text, since a mask is left as it is.
func (c *collector) add(kind Kind, name, text string, o model.Origin) {
	if strings.TrimSpace(text) == "" {
		return
	}
	key := string(kind) + "\x00" + name + "\x00" + text
	if c.seen[key] {
		return
	}
	c.seen[key] = true
	cut := len(text) > MaxArtifactBytes
	if cut {
		text = cutAt(text, MaxArtifactBytes)
	}
	nameText, _ := c.s.Scrub(name)
	bodyText, _ := c.s.Scrub(text)
	c.out = append(c.out, Artifact{Kind: kind, Name: nameText, Text: bodyText, Cut: cut, Origin: o})
}

// cutAt cuts s to at most n bytes, on a rune boundary.
func cutAt(s string, n int) string {
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
