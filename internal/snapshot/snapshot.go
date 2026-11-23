// Package snapshot saves what each scan found, masked, keeps the newest
// Keep of them, and works out what changed since the last one. A snapshot
// holds texts only as hashes of their masked form, never the text, so jarx
// doesn't keep copies of your instruction and memory files on disk.
package snapshot

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/redact"
)

// Version is the snapshot format. A snapshot from a newer jarx isn't read.
const Version = 1

// Kind is what an item is.
type Kind string

// Item kinds, in the order the diff lists them.
const (
	KindFinding     Kind = "finding"
	KindUnknown     Kind = "unknown setting"
	KindProject     Kind = "project"
	KindInstruction Kind = "instruction"
	KindSkill       Kind = "skill"
	KindHook        Kind = "hook"
	KindRule        Kind = "rule"
	KindOption      Kind = "setting"
	KindConfig      Kind = "config file"
	KindServer      Kind = "mcp server"
)

// Item is one thing a scan found. Project, Kind and Key say which thing it
// is; the rest is its state, which the diff compares.
type Item struct {
	Project  redact.Text // the project dir, or empty for scan-wide items
	Kind     Kind
	Key      redact.Text
	InEffect bool
	Why      redact.Text
	Hash     string // of the masked text, when the item has one
	Value    redact.Text
}

// Snapshot is one scan.
type Snapshot struct {
	Taken time.Time
	Items []Item
}

// Input is what a scan found.
type Input struct {
	Projects     []model.Project
	Instructions []model.Instruction // not tied to a project
	Unknown      []model.Unknown
	Findings     []finding.Finding
}

// hashLen is how many hex chars of the SHA-256 a snapshot keeps: plenty to
// tell a change.
const hashLen = 16

func hash(t redact.Text) string {
	if t.IsZero() {
		return ""
	}
	sum := sha256.Sum256([]byte(t.String()))
	return hex.EncodeToString(sum[:])[:hashLen]
}

// builder collects items, keeping the first of each identity.
type builder struct {
	s     *redact.Scrubber
	seen  map[string]bool
	items []Item
}

func (b *builder) add(it Item) {
	id := it.Project.String() + "\x00" + string(it.Kind) + "\x00" + it.Key.String()
	if b.seen[id] {
		return
	}
	b.seen[id] = true
	b.items = append(b.items, it)
}

// Build makes a snapshot of in, taken at taken.
func Build(s *redact.Scrubber, taken time.Time, in Input) Snapshot {
	b := &builder{s: s, seen: map[string]bool{}}
	for _, f := range in.Findings {
		b.add(Item{Kind: KindFinding, Key: b.join(f.RuleID, where(f.Origin), f.Evidence.String()), Value: b.join(f.Severity.String())})
	}
	for _, u := range in.Unknown {
		b.add(Item{Kind: KindUnknown, Key: b.join(string(u.Origin.Agent), u.Key.String(), "in", u.Origin.File.Text().String()), Value: u.Near})
	}
	for _, in := range in.Instructions {
		b.instruction(redact.Text{}, in)
	}
	for _, p := range in.Projects {
		b.project(p)
	}
	return Snapshot{Taken: taken, Items: b.items}
}

func (b *builder) project(p model.Project) {
	dir := p.Path.Text()
	agents := make([]string, 0, len(p.Trust))
	for _, t := range p.Trust {
		agents = append(agents, string(t.Origin.Agent)+" "+string(t.Level))
	}
	b.add(Item{Project: dir, Kind: KindProject, Key: dir, Value: b.join(string(p.Status), strings.Join(agents, ", "))})
	for _, in := range p.Instructions {
		b.instruction(dir, in)
	}
	for _, sk := range p.Skills {
		tools := make([]string, 0, len(sk.Tools))
		for _, t := range sk.Tools {
			tools = append(tools, t.String())
		}
		b.add(Item{
			Project: dir, Kind: KindSkill, Key: b.join(string(sk.Origin.Agent), string(sk.Kind), sk.Name.String(), sk.Path.Text().String()),
			InEffect: sk.Origin.InEffect, Why: sk.Origin.Why, Hash: hash(sk.Text), Value: b.join(strings.Join(tools, ", ")),
		})
	}
	for _, h := range p.Hooks {
		b.add(Item{
			Project: dir, Kind: KindHook,
			Key:      b.join(string(h.Origin.Agent), h.Event.String(), h.Matcher.String(), h.Type.String(), h.Run.String(), "in", h.Origin.File.Text().String()),
			InEffect: h.Origin.InEffect, Why: h.Origin.Why, Hash: hash(h.ScriptText),
		})
	}
	for _, s := range p.Servers {
		b.server(dir, s)
	}
	for _, perm := range p.Permissions {
		b.permissions(dir, perm)
	}
	for _, c := range p.Configs {
		b.add(Item{Project: dir, Kind: KindConfig, Key: b.join(string(c.Origin.Agent), c.Origin.File.Text().String()), InEffect: c.Origin.InEffect, Hash: hash(c.Text)})
	}
}

func (b *builder) instruction(dir redact.Text, in model.Instruction) {
	b.add(Item{
		Project: dir, Kind: KindInstruction, Key: b.join(string(in.Origin.Agent), string(in.Kind), in.Path.Text().String()),
		InEffect: in.Origin.InEffect, Why: in.Origin.Why, Hash: hash(in.Text), Value: b.join(string(in.Read)),
	})
}

func (b *builder) permissions(dir redact.Text, perm model.Permissions) {
	agent := string(perm.Agent)
	for _, l := range perm.DefaultMode.Layers {
		b.add(Item{Project: dir, Kind: KindOption, Key: b.join(agent, "defaultMode in", l.Origin.File.Text().String()), InEffect: l.Origin.InEffect, Why: l.Origin.Why, Value: l.Value})
	}
	for _, o := range perm.Options {
		for _, l := range o.Setting.Layers {
			b.add(Item{Project: dir, Kind: KindOption, Key: b.join(agent, o.Key.String(), "in", l.Origin.File.Text().String()), InEffect: l.Origin.InEffect, Why: l.Origin.Why, Value: l.Value})
		}
	}
	for _, r := range perm.Rules {
		b.add(Item{Project: dir, Kind: KindRule, Key: b.join(agent, string(r.Action), r.Rule.String(), "in", r.Origin.File.Text().String()), InEffect: r.Origin.InEffect, Why: r.Origin.Why})
	}
	for _, d := range perm.AdditionalDirectories {
		b.add(Item{Project: dir, Kind: KindRule, Key: b.join(agent, "additionalDirectories", d.Value.String(), "in", d.Origin.File.Text().String()), InEffect: d.Origin.InEffect, Why: d.Origin.Why})
	}
}

func where(o model.Origin) string {
	w := o.File.Text().String()
	if o.Line > 0 {
		w += ":" + strconv.Itoa(o.Line)
	}
	return w
}

// join builds a Text from parts that are already masked or jarx's own
// words. Scrubbing them again is a no-op, since the scrubber leaves masks
// alone, but going through redact keeps the rule that only it makes a Text.
func (b *builder) join(parts ...string) redact.Text {
	var nonEmpty []string
	for _, p := range parts {
		if p != "" {
			nonEmpty = append(nonEmpty, p)
		}
	}
	t, _ := b.s.Scrub(strings.Join(nonEmpty, " "))
	return t
}

// server keeps an MCP server definition by its name and file, with whether
// it starts as the value and its whole masked definition as a hash, so a
// changed command, URL or header shows as "content changed".
func (b *builder) server(dir redact.Text, s model.Server) {
	parts := make([]string, 0, 4+len(s.Args)+len(s.Env)+len(s.Headers))
	parts = append(parts, string(s.Transport), s.Command.String())
	for _, a := range s.Args {
		parts = append(parts, a.String())
	}
	parts = append(parts, s.URL.String(), s.HeadersHelper.String())
	for _, kv := range append(slices.Clone(s.Env), s.Headers...) {
		parts = append(parts, kv.Key.String()+"="+kv.Value.String())
	}
	b.add(Item{
		Project: dir, Kind: KindServer,
		Key:      b.join(string(s.Origin.Agent), string(s.Origin.Scope), s.Name.String(), "in", s.Origin.File.Text().String()),
		InEffect: s.Origin.InEffect, Why: s.Origin.Why, Value: b.join(string(s.Start)), Hash: hash(b.join(strings.Join(parts, "\x00"))),
	})
}
