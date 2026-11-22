package claude

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"

	"github.com/nickelsec/jarx/internal/agent"
	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/fsys"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/platform"
	"github.com/nickelsec/jarx/internal/redact"
)

// Settings files and precedence come from code.claude.com/docs/en/settings:
// local (.claude/settings.local.json) > project (.claude/settings.json) >
// user (~/.claude/settings.json, or $CLAUDE_CONFIG_DIR/settings.json). The
// files are strict JSON. Trust rules come from
// code.claude.com/docs/en/permissions#project-allow-rules-and-workspace-trust.
// Managed settings and --settings sit above these and are read separately.

// The adapter reads settings.
var _ agent.SettingsReader = Adapter{}

// layer is what jarx keeps from one settings file. Every string is already
// scrubbed.
type layer struct {
	origin      model.Origin
	defaultMode *redact.Text
	modeOff     redact.Text // set when only this layer's defaultMode is ignored
	rules       []model.PermissionRule
	dirs        []redact.Text

	// broken means the file exists but couldn't be read or parsed. A broken
	// managed document still counts as present.
	broken bool
	// What a managed layer says about the managed tier itself.
	policy      bool   // sets a policy key to something other than null
	behavior    string // managedSourcesBehavior, "" when unset
	helper      bool   // sets a policyHelper
	managedOnly *bool  // allowManagedPermissionRulesOnly

	// What the instruction reader needs. Paths stay raw: jarx reads them.
	outputStyle      *redact.Text
	memoryDir        string // autoMemoryDirectory, "" when unset
	memoryOn         *bool  // autoMemoryEnabled
	instructionFiles string // pluginConfigs: the AGENTS.md plugin's instructionFiles
	claudeMd         *redact.Text
}

// disable takes a whole layer out of effect.
func (l *layer) disable(why redact.Text) {
	l.origin.InEffect, l.origin.Why = false, why
	for i := range l.rules {
		l.rules[i].Origin.InEffect, l.rules[i].Origin.Why = false, why
	}
}

// Settings reads the managed sources and user settings once, then each ok
// project's project and local files, and stores the result on each project.
// Unknown keys come back once per file.
func (Adapter) Settings(c agent.Context, projects []model.Project) ([]model.Unknown, []finding.Finding) {
	all := loadSettings(c)
	unknown, findings := all.unknown, all.findings
	for i := range projects {
		p := &projects[i]
		if p.Status != model.ProjectOK {
			continue
		}
		layers, u, f := all.forProject(c, *p)
		unknown, findings = append(unknown, u...), append(findings, f...)
		if perm, ok := permissions(c, *p, layers, all.managed.rulesOnly); ok {
			p.Permissions = append(p.Permissions, perm)
		}
	}
	return unknown, findings
}

// allSettings is the settings every project shares: the managed tier and
// the user file.
type allSettings struct {
	managed  managed
	user     *layer
	userFile string
	unknown  []model.Unknown
	findings []finding.Finding
}

func loadSettings(c agent.Context) allSettings {
	s := allSettings{managed: readManaged(c), userFile: userSettingsFile(c.Env)}
	s.unknown, s.findings = s.managed.unknown, s.managed.findings
	user, u, f := readLayer(c, s.userFile, model.ScopeUser)
	s.user, s.unknown, s.findings = user, append(s.unknown, u...), append(s.findings, f...)
	return s
}

// shared is the managed and user layers, highest first.
func (s allSettings) shared() []*layer { return append(slices.Clone(s.managed.layers), s.user) }

// forProject returns p's layers, highest first: managed, local, project,
// user. A missing file is a nil layer.
func (s allSettings) forProject(c agent.Context, p model.Project) ([]*layer, []model.Unknown, []finding.Finding) {
	dir := filepath.Join(p.Path.Raw(), ".claude")
	layers := slices.Clone(s.managed.layers)
	local, unknown, findings := readLayer(c, filepath.Join(dir, "settings.local.json"), model.ScopeLocal)
	layers = append(layers, local)
	if projFile := filepath.Join(dir, "settings.json"); projFile != s.userFile {
		proj, u, f := readLayer(c, projFile, model.ScopeProject)
		unknown, findings = append(unknown, u...), append(findings, f...)
		layers = append(layers, proj)
	}
	return append(layers, s.user), unknown, findings
}

// effective returns the value from the highest in-effect layer that sets
// it, and that layer.
func effective[T comparable](layers []*layer, get func(*layer) T) (T, *layer) {
	var zero T
	for _, l := range layers {
		if l == nil || !l.origin.InEffect {
			continue
		}
		if v := get(l); v != zero {
			return v, l
		}
	}
	return zero, nil
}

func userSettingsFile(env platform.Env) string {
	if dir, ok := env.Lookup("CLAUDE_CONFIG_DIR"); ok && dir != "" {
		return filepath.Join(env.MapPath(dir), "settings.json")
	}
	return filepath.Join(env.Home, ".claude", "settings.json")
}

// configHome says whether dir is the user's configuration home: the home dir,
// or the dir whose .claude subdir CLAUDE_CONFIG_DIR names. Local allows there
// skip the trust step.
func configHome(env platform.Env, dir string) bool {
	if dir == env.Home {
		return true
	}
	if cfg, ok := env.Lookup("CLAUDE_CONFIG_DIR"); ok && cfg != "" {
		cfg = env.MapPath(cfg)
		return filepath.Base(cfg) == ".claude" && filepath.Dir(cfg) == dir
	}
	return false
}

// trustWhy says why trust-gated values from a project wait, or "" when the
// project is trusted.
func trustWhy(p model.Project) string {
	for _, t := range p.Trust {
		if t.Origin.Agent != model.AgentClaude {
			continue
		}
		switch t.Level {
		case model.TrustTrusted:
			return ""
		case model.TrustUntrusted:
			return "waits for trust: the folder isn't trusted"
		case model.TrustUnknown:
			return "waits for trust: trust is unknown"
		}
	}
	return "waits for trust: Claude has no trust record for this folder"
}

// permissions merges the layers, highest first, into one view for p. It
// marks what Claude ignores or holds back, and why.
func permissions(c agent.Context, p model.Project, layers []*layer, managedOnly bool) (model.Permissions, bool) {
	m := merger{
		c:           c,
		waits:       trustWhy(p),
		home:        configHome(c.Env, p.Path.Raw()),
		managedOnly: managedOnly,
		perm:        model.Permissions{Agent: model.AgentClaude},
	}
	for _, l := range layers {
		if l != nil {
			m.add(l)
		}
	}
	m.settleModes()
	ok := len(m.perm.DefaultMode.Layers) > 0 || len(m.perm.Rules) > 0 || len(m.perm.AdditionalDirectories) > 0
	return m.perm, ok
}

// merger builds one project's Permissions from its layers.
type merger struct {
	c           agent.Context
	waits       string // why trust-gated values wait, "" when trusted
	home        bool   // the project is the config home
	managedOnly bool   // allowManagedPermissionRulesOnly is on
	perm        model.Permissions
}

func (m *merger) add(l *layer) {
	if l.defaultMode != nil {
		m.perm.DefaultMode.Layers = append(m.perm.DefaultMode.Layers, model.Layer[redact.Text]{Value: *l.defaultMode, Origin: m.modeOrigin(l)})
	}
	for _, r := range l.rules {
		m.perm.Rules = append(m.perm.Rules, m.rule(r))
	}
	for _, d := range l.dirs {
		m.perm.AdditionalDirectories = append(m.perm.AdditionalDirectories,
			model.Layer[redact.Text]{Value: d, Origin: m.gate(l.origin)})
	}
}

// modeOrigin is where l's defaultMode came from, out of effect when Claude
// ignores it there.
func (m *merger) modeOrigin(l *layer) model.Origin {
	o := l.origin
	switch {
	case !o.InEffect:
	case !l.modeOff.IsZero():
		o.InEffect, o.Why = false, l.modeOff
	case repoFile(o.Scope) && bypassLike(l.defaultMode.String()):
		o.InEffect = false
		o.Why = m.why("defaultMode " + l.defaultMode.String() + " is ignored from " + string(o.Scope) + " files")
	}
	return o
}

// rule applies the managed-only lock and the trust gate to one rule.
func (m *merger) rule(r model.PermissionRule) model.PermissionRule {
	if m.managedOnly && r.Origin.Scope != model.ScopeManaged && r.Origin.InEffect {
		r.Origin.InEffect = false
		r.Origin.Why = m.why("allowManagedPermissionRulesOnly is on in managed settings, so Claude ignores rules from " +
			string(r.Origin.Scope) + " files")
	}
	if r.Action == model.RuleAllow {
		r.Origin = m.gate(r.Origin)
	}
	return r
}

// gate holds back a value that grants something until the folder is
// trusted. Project values always wait. Local ones do too, apart from the
// config home, since Claude only checks whether the local file is the user's
// own after the folder is trusted.
func (m *merger) gate(o model.Origin) model.Origin {
	gated := m.waits != "" && (o.Scope == model.ScopeProject || (o.Scope == model.ScopeLocal && !m.home))
	if gated && o.InEffect {
		o.InEffect, o.Why = false, m.why(string(o.Scope)+" allow "+m.waits)
	}
	return o
}

// settleModes leaves only the highest in-effect defaultMode layer in effect.
func (m *merger) settleModes() {
	won := false
	for i := range m.perm.DefaultMode.Layers {
		o := &m.perm.DefaultMode.Layers[i].Origin
		if o.InEffect && won {
			o.InEffect, o.Why = false, m.why("overridden by a higher scope")
		}
		won = won || o.InEffect
	}
}

func (m *merger) why(s string) redact.Text {
	t, _ := m.c.Scrub.Scrub(s)
	return t
}

func repoFile(s model.Scope) bool { return s == model.ScopeProject || s == model.ScopeLocal }

// bypassLike is a defaultMode Claude won't take from project or local files.
func bypassLike(mode string) bool { return mode == "auto" || mode == "bypassPermissions" }

// readLayer reads one settings file. A missing file is nil with no findings.
// A file that exists but can't be read is a broken layer: too large ones are
// recorded by fsys, others get a finding.
func readLayer(c agent.Context, path string, scope model.Scope) (*layer, []model.Unknown, []finding.Finding) {
	origin := model.Origin{Agent: model.AgentClaude, File: model.NewPath(c.Scrub, path), Scope: scope, InEffect: true}
	data, err := c.Files.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, nil, nil
	case errors.Is(err, fsys.ErrTooLarge):
		return &layer{origin: origin, broken: true}, nil, nil // fsys records it, and it becomes a finding
	case err != nil:
		r := &layerReader{c: c, l: &layer{origin: origin, broken: true}}
		r.problem("couldn't open the file")
		return r.l, nil, r.findings
	}
	return parseLayer(c, origin, data)
}

// parseLayer parses one settings document. One that isn't valid JSON is a
// broken layer and one finding that says where, never what. A bad value is
// skipped with a finding and the rest is kept, like Claude does.
func parseLayer(c agent.Context, origin model.Origin, data []byte) (*layer, []model.Unknown, []finding.Finding) {
	r := &layerReader{c: c, l: &layer{origin: origin}}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		r.l.broken = true
		r.problem(jsonProblem(data, err))
		return r.l, nil, r.findings
	}
	for _, key := range sortedKeys(top) {
		r.topKey(key, top[key])
	}
	return r.l, r.unknown, r.findings
}

// layerReader collects one file's layer, unknown keys and findings.
type layerReader struct {
	c        agent.Context
	l        *layer
	unknown  []model.Unknown
	findings []finding.Finding
}

func (r *layerReader) topKey(key string, raw json.RawMessage) {
	r.l.policy = r.l.policy || isPolicyKey(key, raw)
	known, allowed := keyAllowed(key, r.l.origin.Scope)
	if !known {
		if !hasKnownChild(key) {
			r.unknownKey(key)
		}
		return
	}
	if r.l.origin.Scope == model.ScopeManaged && allowed {
		r.managedKey(key, raw)
	}
	if allowed {
		r.instructionKey(key, raw)
	}
	if key != "permissions" {
		return // read by later items, or not needed yet
	}
	var perms map[string]json.RawMessage
	if err := json.Unmarshal(raw, &perms); err != nil {
		r.problem("permissions isn't a JSON object")
		return
	}
	for _, sub := range sortedKeys(perms) {
		r.permission(sub, perms[sub])
	}
}

// permission reads one key inside permissions.
func (r *layerReader) permission(sub string, raw json.RawMessage) {
	full := "permissions." + sub
	known, allowed := keyAllowed(full, r.l.origin.Scope)
	if !known {
		r.unknownKey(full)
		return
	}
	o := r.l.origin
	if !allowed {
		o.InEffect = false
		o.Why = r.scrub("Claude doesn't read " + full + " from " + string(o.Scope) + " files")
	}
	switch sub {
	case "allow", "ask", "deny":
		for _, rule := range r.strings(full, raw) {
			r.l.rules = append(r.l.rules, model.PermissionRule{Action: model.RuleAction(sub), Rule: rule, Origin: o})
		}
	case "additionalDirectories":
		r.l.dirs = append(r.l.dirs, r.strings(full, raw)...)
	case "defaultMode":
		var mode string
		if err := json.Unmarshal(raw, &mode); err != nil {
			r.problem(full + " isn't a string, skipped")
			return
		}
		t := r.scrub(mode)
		r.l.defaultMode = &t
	}
}

// strings decodes a JSON list of strings, scrubbing each. Entries that
// aren't strings, or a value that isn't a list, get one finding.
func (r *layerReader) strings(full string, raw json.RawMessage) []redact.Text {
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		r.problem(full + " isn't a list of strings, skipped")
		return nil
	}
	out := make([]redact.Text, 0, len(items))
	bad := false
	for _, it := range items {
		var s string
		if err := json.Unmarshal(it, &s); err != nil {
			bad = true
			continue
		}
		out = append(out, r.scrub(s))
	}
	if bad {
		r.problem(full + " has values that aren't strings, skipped")
	}
	return out
}

func (r *layerReader) problem(why string) {
	r.findings = append(r.findings, finding.UnreadableRecord().New(r.l.origin, r.scrub(why)))
}

func (r *layerReader) unknownKey(key string) {
	r.unknown = append(r.unknown, model.Unknown{Key: r.scrub(key), Origin: r.l.origin})
}

func (r *layerReader) scrub(s string) redact.Text {
	t, _ := r.c.Scrub.Scrub(s)
	return t
}

// jsonProblem says what's wrong with data and on which line, never quoting
// it.
func jsonProblem(data []byte, err error) string {
	if syn, ok := errors.AsType[*json.SyntaxError](err); ok {
		line := bytes.Count(data[:min(int(syn.Offset), len(data))], []byte("\n")) + 1
		return fmt.Sprintf("not valid JSON (line %d)", line)
	}
	if _, ok := errors.AsType[*json.UnmarshalTypeError](err); ok {
		return "the file isn't a JSON object"
	}
	return "not valid JSON"
}
