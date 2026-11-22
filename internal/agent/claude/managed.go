package claude

import (
	"encoding/json"
	"errors"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"

	"github.com/nickelsec/jarx/internal/agent"
	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/platform"
	"github.com/nickelsec/jarx/internal/redact"
)

// Managed settings, from code.claude.com/docs/en/managed-settings:
//
//   - Sources rank remote > MDM (macOS plist or the HKLM registry) > managed
//     settings files > the HKCU registry. Remote settings live on a server
//     and the macOS plist's location isn't documented, so jarx reads neither
//     (see Limits in docs/prd.md).
//   - The files are managed-settings.json, then managed-settings.d/*.json in
//     name order, merged. Hidden and non-.json files are skipped.
//   - Under managedSourcesBehavior "first-wins" (the default) only the top
//     source with a policy key counts. Under "merge" every admin source with
//     one counts, but defaultMode comes from the top source only. The key is
//     read from the top source that carries it or a policy key.
//   - HKCU isn't an admin source. It counts only when no admin document is
//     present, and never merges.
//
// The cross-source keys (sandbox locks, deniedMcpServers, env and the rest)
// come with the items that read those keys.

const (
	keyWSLInherits     = "wslInheritsWindowsSettings"
	keyManagedBehavior = "managedSourcesBehavior"
	behaviorMerge      = "merge"
	policyKey          = `SOFTWARE\Policies\ClaudeCode`
	policyValue        = "Settings"
)

// PolicyHelperSet is the info finding for a managed policyHelper: Claude
// runs it to compute managed settings, and jarx doesn't run it.
func PolicyHelperSet() finding.Rule {
	return finding.Rule{
		ID:       "JARX-CLAUDE-001",
		Severity: finding.Info,
		Title:    "managed settings come from a policy helper jarx doesn't run",
		Fix:      "the managed settings shown may not be the ones in force; run /status in Claude Code to see them",
	}
}

// Rules returns the rules the Claude adapter owns.
func Rules() []finding.Rule {
	return []finding.Rule{PolicyHelperSet(), ImportsCredential(), ShellInjection(), RepoSkillGrants()}
}

// managedDirFor is the system dir Claude reads managed settings files from.
// It's "" when the root it hangs off isn't known.
func managedDirFor(goos string, r platform.Roots) string {
	var root, name string
	switch goos {
	case "windows":
		root, name = r.ProgramFiles, "ClaudeCode"
	case "darwin":
		root, name = r.LibraryAppSupport, "ClaudeCode"
	default:
		root, name = r.Etc, "claude-code"
	}
	if root == "" {
		return ""
	}
	return filepath.Join(root, name)
}

func managedDir(env platform.Env) string {
	roots, ok := env.SystemRoots()
	if !ok {
		return ""
	}
	return managedDirFor(env.GOOS, roots)
}

// source is one managed source: its layers highest first, as merged.
type source struct {
	name    string
	admin   bool
	layers  []*layer
	present bool // an admin document is there, even one jarx couldn't read
}

// policy says whether any layer sets a policy key.
func (s *source) policy() bool {
	return slices.ContainsFunc(s.layers, func(l *layer) bool { return l.policy })
}

// carriesBehavior says whether the source carries managedSourcesBehavior or
// a policy key, which is where Claude reads the behavior from.
func (s *source) carriesBehavior() bool {
	return s.policy() || slices.ContainsFunc(s.layers, func(l *layer) bool { return l.behavior != "" })
}

// first returns the value from the highest layer that sets it.
func first[T comparable](s *source, get func(*layer) T) T {
	var zero T
	for _, l := range s.layers {
		if v := get(l); v != zero {
			return v
		}
	}
	return zero
}

// managed is the managed tier as one scan sees it.
type managed struct {
	layers    []*layer // highest first, with the ones that lose marked
	rulesOnly bool     // allowManagedPermissionRulesOnly is on
	unknown   []model.Unknown
	findings  []finding.Finding
}

// readManaged reads every managed source jarx can see and works out which
// ones are in effect.
func readManaged(c agent.Context) managed {
	var m managed
	add := func(s *source, u []model.Unknown, f []finding.Finding) *source {
		m.unknown, m.findings = append(m.unknown, u...), append(m.findings, f...)
		return s
	}
	hklm := add(registrySource(c, platform.HKLM))
	files := add(fileSource(c))
	hkcu := add(registrySource(c, platform.HKCU))
	hkcu.present = false // never an admin document

	m.choose(c, []*source{hklm, files}, hkcu)
	for _, s := range []*source{hklm, files, hkcu} {
		m.layers = append(m.layers, s.layers...)
	}
	return m
}

// choose marks which sources are in effect, sets the managed-only lock and
// adds the policy helper finding.
func (m *managed) choose(c agent.Context, admin []*source, hkcu *source) {
	text := func(s string) redact.Text { t, _ := c.Scrub.Scrub(s); return t }

	candidates := admin
	if slices.ContainsFunc(admin, func(s *source) bool { return s.present }) {
		hkcu.disable(text("HKCU policy is ignored: an admin managed source is present"))
	} else {
		candidates = append(slices.Clone(admin), hkcu)
	}
	topAt := slices.IndexFunc(candidates, (*source).policy)
	if topAt < 0 {
		return
	}
	top := candidates[topAt]
	inUse := sourcesInUse(candidates, top)

	for _, s := range candidates {
		if !slices.Contains(inUse, s) {
			s.disable(text("ignored: " + top.name + " is the managed source in use (first-wins)"))
		}
	}
	for _, s := range inUse[1:] {
		off := text("defaultMode is read only from " + top.name)
		for _, l := range s.layers {
			l.modeOff = off
		}
	}
	m.rulesOnly = slices.ContainsFunc(inUse, func(s *source) bool {
		on := first(s, func(l *layer) *bool { return l.managedOnly })
		return on != nil && *on
	})
	if !top.admin {
		return // Claude ignores a policyHelper in HKCU
	}
	if at := slices.IndexFunc(top.layers, func(l *layer) bool { return l.helper }); at >= 0 {
		ev := text("a policyHelper is set, so Claude computes the managed settings at startup")
		m.findings = append(m.findings, PolicyHelperSet().New(top.layers[at].origin, ev))
	}
}

// sourcesInUse returns the sources Claude applies, top first: just the top
// one under first-wins, or every admin source with a policy key under merge.
// The behavior comes from the highest source that carries it or a policy key.
func sourcesInUse(candidates []*source, top *source) []*source {
	behavior := ""
	if at := slices.IndexFunc(candidates, (*source).carriesBehavior); at >= 0 {
		behavior = first(candidates[at], func(l *layer) string { return l.behavior })
	}
	if behavior != behaviorMerge || !top.admin {
		return []*source{top}
	}
	var inUse []*source
	for _, s := range candidates {
		if s.admin && s.policy() {
			inUse = append(inUse, s)
		}
	}
	return inUse
}

func (s *source) disable(why redact.Text) {
	for _, l := range s.layers {
		l.disable(why)
	}
}

// registrySource reads the Settings value under the policy key in hive.
func registrySource(c agent.Context, hive platform.Hive) (*source, []model.Unknown, []finding.Finding) {
	s := &source{name: hive.String() + " policy", admin: hive == platform.HKLM}
	reg, ok := c.Env.Registry()
	if !ok {
		return s, nil, nil
	}
	where := hive.String() + `\` + policyKey + `\` + policyValue
	origin := model.Origin{Agent: model.AgentClaude, File: model.NewPath(c.Scrub, where), Scope: model.ScopeManaged, InEffect: true}
	v, err := reg.String(hive, policyKey, policyValue)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return s, nil, nil
	case err != nil:
		r := &layerReader{c: c, l: &layer{origin: origin, broken: true}}
		r.problem("couldn't read the registry value")
		s.layers, s.present = []*layer{r.l}, true
		return s, nil, r.findings
	}
	l, u, f := parseLayer(c, origin, []byte(v))
	s.layers = []*layer{l}
	s.present = l.broken || l.policy
	return s, u, f
}

// fileSource reads managed-settings.json and managed-settings.d/*.json. The
// layers come back highest first: the last file in merge order wins.
func fileSource(c agent.Context) (*source, []model.Unknown, []finding.Finding) {
	s := &source{name: "managed settings files", admin: true}
	dir := managedDir(c.Env)
	if dir == "" {
		return s, nil, nil
	}
	dropIns, findings := dropInFiles(c, filepath.Join(dir, "managed-settings.d"))
	s.present = len(findings) > 0
	paths := append([]string{filepath.Join(dir, "managed-settings.json")}, dropIns...)

	var unknown []model.Unknown
	for _, p := range slices.Backward(paths) {
		l, u, f := readLayer(c, p, model.ScopeManaged)
		unknown, findings = append(unknown, u...), append(findings, f...)
		if l != nil {
			s.layers = append(s.layers, l)
			s.present = s.present || l.broken || l.policy
		}
	}
	return s, unknown, findings
}

// dropInFiles lists the *.json files in dir in name order, skipping hidden
// files and anything that isn't a plain file. A folder that's there but
// can't be listed is one finding.
func dropInFiles(c agent.Context, dir string) ([]string, []finding.Finding) {
	entries, err := c.Files.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		r := &layerReader{c: c, l: &layer{broken: true, origin: model.Origin{
			Agent: model.AgentClaude, File: model.NewPath(c.Scrub, dir), Scope: model.ScopeManaged,
		}}}
		r.problem("couldn't list the folder")
		return nil, r.findings
	}
	var names []string
	for _, e := range entries {
		if e.Type().IsRegular() && !strings.HasPrefix(e.Name(), ".") && strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	slices.Sort(names)
	paths := make([]string, 0, len(names))
	for _, n := range names {
		paths = append(paths, filepath.Join(dir, n))
	}
	return paths, nil
}

// managedKey reads the keys that shape the managed tier itself.
func (r *layerReader) managedKey(key string, raw json.RawMessage) {
	switch key {
	case keyManagedBehavior:
		var v string
		if err := json.Unmarshal(raw, &v); err != nil {
			r.problem(key + " isn't a string, skipped")
			return
		}
		r.l.behavior = v
	case "policyHelper":
		r.l.helper = string(raw) != "null"
	case "allowManagedPermissionRulesOnly":
		var v bool
		if err := json.Unmarshal(raw, &v); err != nil {
			r.problem(key + " isn't a bool, skipped")
			return
		}
		r.l.managedOnly = &v
	}
}

// isPolicyKey says whether key set to raw counts as a policy key: any key
// but the two control keys, set to something other than null.
func isPolicyKey(key string, raw json.RawMessage) bool {
	return key != keyWSLInherits && key != keyManagedBehavior && string(raw) != "null"
}
