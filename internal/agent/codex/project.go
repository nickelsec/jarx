package codex

import (
	"path/filepath"
	"slices"
	"strings"

	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/redact"
)

// view is one project's layers, highest first.
type view struct {
	s        *settings
	layers   []*layer
	findings []finding.Finding
}

func (s *settings) forProject(p model.Project) *view {
	v := &view{s: s}
	add := func(l *layer) {
		if l != nil {
			v.layers = append(v.layers, l)
		}
	}
	add(s.managed)
	for _, l := range s.projectLayers(p) {
		add(l)
	}
	for _, l := range s.profiles {
		add(l)
	}
	add(s.user)
	add(s.system)
	return v
}

// projectLayers reads every .codex/config.toml from the project root marker
// down to the project dir, closest first. They load only when the project
// is trusted.
func (s *settings) projectLayers(p model.Project) []*layer {
	why := projectTrustWhy(p)
	var out []*layer
	for _, dir := range s.projectDirs(p.Path.Raw()) {
		l := s.read(filepath.Join(dir, ".codex", "config.toml"), model.ScopeProject)
		if l == nil {
			continue
		}
		// Codex ignores provider, notification, telemetry and profile keys
		// in project files (openai_base_url, model_provider, notify, otel,
		// profile, profiles and a few more), with a startup warning. None of
		// those are options jarx records yet; the egress panel in phase 5
		// will need to skip them from project layers.
		l.legacy = false
		if why != "" {
			l.origin.InEffect, l.origin.Why = false, s.text(why)
		}
		out = append(out, l)
	}
	return out
}

func projectTrustWhy(p model.Project) string {
	for _, t := range p.Trust {
		if t.Origin.Agent != model.AgentCodex {
			continue
		}
		if t.Level == model.TrustTrusted {
			return ""
		}
		return "Codex loads project config only in trusted projects, and this one's trust is " + string(t.Level)
	}
	return "Codex loads project config only in trusted projects, and this one has no trust record"
}

// projectDirs is the project dir and its parents up to the project root
// marker, closest first. With no marker found, it's the project dir alone.
func (s *settings) projectDirs(dir string) []string {
	markers := []string{".git"}
	for _, l := range []*layer{s.user, s.system} {
		if l != nil && l.hasMarks {
			markers = l.markers
			break
		}
	}
	var dirs []string
	for d := filepath.Clean(dir); ; d = filepath.Dir(d) {
		dirs = append(dirs, d)
		if slices.ContainsFunc(markers, func(m string) bool { _, err := s.c.Files.Stat(filepath.Join(d, m)); return err == nil }) {
			return dirs
		}
		if filepath.Dir(d) == d || (s.c.Env.Fake() && d == s.c.Env.Home) || len(markers) == 0 {
			return []string{filepath.Clean(dir)}
		}
	}
}

// loaded is every layer that's in effect, highest first.
func (v *view) loaded() []*layer {
	return slices.DeleteFunc(slices.Clone(v.layers), func(l *layer) bool { return !l.origin.InEffect })
}

// legacySandbox reports the layer whose sandbox_mode makes Codex use the
// legacy sandbox, or nil when permission profiles are in use.
func (v *view) legacySandbox() *layer {
	if v.s.req != nil && v.s.req.profiles != nil {
		return nil // managed allowed_permission_profiles makes Codex use profiles
	}
	for _, l := range v.loaded() {
		if _, ok := l.values[keySandboxMode]; ok {
			return l
		}
	}
	return nil
}

func (v *view) permissions() (model.Permissions, bool) {
	perm := model.Permissions{Agent: model.AgentCodex}
	legacy := v.legacySandbox()
	for _, key := range optionKeys {
		if o, ok := v.option(key, legacy); ok {
			perm.Options = append(perm.Options, o)
		}
	}
	perm.Rules = v.rules(perm, legacy)
	v.sandboxFindings(legacy)
	v.profileFindings()
	return perm, len(perm.Options) > 0 || len(perm.Rules) > 0
}

// option builds one key's layers: the highest loaded layer that requirements
// allow wins.
func (v *view) option(key string, legacy *layer) (model.Option, bool) {
	o := model.Option{Key: v.s.text(key)}
	won := false
	for _, l := range v.layers {
		val, ok := l.values[key]
		if !ok {
			continue
		}
		origin := l.origin
		if why := v.optionWhy(key, val, legacy, won); origin.InEffect && why != "" {
			origin.InEffect, origin.Why = false, v.s.text(why)
		}
		won = won || origin.InEffect
		o.Setting.Layers = append(o.Setting.Layers, model.Layer[redact.Text]{Value: v.s.text(val), Origin: origin})
	}
	return o, len(o.Setting.Layers) > 0
}

// optionWhy says why a loaded layer's value isn't the one in effect, or "".
func (v *view) optionWhy(key, val string, legacy *layer, won bool) string {
	switch {
	case key == keyDefaultPerm && legacy != nil:
		return "sandbox_mode is set in " + legacy.origin.File.Text().String() + ", so Codex uses the legacy sandbox and ignores default_permissions"
	case key == keySandboxMode && v.s.req != nil && v.s.req.profiles != nil:
		return "managed allowed_permission_profiles makes Codex use permission profiles instead"
	case won:
		return "overridden by a higher layer"
	}
	if v.s.req != nil {
		if allowed, ok := v.s.req.allowed[key]; ok && !slices.Contains(allowed, val) {
			return "requirements don't allow " + val + " (allowed: " + strings.Join(allowed, ", ") + "); Codex falls back to an allowed value"
		}
	}
	return ""
}

// activeProfile is the permission profile in effect, or "".
func activeProfile(perm model.Permissions) string {
	for _, o := range perm.Options {
		if o.Key.String() != keyDefaultPerm {
			continue
		}
		if eff, ok := o.Setting.Effective(); ok {
			return eff.Value.String()
		}
	}
	return ""
}

// rules lists every permission profile's filesystem rules. For each profile
// and path the highest loaded layer wins. Only the active profile's rules
// are in effect, and none are under the legacy sandbox.
func (v *view) rules(perm model.Permissions, legacy *layer) []model.PermissionRule {
	active := activeProfile(perm)
	seen := map[string]bool{}
	var out []model.PermissionRule
	for _, l := range v.layers {
		for _, name := range sortedKeys(l.profiles) {
			for _, path := range sortedKeys(l.profiles[name]) {
				o := l.origin
				key := name + "\x00" + path
				why := ""
				switch {
				case !o.InEffect:
				case legacy != nil:
					why = "sandbox_mode is set in " + legacy.origin.File.Text().String() + ", so Codex ignores permission profiles"
				case seen[key]:
					why = "overridden by a higher layer"
				case v.s.text(name).String() != active:
					why = "profile " + name + " isn't the one selected"
				}
				if o.InEffect {
					seen[key] = true
				}
				if why != "" {
					o.InEffect, o.Why = false, v.s.text(why)
				}
				out = append(out, model.PermissionRule{Action: access(l.profiles[name][path]), Rule: v.s.text(name + " " + path), Origin: o})
			}
		}
	}
	return out
}

// access maps a filesystem entry's value to a rule action.
func access(a string) model.RuleAction {
	switch a {
	case "write":
		return model.RuleWrite
	case "deny":
		return model.RuleDeny
	default:
		return model.RuleRead
	}
}

// sandboxFindings flags a sandbox_mode that turns off a default_permissions
// set in another layer: high when a project file does it, medium when it's
// the user's own layers.
func (v *view) sandboxFindings(legacy *layer) {
	if legacy == nil {
		return
	}
	var dp *layer
	for _, l := range v.loaded() {
		if _, ok := l.values[keyDefaultPerm]; ok && l != legacy {
			dp = l
			break
		}
	}
	if dp == nil {
		if _, ok := legacy.values[keyDefaultPerm]; !ok {
			return
		}
		dp = legacy
	}
	ev := v.s.text(legacy.origin.File.Text().String() + " sets sandbox_mode = " + legacy.values[keySandboxMode] +
		", so Codex ignores default_permissions = " + dp.values[keyDefaultPerm] + " from " + string(dp.origin.Scope) + " settings")
	rule := OwnSandboxModeWins()
	if legacy.origin.Scope == model.ScopeProject && dp.origin.Scope != model.ScopeProject {
		rule = RepoDropsPermissions()
	}
	v.findings = append(v.findings, rule.New(legacy.origin, ev))
}

// profileFindings flags a loaded project layer that changes a permission
// profile a loaded non-project layer defines.
func (v *view) profileFindings() {
	theirs := map[string]model.Scope{}
	for _, l := range v.loaded() {
		if l.origin.Scope == model.ScopeProject {
			continue
		}
		for name := range l.profiles {
			if _, ok := theirs[name]; !ok {
				theirs[name] = l.origin.Scope
			}
		}
	}
	for _, l := range v.loaded() {
		if l.origin.Scope != model.ScopeProject {
			continue
		}
		for _, name := range sortedKeys(l.profiles) {
			if scope, ok := theirs[name]; ok {
				ev := v.s.text(l.origin.File.Text().String() + " changes permission profile " + name + ", defined in " + string(scope) + " settings")
				v.findings = append(v.findings, RepoWidensProfile().New(l.origin, ev))
			}
		}
	}
}
