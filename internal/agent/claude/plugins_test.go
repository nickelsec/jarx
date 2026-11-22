package claude

import (
	"strings"
	"testing"

	"github.com/nickelsec/jarx/internal/model"
)

const fmtRoot = ".claude/plugins/cache/m/fmt/1.0.0"

// fmtPlugin is an installed plugin with one of each component.
func fmtPlugin(enabled string) map[string]string {
	return map[string]string{
		".claude/settings.json": `{"enabledPlugins": {"fmt@m": ` + enabled + `}}`,
		".claude/plugins/installed_plugins.json": `{"version": 2, "plugins": {"fmt@m": [
			{"scope": "user", "installPath": "/` + fmtRoot + `", "version": "1.0.0"}]}}`,
		fmtRoot + "/.claude-plugin/plugin.json": `{"name": "fmt"}`,
		fmtRoot + "/skills/lint/SKILL.md":       "---\ndescription: lint\n---\nrun !`eslint .`",
		fmtRoot + "/commands/go.md":             "go",
		fmtRoot + "/agents/rev.md":              "---\nname: rev\ndescription: d\npermissionMode: bypassPermissions\n---\nx",
		fmtRoot + "/hooks/hooks.json":           `{"hooks": {"PostToolUse": [{"hooks": [{"type": "command", "command": "${CLAUDE_PLUGIN_ROOT}/scripts/f.sh"}]}]}}`,
		fmtRoot + "/scripts/f.sh":               "prettier --write .",
	}
}

func pluginByID(t *testing.T, p model.Project, id string) model.Plugin {
	t.Helper()
	for _, pl := range p.Plugins {
		if pl.ID.String() == id {
			return pl
		}
	}
	t.Fatalf("no plugin %s in %+v", id, p.Plugins)
	return model.Plugin{}
}

func pluginSkills(p model.Project) map[string]model.Skill {
	out := map[string]model.Skill{}
	for _, s := range p.Skills {
		if !s.Plugin.IsZero() {
			out[s.Name.String()] = s
		}
	}
	return out
}

func TestEnabledPluginsMergePerID(t *testing.T) {
	c := fakeHome(t, map[string]string{
		".claude/settings.json":         `{"enabledPlugins": {"a@m": true, "b@m": true}}`,
		"p/.claude/settings.local.json": `{"enabledPlugins": {"b@m": false}}`,
	})

	p, _ := extensionsFor(t, c)

	for id, want := range map[string]struct {
		on    bool
		scope model.Scope
	}{"a@m": {true, model.ScopeUser}, "b@m": {false, model.ScopeLocal}} {
		eff, ok := pluginByID(t, p, id).Enabled.Effective()
		if !ok || eff.Value != want.on || eff.Origin.Scope != want.scope {
			t.Errorf("%s enabled = %+v, want %v from %s", id, eff, want.on, want.scope)
		}
	}
}

func TestAnInstalledPluginComesFromItsInstallRecord(t *testing.T) {
	p, _ := extensionsFor(t, fakeHome(t, fmtPlugin("true")))

	pl := pluginByID(t, p, "fmt@m")
	if !pl.Origin.InEffect || pl.Version.String() != "1.0.0" || !strings.HasSuffix(pl.Path.Raw(), "1.0.0") || !pl.Origin.Observed {
		t.Errorf("plugin = %+v, want loaded, version and path from the (observed) install record", pl)
	}
}

func TestAnInstalledPluginLoadsItsComponents(t *testing.T) {
	c := fakeHome(t, fmtPlugin("true"))

	p, fs := extensionsFor(t, c)

	skills := pluginSkills(p)
	for name, kind := range map[string]model.SkillKind{"fmt:lint": model.SkillSkill, "fmt:go": model.SkillCommand, "fmt:rev": model.SkillSubagent} {
		s, ok := skills[name]
		if !ok || s.Kind != kind || s.Origin.Scope != model.ScopePlugin || !s.Origin.InEffect {
			t.Errorf("%s = %+v (found %v), want a plugin %s in effect", name, skillViews(c, []model.Skill{s}), ok, kind)
		}
	}
	if !skills["fmt:rev"].Mode.IsZero() {
		t.Errorf("plugin subagent mode = %q, want none: Claude ignores permissionMode for plugin subagents", skills["fmt:rev"].Mode)
	}
	if got := len(rulesOf(fs, ShellInjection().ID)); got != 1 {
		t.Errorf("shell injection findings = %d, want 1 for the plugin skill", got)
	}
}

func TestAnInstalledPluginsHooksAreRead(t *testing.T) {
	p, _ := extensionsFor(t, fakeHome(t, fmtPlugin("true")))

	var hook *model.Hook
	for i := range p.Hooks {
		if p.Hooks[i].Origin.Scope == model.ScopePlugin {
			hook = &p.Hooks[i]
		}
	}
	if hook == nil || hook.ScriptText.String() != "prettier --write ." || !hook.Origin.InEffect {
		t.Errorf("plugin hook = %+v, want its script read and in effect", hook)
	}
}

func TestPluginsThatArentOnLoadNothing(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"disabled":      fmtPlugin("false"),
		"not installed": {".claude/settings.json": `{"enabledPlugins": {"fmt@m": true}}`},
		"project enable, untrusted folder": func() map[string]string {
			f := fmtPlugin("true")
			delete(f, ".claude/settings.json")
			f["p/.claude/settings.json"] = `{"enabledPlugins": {"fmt@m": true}}`
			return f
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			c := fakeHome(t, files)
			p := project(c, model.TrustUntrusted)
			ps := []model.Project{p}

			Adapter{}.Extensions(c, ps)

			pl := pluginByID(t, ps[0], "fmt@m")
			if pl.Origin.InEffect || pl.Origin.Why.IsZero() {
				t.Errorf("plugin in effect = %v (why %q), want off with a why", pl.Origin.InEffect, pl.Origin.Why)
			}
			if len(pluginSkills(ps[0])) != 0 || len(ps[0].Hooks) != 0 {
				t.Errorf("components loaded from a plugin that's off: %+v %+v", ps[0].Skills, ps[0].Hooks)
			}
		})
	}
}

func TestUnreadableInstallRecordsDegradeToUnknown(t *testing.T) {
	c := fakeHome(t, map[string]string{
		".claude/settings.json":                  `{"enabledPlugins": {"fmt@m": true}}`,
		".claude/plugins/installed_plugins.json": `["a shape jarx hasn't seen"]`,
	})

	p, fs := extensionsFor(t, c)

	pl := pluginByID(t, p, "fmt@m")
	if !pl.Path.IsZero() || pl.Origin.InEffect || !strings.Contains(pl.Origin.Why.String(), "unknown") {
		t.Errorf("plugin = %+v why %q, want install state unknown", pl, pl.Origin.Why)
	}
	if len(fs) != 0 {
		t.Errorf("findings = %+v, want none: an observed format degrades quietly", fs)
	}
}

func TestPluginComponentPathsCantEscapeTheRoot(t *testing.T) {
	files := fmtPlugin("true")
	files[fmtRoot+"/.claude-plugin/plugin.json"] = `{"name": "fmt", "skills": ["../../../../../../secret-skills", "./extra"]}`
	files[".claude/plugins/secret-skills/x/SKILL.md"] = "outside"
	files[fmtRoot+"/extra/inside/SKILL.md"] = "inside"
	c := fakeHome(t, files)

	p, _ := extensionsFor(t, c)

	skills := pluginSkills(p)
	if _, ok := skills["fmt:inside"]; !ok {
		t.Errorf("skills = %v, want the declared ./extra skill", keys(skills))
	}
	if _, ok := skills["fmt:x"]; ok {
		t.Errorf("a skill from outside the plugin root loaded")
	}
}

func TestManagedHooksOnlyBlocksPluginHooksUnlessManagedEnablesThem(t *testing.T) {
	for name, tc := range map[string]struct {
		managed string
		on      bool
	}{
		"blocked":              {`{"allowManagedHooksOnly": true}`, false},
		"force-enabled by org": {`{"allowManagedHooksOnly": true, "enabledPlugins": {"fmt@m": true}}`, true},
	} {
		t.Run(name, func(t *testing.T) {
			c := managedHome(t, fmtPlugin("true"), map[string]string{"managed-settings.json": tc.managed}, nil)

			p, _ := extensionsFor(t, c)

			for _, h := range p.Hooks {
				if h.Origin.Scope == model.ScopePlugin && h.Origin.InEffect != tc.on {
					t.Errorf("plugin hook in effect = %v (why %q), want %v", h.Origin.InEffect, h.Origin.Why, tc.on)
				}
			}
		})
	}
}

func keys(m map[string]model.Skill) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
