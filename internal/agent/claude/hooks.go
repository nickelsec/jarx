package claude

import (
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"

	"github.com/nickelsec/jarx/internal/agent"
	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/redact"
)

// Hooks, from code.claude.com/docs/en/hooks: a hooks object maps an event to
// matcher groups, each with a list of handlers of type command, http,
// mcp_tool, prompt or agent. Hooks from every settings scope merge. A
// disableAllHooks from outside managed settings can't turn off managed
// hooks, and a managed allowManagedHooksOnly blocks every other hook.
//
// jarx only reads hooks. It never runs a command, sends a request, calls a
// tool or a model, and it never fills in a variable: commands are shown as
// written.

// rawHook is one handler as a settings file wrote it.
type rawHook struct {
	event, matcher string
	handler        hookHandler
}

type hookHandler struct {
	Type    string   `json:"type"`
	Command string   `json:"command"`
	Args    []string `json:"args"`
	URL     string   `json:"url"`
	Server  string   `json:"server"`
	Tool    string   `json:"tool"`
	Prompt  string   `json:"prompt"`
}

// run is what a handler runs, as written.
func (h hookHandler) run() string {
	switch h.Type {
	case typeHTTP:
		return h.URL
	case "mcp_tool":
		return strings.TrimSpace(h.Server + " " + h.Tool)
	case "prompt", "agent":
		return h.Prompt
	default:
		return strings.Join(append([]string{h.Command}, h.Args...), " ")
	}
}

// parseHooks reads a hooks object, skipping what it can't read with a
// finding each.
func (r *layerReader) parseHooks(raw json.RawMessage) []rawHook {
	var events map[string]json.RawMessage
	if json.Unmarshal(raw, &events) != nil {
		r.problem("hooks isn't a JSON object")
		return nil
	}
	var out []rawHook
	for _, event := range sortedKeys(events) {
		var groups []struct {
			Matcher string            `json:"matcher"`
			Hooks   []json.RawMessage `json:"hooks"`
		}
		if json.Unmarshal(events[event], &groups) != nil {
			r.problem("hooks." + event + " isn't a list of matcher groups, skipped")
			continue
		}
		for _, g := range groups {
			for _, h := range g.Hooks {
				var handler hookHandler
				if json.Unmarshal(h, &handler) != nil {
					r.problem("a hook handler under " + event + " isn't a valid object, skipped")
					continue
				}
				out = append(out, rawHook{event: event, matcher: g.Matcher, handler: handler})
			}
		}
	}
	return out
}

// extensionKey reads the settings keys the extensions reader needs.
func (r *layerReader) extensionKey(key string, raw json.RawMessage) {
	boolValue := func() *bool {
		var v bool
		if json.Unmarshal(raw, &v) != nil {
			r.problem(key + " isn't a bool, skipped")
			return nil
		}
		return &v
	}
	switch key {
	case "hooks":
		r.l.hooks = r.parseHooks(raw)
	case "disableAllHooks":
		r.l.hooksOff = boolValue()
	case "allowManagedHooksOnly":
		r.l.managedHooks = boolValue()
	case "disableSkillShellExecution":
		r.l.skillShellOff = boolValue()
	case "enabledPlugins":
		if json.Unmarshal(raw, &r.l.enabledPlugins) != nil {
			r.problem("enabledPlugins isn't a map of plugin ids to true or false, skipped")
		}
	}
}

// The adapter reads extensions.
var _ agent.ExtensionReader = Adapter{}

// Extensions lists the hooks, skills, commands, subagents and plugins Claude
// would use in each ok project. Parse problems in settings files are
// reported by Settings, not again here.
func (Adapter) Extensions(c agent.Context, projects []model.Project) []finding.Finding {
	all := loadSettings(c)
	var findings []finding.Finding
	sh := loadMCPShared(c, func(o model.Origin, why string) {
		t, _ := c.Scrub.Scrub(why)
		findings = append(findings, finding.UnreadableRecord().New(o, t))
	})
	for i := range projects {
		p := &projects[i]
		if p.Status != model.ProjectOK {
			continue
		}
		layers, _, _ := all.forProject(c, *p)
		e := &extReader{c: c, project: p, layers: layers}
		e.settingsHooks()
		e.skills(claudeDir(c.Env))
		e.subagents(claudeDir(c.Env))
		e.plugins(claudeDir(c.Env))
		e.servers(sh)
		findings = append(findings, e.findings...)
	}
	return findings
}

// extReader collects one project's extensions.
type extReader struct {
	c        agent.Context
	project  *model.Project
	layers   []*layer
	findings []finding.Finding
}

func (e *extReader) text(s string) redact.Text {
	t, _ := e.c.Scrub.Scrub(s)
	return t
}

// managedLayers and otherLayers split the layers, highest first.
func (e *extReader) managedLayers() []*layer {
	return slices.DeleteFunc(slices.Clone(e.layers), func(l *layer) bool { return l == nil || l.origin.Scope != model.ScopeManaged })
}

func (e *extReader) otherLayers() []*layer {
	return slices.DeleteFunc(slices.Clone(e.layers), func(l *layer) bool { return l == nil || l.origin.Scope == model.ScopeManaged })
}

// hooksOffWhy says why a hook from scope is off, or "".
func (e *extReader) hooksOffWhy(scope model.Scope) string {
	if scope != model.ScopeManaged {
		if on, _ := effective(e.managedLayers(), func(l *layer) *bool { return l.managedHooks }); on != nil && *on {
			return "allowManagedHooksOnly is on in managed settings, so only managed hooks run"
		}
		if off, l := effective(e.otherLayers(), func(l *layer) *bool { return l.hooksOff }); off != nil && *off {
			return "disableAllHooks is on in " + string(l.origin.Scope) + " settings"
		}
		return ""
	}
	if off, _ := effective(e.managedLayers(), func(l *layer) *bool { return l.hooksOff }); off != nil && *off {
		return "disableAllHooks is on in managed settings"
	}
	return ""
}

// settingsHooks adds the hooks from every settings layer.
func (e *extReader) settingsHooks() {
	for _, l := range e.layers {
		if l == nil {
			continue
		}
		for _, h := range l.hooks {
			o := l.origin
			if why := e.hooksOffWhy(o.Scope); o.InEffect && why != "" {
				o.InEffect, o.Why = false, e.text(why)
			}
			e.project.Hooks = append(e.project.Hooks, e.hook(h, o, ""))
		}
	}
}

// hook builds a model Hook and reads the script its command runs, if jarx
// can tell which. pluginRoot is the plugin's dir for plugin hooks.
func (e *extReader) hook(h rawHook, o model.Origin, pluginRoot string) model.Hook {
	out := model.Hook{
		Event: e.text(h.event), Matcher: e.text(h.matcher), Type: e.text(h.handler.Type),
		Run: e.text(h.handler.run()), Origin: o,
	}
	if h.handler.Type != "" && h.handler.Type != "command" {
		return out
	}
	script := scriptPath(e.c, e.project.Path.Raw(), pluginRoot, h.handler)
	if script == "" {
		return out
	}
	out.Script = model.NewPath(e.c.Scrub, script)
	r := &reader{c: e.c}
	var data []byte
	out.ScriptRead, data = r.read(script)
	if out.ScriptRead == model.ReadOK {
		out.ScriptText = e.text(string(data))
	}
	return out
}

// scriptExts are file types a hook command runs as a script.
//
//nolint:gochecknoglobals // fixed list, read only
var scriptExts = []string{".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".cjs", ".ts", ".rb", ".pl", ".ps1", ".cmd", ".bat"}

// placeholders are the path variables Claude fills into hook commands.
//
//nolint:gochecknoglobals // fixed list, read only
var placeholders = []string{"${CLAUDE_PROJECT_DIR}", "$CLAUDE_PROJECT_DIR", "${CLAUDE_PLUGIN_ROOT}", "$CLAUDE_PLUGIN_ROOT"}

// scriptPath finds the script a command hook runs: the first word that
// uses a path placeholder or ends in a script extension. It resolves only
// the documented path placeholders, never any other variable, so the path
// is all jarx learns. "" means no script.
func scriptPath(c agent.Context, projectDir, pluginRoot string, h hookHandler) string {
	words := append(strings.Fields(h.Command), h.Args...)
	for _, w := range words {
		w = strings.Trim(w, `"'`)
		hasVar := slices.ContainsFunc(placeholders, func(p string) bool { return strings.Contains(w, p) })
		if !hasVar && !slices.Contains(scriptExts, strings.ToLower(filepath.Ext(w))) {
			continue
		}
		if pluginRoot == "" && strings.Contains(w, "CLAUDE_PLUGIN_ROOT") {
			continue // only plugin hooks have a plugin root
		}
		w = strings.NewReplacer(
			"${CLAUDE_PROJECT_DIR}", projectDir, "$CLAUDE_PROJECT_DIR", projectDir,
			"${CLAUDE_PLUGIN_ROOT}", pluginRoot, "$CLAUDE_PLUGIN_ROOT", pluginRoot,
		).Replace(w)
		w = strings.ReplaceAll(w, `"`, "")
		if strings.Contains(w, "$") {
			continue // another variable, which jarx never fills in
		}
		return resolveImport(c.Env, filepath.Join(projectDir, "x"), w)
	}
	return ""
}
