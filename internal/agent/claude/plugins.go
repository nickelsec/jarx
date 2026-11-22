package claude

import (
	"encoding/json"
	"errors"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"

	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/platform"
)

// Plugins, from code.claude.com/docs/en/plugins/loading and
// code.claude.com/docs/en/plugins-reference:
//
//   - enabledPlugins entries merge per plugin id across settings: the
//     highest source that mentions an id decides it, and managed true or
//     false can't be overridden. A plugin the repository enables waits for
//     the folder to be trusted.
//   - Plugin files live under ~/.claude/plugins (or
//     CLAUDE_CODE_PLUGIN_CACHE_DIR). installed_plugins.json records each
//     install's scope, installPath and version. The docs name those fields
//     but not the file's shape, so jarx reads it as an observed format and
//     treats anything else as unknown.
//   - A plugin's components are its skills/, commands/, agents/ and
//     hooks/hooks.json, plus what .claude-plugin/plugin.json declares. A
//     component path that resolves outside the plugin dir doesn't load.
//   - Plugin subagents ignore hooks, mcpServers and permissionMode.
//
// jarx never installs, updates or fetches a plugin or a marketplace, and
// never runs anything a plugin ships.

// install is what jarx keeps from one install record.
type install struct {
	path, version string
}

// pluginsRoot is where Claude keeps plugin files.
func pluginsRoot(env platform.Env, cfg string) string {
	if dir, ok := env.Lookup("CLAUDE_CODE_PLUGIN_CACHE_DIR"); ok && dir != "" {
		return env.MapPath(dir)
	}
	return filepath.Join(cfg, "plugins")
}

// readInstalls reads installed_plugins.json (observed, not documented). ok
// is false when the file is there but jarx can't make sense of it; a
// missing file means nothing is installed.
func readInstalls(e *extReader, root string) (map[string]install, bool) {
	data, err := e.c.Files.ReadFile(filepath.Join(root, "installed_plugins.json"))
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]install{}, true
	}
	if err != nil {
		return nil, false
	}
	var top map[string]json.RawMessage
	if json.Unmarshal(data, &top) != nil {
		return nil, false
	}
	entries := top
	if raw, ok := top["plugins"]; ok {
		if json.Unmarshal(raw, &entries) != nil {
			return nil, false
		}
	}
	out := map[string]install{}
	for id, raw := range entries {
		if !strings.Contains(id, "@") {
			continue // a version number or other bookkeeping
		}
		if in, ok := e.pickInstall(raw); ok {
			out[id] = in
		}
	}
	return out, true
}

type installRecord struct {
	Scope       string `json:"scope"`
	InstallPath string `json:"installPath"`
	Version     string `json:"version"`
	ProjectPath string `json:"projectPath"`
}

// pickInstall takes the record for this project when there is one, else a
// user install, else the first.
func (e *extReader) pickInstall(raw json.RawMessage) (install, bool) {
	var recs []installRecord
	if json.Unmarshal(raw, &recs) != nil {
		var one installRecord
		if json.Unmarshal(raw, &one) != nil {
			return install{}, false
		}
		recs = []installRecord{one}
	}
	best, bestScore := -1, 0
	for i, r := range recs {
		if score := e.installScore(r); score > bestScore {
			best, bestScore = i, score
		}
	}
	if best < 0 {
		return install{}, false
	}
	return install{path: e.c.Env.MapPath(recs[best].InstallPath), version: recs[best].Version}, true
}

// Install record scores, best last. 0 means unusable.
const (
	scoreAny = iota + 1
	scoreUser
	scoreThisProject
)

// installScore ranks an install record for this project.
func (e *extReader) installScore(r installRecord) int {
	switch {
	case r.InstallPath == "":
		return 0
	case r.ProjectPath != "" && e.c.Env.MapPath(r.ProjectPath) == e.project.Path.Raw():
		return scoreThisProject
	case r.Scope == "user":
		return scoreUser
	default:
		return scoreAny
	}
}

// plugins adds every plugin the settings mention and loads the components
// of the ones Claude would load.
func (e *extReader) plugins(cfg string) {
	installs, known := readInstalls(e, pluginsRoot(e.c.Env, cfg))
	for _, id := range e.pluginIDs() {
		pl := e.enabled(id)
		why := e.pluginOffWhy(pl)
		in, installed := installs[id]
		switch {
		case !known:
			why = firstWhy(why, "install state unknown: jarx couldn't read installed_plugins.json (an observed format)")
		case installed:
			pl.Path, pl.Version, pl.Origin.Observed = model.NewPath(e.c.Scrub, in.path), e.text(in.version), true
		default:
			why = firstWhy(why, "enabled in settings but not installed here")
		}
		if why != "" && pl.Origin.InEffect {
			pl.Origin.InEffect, pl.Origin.Why = false, e.text(why)
		}
		e.project.Plugins = append(e.project.Plugins, pl)
		if pl.Origin.InEffect {
			e.loadPlugin(id, in.path)
		}
	}
}

func firstWhy(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// pluginIDs is every id any in-effect layer's enabledPlugins mentions.
func (e *extReader) pluginIDs() []string {
	seen := map[string]bool{}
	for _, l := range e.layers {
		if l == nil || !l.origin.InEffect {
			continue
		}
		for id := range l.enabledPlugins {
			seen[id] = true
		}
	}
	return sortedKeys(seen)
}

// enabled builds a plugin's enabled setting: one layer per source that
// mentions it, the highest in effect.
func (e *extReader) enabled(id string) model.Plugin {
	pl := model.Plugin{ID: e.text(id)}
	var win *layer
	for _, l := range e.layers {
		if l == nil || !l.origin.InEffect {
			continue
		}
		v, ok := l.enabledPlugins[id]
		if !ok {
			continue
		}
		o := l.origin
		if win != nil {
			o.InEffect, o.Why = false, e.text("overridden by "+string(win.origin.Scope)+" settings")
		} else {
			win = l
		}
		pl.Enabled.Layers = append(pl.Enabled.Layers, model.Layer[bool]{Value: v, Origin: o})
	}
	if eff, ok := pl.Enabled.Effective(); ok {
		pl.Origin = eff.Origin
	}
	return pl
}

// pluginOffWhy says why an enabled setting doesn't load the plugin, or "".
func (e *extReader) pluginOffWhy(pl model.Plugin) string {
	eff, ok := pl.Enabled.Effective()
	switch {
	case !ok:
		return "no settings file turns it on"
	case !eff.Value:
		return "turned off in " + string(eff.Origin.Scope) + " settings"
	case eff.Origin.Scope == model.ScopeProject:
		if waits := trustWhy(*e.project); waits != "" {
			return "the repository enables it, and it " + waits
		}
	}
	return ""
}

// managedEnables says whether managed settings force-enable a plugin, which
// keeps its hooks under allowManagedHooksOnly.
func (e *extReader) managedEnables(id string) bool {
	for _, l := range e.managedLayers() {
		if l.origin.InEffect && l.enabledPlugins[id] {
			return true
		}
	}
	return false
}

// manifest is the part of plugin.json jarx reads.
type manifest struct {
	Name     string          `json:"name"`
	Skills   json.RawMessage `json:"skills"`
	Commands json.RawMessage `json:"commands"`
	Agents   json.RawMessage `json:"agents"`
	Hooks    json.RawMessage `json:"hooks"`
}

// paths reads a component key that's a path or a list of paths. Other
// shapes (like an inline commands map) give no paths.
func paths(raw json.RawMessage) []string {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return []string{one}
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		return many
	}
	return nil
}

// inRoot joins a component path onto the plugin root, or returns "" when it
// would leave the root.
func inRoot(root, p string) string {
	if filepath.IsAbs(p) || strings.HasPrefix(p, `\`) {
		return ""
	}
	rel := filepath.Clean(filepath.FromSlash(p))
	if rel != "." && !filepath.IsLocal(rel) {
		return ""
	}
	return filepath.Join(root, rel)
}

// loadPlugin adds a loaded plugin's skills, commands, subagents and hooks.
func (e *extReader) loadPlugin(id, root string) {
	var m manifest
	if status, data := (&reader{c: e.c}).read(filepath.Join(root, ".claude-plugin", "plugin.json")); status == model.ReadOK {
		_ = json.Unmarshal(data, &m)
	}
	name := m.Name
	if name == "" {
		name, _, _ = strings.Cut(id, "@")
	}
	from := len(e.project.Skills)
	for _, dir := range e.componentPaths(root, "skills", m.Skills) {
		e.skillDir(dir, model.ScopePlugin)
	}
	for _, p := range e.componentPaths(root, "commands", m.Commands) {
		e.commandDir(p, model.ScopePlugin)
	}
	for _, p := range e.componentPaths(root, "agents", m.Agents) {
		e.agentDir(p, model.ScopePlugin)
	}
	for i := from; i < len(e.project.Skills); i++ {
		s := &e.project.Skills[i]
		s.Plugin, s.Name = e.text(id), e.text(name+":"+s.Name.String())
		if s.Kind == model.SkillSubagent {
			s.Mode, s.Hooks = e.text(""), e.text("") // ignored for plugin subagents
			s.Origin.InEffect, s.Origin.Why = true, e.text("")
		}
		e.skillFindings(*s)
	}
	e.pluginHooks(id, root, m.Hooks)
}

// componentPaths is a component's default dir plus what the manifest
// declares, inside the plugin root only.
func (e *extReader) componentPaths(root, def string, declared json.RawMessage) []string {
	out := []string{filepath.Join(root, def)}
	for _, p := range paths(declared) {
		if full := inRoot(root, p); full != "" && !slices.Contains(out, full) {
			out = append(out, full)
		}
	}
	return out
}

// pluginHooks adds the hooks from hooks/hooks.json and the manifest's hooks
// files.
func (e *extReader) pluginHooks(id, root string, declared json.RawMessage) {
	files := []string{filepath.Join(root, "hooks", "hooks.json")}
	for _, p := range paths(declared) {
		if full := inRoot(root, p); full != "" && !slices.Contains(files, full) {
			files = append(files, full)
		}
	}
	why := e.hooksOffWhy(model.ScopePlugin)
	if strings.HasPrefix(why, "allowManagedHooksOnly") && e.managedEnables(id) {
		why = "" // managed settings force-enable this plugin, which keeps its hooks
	}
	for _, f := range files {
		o := model.Origin{Agent: model.AgentClaude, File: model.NewPath(e.c.Scrub, f), Scope: model.ScopePlugin, InEffect: true}
		if why != "" {
			o.InEffect, o.Why = false, e.text(why)
		}
		for _, h := range e.hooksFile(f, o) {
			e.project.Hooks = append(e.project.Hooks, e.hook(h, o, root))
		}
	}
}

// hooksFile reads a plugin hooks file: a hooks object under a top-level
// "hooks" key.
func (e *extReader) hooksFile(f string, o model.Origin) []rawHook {
	status, data := (&reader{c: e.c}).read(f)
	if status != model.ReadOK {
		return nil
	}
	var wrapper struct {
		Hooks json.RawMessage `json:"hooks"`
	}
	if json.Unmarshal(data, &wrapper) != nil || wrapper.Hooks == nil {
		return nil
	}
	lr := &layerReader{c: e.c, l: &layer{origin: o}}
	return lr.parseHooks(wrapper.Hooks)
}
