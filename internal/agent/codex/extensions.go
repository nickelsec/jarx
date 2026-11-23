package codex

import (
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"

	"github.com/nickelsec/jarx/internal/agent"
	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/platform"
)

// Skills, from developers.openai.com/codex/skills: <name>/SKILL.md folders
// in .agents/skills of every dir from the working dir up to the repo root,
// $HOME/.agents/skills, /etc/codex/skills, and the bundled ones. Same-named
// skills don't merge: both load. [[skills.config]] entries in the user's
// config.toml turn skills off by path or name, and the last match wins.
//
// Hooks, from developers.openai.com/codex/hooks: hooks.json in the system
// dir, $CODEX_HOME and each trusted project's .codex, plus inline [hooks] in
// the config.toml beside them and in requirements.toml. Matching hooks from
// every source combine. Codex runs a non-managed hook only after the user
// reviews and trusts that exact definition, which Codex records where jarx
// can't see. [features].hooks = false turns hooks off, and requirements can
// pin it or allow managed hooks only.
//
// jarx only reads all of this. It never runs a hook or a skill.

// adminSkillsDir is /etc/codex/skills. The docs give no Windows path.
func adminSkillsDir(env platform.Env) string {
	roots, ok := env.SystemRoots()
	if !ok || env.GOOS == goosWindows || roots.Etc == "" {
		return ""
	}
	return filepath.Join(roots.Etc, "codex", "skills")
}

// systemHooksFile is the system hooks.json.
func systemHooksFile(env platform.Env) string {
	roots, ok := env.SystemRoots()
	if !ok {
		return ""
	}
	if env.GOOS == goosWindows {
		if roots.ProgramData == "" {
			return ""
		}
		return filepath.Join(roots.ProgramData, "OpenAI", "Codex", "hooks.json")
	}
	if roots.Etc == "" {
		return ""
	}
	return filepath.Join(roots.Etc, "codex", "hooks.json")
}

// The adapter reads extensions.
var _ agent.ExtensionReader = Adapter{}

// Extensions lists the skills and hooks Codex would use in each ok project.
func (Adapter) Extensions(c agent.Context, projects []model.Project) []finding.Finding {
	s := &settings{c: c}
	s.load()
	var findings []finding.Finding
	for i := range projects {
		p := &projects[i]
		if p.Status != model.ProjectOK {
			continue
		}
		v := s.forProject(*p)
		e := &extensions{v: v, project: p}
		e.skills()
		e.hooks()
		e.servers()
		findings = append(findings, e.findings...)
	}
	return findings // parse problems come from Settings
}

type extensions struct {
	v        *view
	project  *model.Project
	findings []finding.Finding
}

func (e *extensions) skills() {
	env := e.v.s.c.Env
	for _, d := range e.v.s.projectDirs(e.project.Path.Raw()) {
		e.skillDir(filepath.Join(d, ".agents", "skills"), model.ScopeProject)
	}
	e.skillDir(filepath.Join(env.Home, ".agents", "skills"), model.ScopeUser)
	if dir := adminSkillsDir(env); dir != "" {
		e.skillDir(dir, model.ScopeSystem)
	}
}

// skillDir adds <dir>/<name>/SKILL.md for every skill folder, following a
// symlinked folder to its target.
func (e *extensions) skillDir(dir string, scope model.Scope) {
	c := e.v.s.c
	entries, err := c.Files.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		sub := filepath.Join(dir, entry.Name())
		if info, err := c.Files.Stat(sub); err != nil || !info.IsDir() {
			continue
		}
		file := filepath.Join(sub, "SKILL.md")
		data, status := (&chainReader{v: e.v}).read(file)
		if status == model.ReadMissing {
			continue
		}
		name := entry.Name()
		s := model.Skill{
			Kind: model.SkillSkill, Path: model.NewPath(c.Scrub, file), Load: model.LoadInvoked, Read: status,
			Origin: model.Origin{Agent: model.AgentCodex, File: model.NewPath(c.Scrub, file), Scope: scope, InEffect: true},
		}
		if status == model.ReadOK {
			s.Text = e.v.s.text(string(data))
			if fm, _, ok := agent.Frontmatter(string(data)); ok && fm["name"] != "" {
				name = fm["name"]
			}
		}
		s.Name = e.v.s.text(name)
		if off, why := e.skillOff(file, name); off {
			s.Origin.InEffect, s.Origin.Why = false, e.v.s.text(why)
		}
		e.project.Skills = append(e.project.Skills, s)
	}
}

// skillOff applies the user's [[skills.config]] entries in order; the last
// one that matches the skill's path or name wins.
func (e *extensions) skillOff(file, name string) (bool, string) {
	if e.v.s.user == nil {
		return false, ""
	}
	skills, _ := e.v.s.user.raw["skills"].(map[string]any)
	off, why := false, ""
	for _, entry := range tables(skills["config"]) {
		enabled, ok := entry["enabled"].(bool)
		if !ok {
			continue
		}
		path, _ := entry["path"].(string)
		match, _ := entry["name"].(string)
		if (path != "" && e.v.s.c.Env.MapPath(path) == file) || (match != "" && match == name) {
			off, why = !enabled, "turned off by a [[skills.config]] entry in the user config.toml"
		}
	}
	return off, why
}

// tables reads an array of TOML tables, however the decoder typed it.
func tables(v any) []map[string]any {
	switch v := v.(type) {
	case []map[string]any:
		return v
	case []any:
		var out []map[string]any
		for _, x := range v {
			if m, ok := x.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	}
	return nil
}

// hookSource is one place hooks come from.
type hookSource struct {
	file    string
	hooks   any // the hooks table or object, as decoded
	origin  model.Origin
	managed bool
}

func (e *extensions) hooks() {
	s := e.v.s
	var sources []hookSource
	if f := systemHooksFile(s.c.Env); f != "" {
		sources = append(sources, e.jsonHooks(f, model.ScopeSystem, true, "")...)
	}
	if s.system != nil {
		sources = append(sources, hookSource{s.system.origin.File.Raw(), s.system.raw["hooks"], s.system.origin, true})
	}
	if s.req != nil {
		sources = append(sources, hookSource{s.req.origin.File.Raw(), s.req.raw["hooks"], s.req.origin, true})
	}
	sources = append(sources, e.jsonHooks(filepath.Join(codexHome(s.c.Env), "hooks.json"), model.ScopeUser, false, "")...)
	if s.user != nil {
		sources = append(sources, hookSource{s.user.origin.File.Raw(), s.user.raw["hooks"], s.user.origin, false})
	}
	why := projectTrustWhy(*e.project)
	dirs := s.projectDirs(e.project.Path.Raw())
	slices.Reverse(dirs)
	for _, d := range dirs {
		sources = append(sources, e.jsonHooks(filepath.Join(d, ".codex", "hooks.json"), model.ScopeProject, false, why)...)
	}
	for _, l := range e.v.layers {
		if l.origin.Scope == model.ScopeProject {
			sources = append(sources, hookSource{l.origin.File.Raw(), l.raw["hooks"], l.origin, false})
		}
	}
	for _, src := range sources {
		e.addHooks(src)
	}
}

// jsonHooks reads a hooks.json file. why, when set, is why its hooks don't
// load (an untrusted project).
func (e *extensions) jsonHooks(file string, scope model.Scope, managed bool, why string) []hookSource {
	data, status := (&chainReader{v: e.v}).read(file)
	if status != model.ReadOK {
		return nil
	}
	var doc struct {
		Hooks any `json:"hooks"`
	}
	if json.Unmarshal(data, &doc) != nil {
		return nil
	}
	o := model.Origin{Agent: model.AgentCodex, File: model.NewPath(e.v.s.c.Scrub, file), Scope: scope, InEffect: true}
	if why != "" {
		o.InEffect, o.Why = false, e.v.s.text(why)
	}
	return []hookSource{{file, doc.Hooks, o, managed}}
}

// rawHandler is a hook handler as either format decodes it.
type rawHandler struct {
	Type    string `json:"type"`
	Command string `json:"command"`
}

// addHooks adds every handler in one source, through a JSON round trip so
// hooks.json and inline TOML read the same way.
func (e *extensions) addHooks(src hookSource) {
	events, _ := src.hooks.(map[string]any)
	for _, event := range sortedKeys(events) {
		data, err := json.Marshal(events[event])
		if err != nil {
			continue
		}
		var groups []struct {
			Matcher string       `json:"matcher"`
			Hooks   []rawHandler `json:"hooks"`
		}
		if json.Unmarshal(data, &groups) != nil {
			continue // not a list of matcher groups, like managed_dir
		}
		for _, g := range groups {
			for _, h := range g.Hooks {
				e.project.Hooks = append(e.project.Hooks, e.hook(src, event, g.Matcher, h))
			}
		}
	}
}

func (e *extensions) hook(src hookSource, event, matcher string, h rawHandler) model.Hook {
	t := e.v.s.text
	o := src.origin
	if why := e.hooksOffWhy(src.managed); o.InEffect && why != "" {
		o.InEffect, o.Why = false, t(why)
	}
	out := model.Hook{Event: t(event), Matcher: t(matcher), Type: t(h.Type), Run: t(h.Command), Origin: o}
	if !src.managed {
		out.Note = t("Codex runs it only after you review and trust it in /hooks; jarx can't see whether you did")
	}
	if script := e.scriptPath(h.Command); script != "" {
		out.Script = model.NewPath(e.v.s.c.Scrub, script)
		var data []byte
		data, out.ScriptRead = (&chainReader{v: e.v}).read(script)
		if out.ScriptRead == model.ReadOK {
			out.ScriptText = t(string(data))
		}
	}
	return out
}

// hooksOffWhy says why hooks are off, or "".
func (e *extensions) hooksOffWhy(managed bool) string {
	if why, decided := e.requirementsHooks(managed); decided {
		return why
	}
	return e.configHooks()
}

// requirementsHooks says what requirements.toml decides about a hook:
// managed hooks only, or [features].hooks pinned on or off. decided is false
// when requirements leave it to config.
func (e *extensions) requirementsHooks(managed bool) (string, bool) {
	req := e.v.s.req
	if req == nil {
		return "", false
	}
	if only, _ := req.raw["allow_managed_hooks_only"].(bool); only && !managed {
		return "requirements allow managed hooks only", true
	}
	f, _ := req.raw["features"].(map[string]any)
	on, ok := f["hooks"].(bool)
	switch {
	case !ok:
		return "", false
	case !on:
		return "requirements turn hooks off", true
	default:
		return "", true // requirements pin hooks on, whatever config says
	}
}

// configHooks says why config turns hooks off, or "": the highest loaded
// layer that sets [features].hooks (or its old name, codex_hooks) decides.
func (e *extensions) configHooks() string {
	for _, l := range e.v.loaded() {
		f, _ := l.raw["features"].(map[string]any)
		for _, key := range []string{"hooks", "codex_hooks"} {
			if on, ok := f[key].(bool); ok {
				if !on {
					return "[features].hooks is off in " + string(l.origin.Scope) + " config"
				}
				return ""
			}
		}
	}
	return ""
}

// scriptPath finds a script file a hook command runs: the first word with a
// script extension. ~ is the home dir, a relative path is from the project.
// Variables and $(...) are never filled in.
func (e *extensions) scriptPath(command string) string {
	for w := range strings.FieldsSeq(command) {
		w = strings.Trim(w, `"'`)
		if strings.Contains(w, "$") || !slices.Contains(scriptExts, strings.ToLower(filepath.Ext(w))) {
			continue
		}
		env := e.v.s.c.Env
		switch {
		case strings.HasPrefix(w, "~/"):
			return filepath.Join(env.Home, filepath.FromSlash(w[2:]))
		case filepath.IsAbs(w), strings.HasPrefix(w, "/"):
			return env.MapPath(w)
		default:
			return filepath.Join(e.project.Path.Raw(), filepath.FromSlash(w))
		}
	}
	return ""
}

// scriptExts are file types a hook command runs as a script.
//
//nolint:gochecknoglobals // fixed list, read only
var scriptExts = []string{".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".cjs", ".ts", ".rb", ".pl", ".ps1", ".cmd", ".bat"}
