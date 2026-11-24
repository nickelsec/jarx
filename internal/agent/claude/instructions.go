package claude

import (
	"encoding/json"
	"errors"
	"io/fs"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/nickelsec/jarx/internal/agent"
	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/fsys"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/platform"
	"github.com/nickelsec/jarx/internal/redact"
)

// Instruction files, from code.claude.com/docs/en/memory and
// code.claude.com/docs/en/output-styles:
//
//   - CLAUDE.md, .claude/CLAUDE.md and CLAUDE.local.md load at launch from
//     the working dir and every dir above it, root first, local last in each
//     dir. In subfolders they load on demand.
//   - AGENTS.md and .claude/AGENTS.md load instead, by default only when no
//     CLAUDE.md, .claude/CLAUDE.md or CLAUDE.local.md is in the working dir
//     or above. The AGENTS.md plugin's instructionFiles option changes that.
//   - .claude/rules/**/*.md load at launch, or with a paths frontmatter only
//     when matching files are read. ~/.claude/rules/ is the user's set.
//   - @path imports load with their file, relative to it, up to four hops.
//     An import from a project file that resolves outside the working dir
//     waits for the user to approve it; one from a user file doesn't.
//   - Auto memory's MEMORY.md loads at launch, its topic files on demand.
//   - Output styles load when selected with outputStyle.
//
// Every read goes through fsys, which refuses credential files (even behind
// a symlink), network paths, FIFOs and devices, and anything over 10 MiB.

// maxImportDepth is Claude's import limit: four hops.
const maxImportDepth = 4

// The instruction file names Claude looks for.
const (
	nameClaudeMD = "CLAUDE.md"
	nameLocalMD  = "CLAUDE.local.md"
	nameAgentsMD = "AGENTS.md"
)

// Values of the AGENTS.md plugin's instructionFiles option.
const (
	filesClaudeOrAgents  = "claude-md-or-agents-md" // the default
	filesClaudeAndAgents = "claude-md-and-agents-md"
	filesClaudeOnly      = "claude-md"
	filesManagedOnly     = "managed-only"
)

// ImportsCredential is the finding for an instruction source that is a
// credential file. Claude loads it into context, so the agent sees the
// secret. jarx itself never reads it.
func ImportsCredential() finding.Rule {
	return finding.Rule{
		ID:       "JARX-CLAUDE-002",
		Severity: finding.High,
		Title:    "an @import pulls in a credential file",
		Detail:   "an instruction file pulls a credential file into Claude's context",
		Fix:      "remove the @import or symlink; Claude would load the secret as instructions",
	}
}

// The adapter reads instructions.
var _ agent.InstructionReader = Adapter{}

// Instructions lists what Claude reads as instructions for each ok project,
// and the memory it can't tie to one project.
func (Adapter) Instructions(c agent.Context, projects []model.Project) ([]model.Instruction, []finding.Finding) {
	all := loadSettings(c)
	cfg := claudeDir(c.Env)
	g := &reader{c: c, seen: map[string]bool{}}
	g.globalMemory(all.shared(), cfg)
	findings := g.findings

	for i := range projects {
		p := &projects[i]
		if p.Status != model.ProjectOK {
			continue
		}
		layers, _, _ := all.forProject(c, *p) // their findings come from Settings
		r := &reader{c: c, project: p, layers: layers, seen: map[string]bool{}, mode: instructionFilesMode(layers)}
		r.managed(all.managed)
		r.user(cfg)
		r.tree(cfg)
		r.projectRules()
		r.subdirs()
		r.outputStyles(cfg)
		r.memory(cfg)
		r.agentMemory()
		p.Instructions = r.out
		findings = append(findings, r.findings...)
	}
	return g.out, findings
}

// claudeDir is ~/.claude, or CLAUDE_CONFIG_DIR.
func claudeDir(env platform.Env) string {
	if dir, ok := env.Lookup("CLAUDE_CONFIG_DIR"); ok && dir != "" {
		return env.MapPath(dir)
	}
	return filepath.Join(env.Home, ".claude")
}

func instructionFilesMode(layers []*layer) string {
	if mode, _ := effective(layers, func(l *layer) string { return l.instructionFiles }); mode != "" {
		return mode
	}
	return filesClaudeOrAgents
}

// reader collects one project's instructions.
type reader struct {
	c        agent.Context
	project  *model.Project // nil for the global list
	layers   []*layer
	mode     string
	seen     map[string]bool
	out      []model.Instruction
	findings []finding.Finding
}

// instrSource is one instruction to add.
type instrSource struct {
	kind  model.InstructionKind
	path  string
	load  model.LoadWhen
	scope model.Scope
	why   string // why it's not in effect, "" when it is
	// listMissing lists the file even when it doesn't exist (imports).
	listMissing bool
	// imports says whether to follow its @imports.
	imports bool
}

func (r *reader) text(s string) redact.Text {
	t, _ := r.c.Scrub.Scrub(s)
	return t
}

// add reads one source and appends it, then follows its imports.
func (r *reader) add(s instrSource) {
	r.addImported(s, model.Instruction{}, 0)
}

func (r *reader) addImported(s instrSource, parent model.Instruction, depth int) {
	key := filepath.Clean(s.path)
	if r.seen[key] {
		return
	}
	in := model.Instruction{
		Kind: s.kind, Path: model.NewPath(r.c.Scrub, s.path), Load: s.load, Depth: depth,
		Origin: model.Origin{Agent: model.AgentClaude, File: model.NewPath(r.c.Scrub, s.path), Scope: s.scope, InEffect: true},
	}
	if depth > 0 {
		in.ImportedBy = parent.Path
	}
	var data []byte
	in.Read, data, s.why = r.load(s, depth)
	if in.Read == model.ReadMissing && !s.listMissing {
		return
	}
	r.seen[key] = true
	if in.Read == model.ReadCredential {
		r.credential(in, parent)
	}
	if s.why != "" {
		in.Origin.InEffect, in.Origin.Why = false, r.text(s.why)
	}
	if in.Read != model.ReadOK {
		r.out = append(r.out, in)
		return
	}
	in.Text = r.text(string(data))
	r.out = append(r.out, in)
	if s.imports {
		r.followImports(in, s, string(data), depth)
	}
}

// load reads a source unless it's past the import limit, and returns why
// it's not in effect: the source's own reason, or one from the read.
func (r *reader) load(s instrSource, depth int) (model.ReadStatus, []byte, string) {
	if depth > maxImportDepth {
		return model.ReadNotFollowed, nil, "past Claude's limit of four import hops"
	}
	status, data := r.read(s.path)
	if s.why == "" {
		s.why = unloadable(status)
	}
	return status, data, s.why
}

// unloadable says why Claude can't load a file jarx couldn't read, or "" when
// Claude still loads it. A credential file still loads: only jarx refuses
// it. Outside the fake home and other read errors say nothing about Claude.
func unloadable(s model.ReadStatus) string {
	switch s {
	case model.ReadMissing:
		return "the file doesn't exist"
	case model.ReadNetwork:
		return "Claude doesn't follow network paths"
	case model.ReadNotRegular:
		return "it isn't a plain file"
	case model.ReadTooLarge:
		return "Claude skips instruction files over 4 MiB"
	case model.ReadOK, model.ReadCredential, model.ReadOutsideHome, model.ReadFailed, model.ReadNotFollowed, model.ReadExistsOnly:
		return ""
	default:
		return ""
	}
}

// read reads path through fsys and says how that went.
func (r *reader) read(path string) (model.ReadStatus, []byte) {
	data, err := r.c.Files.ReadFile(path)
	switch {
	case err == nil:
		return model.ReadOK, data
	case errors.Is(err, fs.ErrNotExist):
		return model.ReadMissing, nil
	case errors.Is(err, fsys.ErrCredential):
		return model.ReadCredential, nil
	case errors.Is(err, fsys.ErrNetworkPath):
		return model.ReadNetwork, nil
	case errors.Is(err, fsys.ErrOutsideHome):
		return model.ReadOutsideHome, nil
	case errors.Is(err, fsys.ErrNotRegular):
		return model.ReadNotRegular, nil
	case errors.Is(err, fsys.ErrTooLarge):
		return model.ReadTooLarge, nil // fsys records it, and it becomes a finding
	default:
		return model.ReadFailed, nil
	}
}

func (r *reader) credential(in model.Instruction, parent model.Instruction) {
	what := "an instruction source is a credential file"
	if !parent.Path.IsZero() {
		what = "an @import in " + parent.Path.Text().String() + " points at a credential file"
	}
	r.findings = append(r.findings, ImportsCredential().New(in.Origin, r.text(what+"; jarx didn't read it")))
}

// followImports adds the @imports in one file.
func (r *reader) followImports(from model.Instruction, s instrSource, text string, depth int) {
	for _, im := range agent.Imports(text) {
		target := resolveImport(r.c.Env, from.Path.Raw(), im.Path)
		child := instrSource{kind: model.InstructionImport, path: target, load: s.load, scope: s.scope, listMissing: true, imports: true}
		switch {
		case !from.Origin.InEffect:
			child.why = "the file that imports it isn't loaded"
		case r.external(s.scope, target):
			child.why = "external import: Claude asks you to approve imports from outside the project first, and jarx can't see whether you did"
		}
		r.addImported(child, from, depth+1)
	}
}

// external says whether an import from a project-level file resolves
// outside the project dir.
func (r *reader) external(scope model.Scope, target string) bool {
	if r.project == nil || (scope != model.ScopeProject && scope != model.ScopeLocal) {
		return false
	}
	rel, err := filepath.Rel(r.project.Path.Raw(), target)
	return err != nil || !filepath.IsLocal(rel)
}

// resolveImport turns an @path into a path to read: ~/ is the home dir, an
// absolute path is read as a record path (inside the fake home under
// --home), and anything else is relative to the importing file.
func resolveImport(env platform.Env, from, raw string) string {
	switch {
	case raw == "~":
		return env.Home
	case strings.HasPrefix(raw, "~/"), strings.HasPrefix(raw, `~\`):
		return filepath.Join(env.Home, filepath.FromSlash(raw[2:]))
	case filepath.IsAbs(raw), strings.HasPrefix(raw, "/"), strings.HasPrefix(raw, `\`):
		return env.MapPath(raw)
	default:
		return filepath.Join(filepath.Dir(from), filepath.FromSlash(raw))
	}
}

// managed adds the managed CLAUDE.md and any managed claudeMd setting.
func (r *reader) managed(m managed) {
	if dir := managedDir(r.c.Env); dir != "" {
		r.add(instrSource{kind: model.InstructionFile, path: filepath.Join(dir, nameClaudeMD), load: model.LoadLaunch, scope: model.ScopeManaged, imports: true})
	}
	for _, l := range m.layers {
		if l.claudeMd == nil {
			continue
		}
		in := model.Instruction{Kind: model.InstructionSetting, Path: l.origin.File, Load: model.LoadLaunch, Read: model.ReadOK, Text: *l.claudeMd, Origin: l.origin}
		r.out = append(r.out, in)
	}
}

// launchWhy is why a launch-time file is left out under the current
// instructionFiles mode, or "".
func (r *reader) launchWhy() string {
	if r.mode == filesManagedOnly {
		return "instructionFiles is managed-only, so Claude loads only managed instructions at launch"
	}
	return ""
}

// user adds ~/.claude/CLAUDE.md and the user's rules.
func (r *reader) user(cfg string) {
	r.add(instrSource{kind: model.InstructionFile, path: filepath.Join(cfg, nameClaudeMD), load: model.LoadLaunch, scope: model.ScopeUser, why: r.launchWhy(), imports: true})
	r.rules(filepath.Join(cfg, "rules"), model.ScopeUser, model.LoadLaunch, r.launchWhy())
}

// tree adds the instruction files in the project dir and every dir above
// it, root first. Under --home it stops at the fake home. When the home dir
// is one of them, its .claude/CLAUDE.md is the user's file, added by user
// and not counted as a project CLAUDE.md.
func (r *reader) tree(cfg string) {
	userFile := filepath.Join(cfg, nameClaudeMD)
	dirs := ancestors(r.c.Env, r.project.Path.Raw())
	claudeFound := false
	for _, d := range dirs {
		for _, name := range []string{nameClaudeMD, ".claude/" + nameClaudeMD, nameLocalMD} {
			p := filepath.Join(d, filepath.FromSlash(name))
			if p != userFile && r.exists(p) {
				claudeFound = true
			}
		}
	}
	agentsWhy := r.agentsWhy(claudeFound)
	for _, d := range dirs {
		r.add(instrSource{kind: model.InstructionFile, path: filepath.Join(d, nameClaudeMD), load: model.LoadLaunch, scope: model.ScopeProject, why: r.launchWhy(), imports: true})
		r.add(instrSource{kind: model.InstructionFile, path: filepath.Join(d, ".claude", nameClaudeMD), load: model.LoadLaunch, scope: model.ScopeProject, why: r.launchWhy(), imports: true})
		r.add(instrSource{kind: model.InstructionLocal, path: filepath.Join(d, nameLocalMD), load: model.LoadLaunch, scope: model.ScopeLocal, why: r.launchWhy(), imports: true})
		r.add(instrSource{kind: model.InstructionFile, path: filepath.Join(d, nameAgentsMD), load: model.LoadLaunch, scope: model.ScopeProject, why: agentsWhy, imports: true})
		r.add(instrSource{kind: model.InstructionFile, path: filepath.Join(d, ".claude", nameAgentsMD), load: model.LoadLaunch, scope: model.ScopeProject, why: agentsWhy, imports: true})
	}
}

// agentsWhy is why AGENTS.md files are left out, or "".
func (r *reader) agentsWhy(claudeFound bool) string {
	switch r.mode {
	case filesManagedOnly:
		return r.launchWhy()
	case filesClaudeOnly:
		return "instructionFiles is claude-md, so Claude reads CLAUDE.md files only"
	case filesClaudeAndAgents:
		return ""
	default:
		if claudeFound {
			return "Claude reads the CLAUDE.md files here instead (the default instructionFiles, claude-md-or-agents-md)"
		}
		return ""
	}
}

func (r *reader) exists(path string) bool {
	info, err := r.c.Files.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

// ancestors returns dir and every dir above it, root first. Under --home the
// fake home is the top.
func ancestors(env platform.Env, dir string) []string {
	var out []string
	for d := filepath.Clean(dir); ; d = filepath.Dir(d) {
		out = append(out, d)
		if env.Fake() && d == env.Home {
			break
		}
		if filepath.Dir(d) == d {
			break
		}
	}
	slices.Reverse(out)
	return out
}

// projectRules adds the project's .claude/rules.
func (r *reader) projectRules() {
	r.rules(filepath.Join(r.project.Path.Raw(), ".claude", "rules"), model.ScopeProject, model.LoadLaunch, r.launchWhy())
}

// rules adds every .md file under dir. A rule with paths frontmatter loads
// only when matching files are read.
func (r *reader) rules(dir string, scope model.Scope, load model.LoadWhen, why string) {
	var files []string
	_ = r.c.Files.Walk(dir, func(path string, _ fs.DirEntry) error {
		if strings.EqualFold(filepath.Ext(path), ".md") {
			files = append(files, path)
		}
		return nil
	})
	slices.Sort(files)
	for _, f := range files {
		l := load
		if fm, ok := r.frontmatter(f); ok {
			if _, has := fm["paths"]; has {
				l = model.LoadMatching
			}
		}
		r.add(instrSource{kind: model.InstructionRule, path: f, load: l, scope: scope, why: why, imports: true})
	}
}

// frontmatter reads a file's frontmatter keys. The file is read again when
// it's added; both reads go through fsys and its checks.
func (r *reader) frontmatter(path string) (map[string]string, bool) {
	status, data := r.read(path)
	if status != model.ReadOK {
		return nil, false
	}
	fm, _, ok := agent.Frontmatter(string(data))
	return fm, ok
}

// subdirs adds the instruction files in the project's subfolders, which load
// on demand: CLAUDE.md, CLAUDE.local.md, nested rules, and AGENTS.md where a
// subfolder has no CLAUDE files of its own.
func (r *reader) subdirs() {
	claudeIn := map[string]bool{}
	for _, f := range r.project.Files {
		rel := filepath.ToSlash(f.Raw())
		if base := path.Base(rel); base == nameClaudeMD || base == nameLocalMD {
			claudeIn[strings.TrimSuffix(path.Dir(rel), "/.claude")] = true
		}
	}
	for _, f := range r.project.Files {
		rel := filepath.ToSlash(f.Raw())
		if dir := path.Dir(rel); dir == "." || dir == ".claude" || strings.HasPrefix(rel, ".claude/") {
			continue // the project's own files, added at launch
		}
		if s, ok := r.subdirSource(rel, claudeIn); ok {
			r.add(s)
		}
	}
}

// subdirSource says what a file in a subfolder is, if it's an instruction.
func (r *reader) subdirSource(rel string, claudeIn map[string]bool) (instrSource, bool) {
	s := instrSource{
		kind: model.InstructionFile, path: filepath.Join(r.project.Path.Raw(), filepath.FromSlash(rel)),
		load: model.LoadOnDemand, scope: model.ScopeProject, imports: true,
	}
	switch base := path.Base(rel); {
	case base == nameClaudeMD:
	case base == nameLocalMD:
		s.kind, s.scope = model.InstructionLocal, model.ScopeLocal
	case base == nameAgentsMD && !claudeIn[path.Dir(rel)] && r.mode != filesClaudeOnly:
	case strings.Contains(rel, "/.claude/rules/") && strings.EqualFold(path.Ext(rel), ".md"):
		s.kind = model.InstructionRule
	default:
		return instrSource{}, false
	}
	return s, true
}

// outputStyles adds the user, project and managed output styles. The one
// named by the effective outputStyle is in effect.
func (r *reader) outputStyles(cfg string) {
	selected, _ := effective(r.layers, func(l *layer) *redact.Text { return l.outputStyle })
	dirs := []struct {
		dir   string
		scope model.Scope
	}{
		{filepath.Join(r.project.Path.Raw(), ".claude", "output-styles"), model.ScopeProject},
		{filepath.Join(cfg, "output-styles"), model.ScopeUser},
	}
	if m := managedDir(r.c.Env); m != "" {
		dirs = append(dirs, struct {
			dir   string
			scope model.Scope
		}{filepath.Join(m, ".claude", "output-styles"), model.ScopeManaged})
	}
	for _, d := range dirs {
		for _, f := range r.mdFiles(d.dir) {
			name := strings.TrimSuffix(filepath.Base(f), filepath.Ext(f))
			if fm, ok := r.frontmatter(f); ok && fm["name"] != "" {
				name = fm["name"]
			}
			why := "no output style is selected"
			if selected != nil {
				why = "not the selected output style"
				if r.text(name).String() == selected.String() {
					why = ""
				}
			}
			r.add(instrSource{kind: model.InstructionOutputStyle, path: f, load: model.LoadSelected, scope: d.scope, why: why})
		}
	}
}

// mdFiles lists the .md files directly in dir, in name order.
func (r *reader) mdFiles(dir string) []string {
	entries, err := r.c.Files.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.Type().IsRegular() && strings.EqualFold(filepath.Ext(e.Name()), ".md") {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	slices.Sort(out)
	return out
}

// memoryOff says why auto memory is off, or "".
func memoryOff(env platform.Env, layers []*layer) string {
	if v, ok := env.Lookup("CLAUDE_CODE_DISABLE_AUTO_MEMORY"); ok && v != "" && v != "0" && !strings.EqualFold(v, "false") {
		return "auto memory is off: CLAUDE_CODE_DISABLE_AUTO_MEMORY is set"
	}
	for _, l := range layers {
		if l != nil && l.origin.InEffect && l.memoryOn != nil {
			if !*l.memoryOn {
				return "auto memory is off: autoMemoryEnabled is false in " + string(l.origin.Scope) + " settings"
			}
			return ""
		}
	}
	return ""
}

// memory adds the project's auto memory when jarx knows its folder: an
// autoMemoryDirectory setting, or CLAUDE_CODE_PROJECT_DIR_NAME next to
// CLAUDE_CONFIG_DIR. Otherwise it's in the global list.
func (r *reader) memory(cfg string) {
	dir, l := effective(r.layers, func(l *layer) string { return l.memoryDir })
	scope := model.ScopeUser
	switch {
	case dir != "":
		dir = resolveImport(r.c.Env, cfg, dir)
		scope = l.origin.Scope
	case r.projectDirName() != "":
		dir = filepath.Join(cfg, "projects", r.projectDirName(), "memory")
	default:
		return
	}
	r.memoryDir(dir, scope, memoryOff(r.c.Env, r.layers))
}

func (r *reader) projectDirName() string {
	if _, ok := r.c.Env.Lookup("CLAUDE_CONFIG_DIR"); !ok {
		return ""
	}
	name, _ := r.c.Env.Lookup("CLAUDE_CODE_PROJECT_DIR_NAME")
	return name
}

// memoryDir adds one auto memory folder: MEMORY.md at launch, the topic
// files on demand.
func (r *reader) memoryDir(dir string, scope model.Scope, why string) {
	for _, f := range r.mdFiles(dir) {
		load := model.LoadOnDemand
		if filepath.Base(f) == "MEMORY.md" {
			load = model.LoadLaunch
		}
		r.add(instrSource{kind: model.InstructionMemory, path: f, load: load, scope: scope, why: why})
	}
}

// globalMemory adds the memory jarx can't tie to a project: every
// <config>/projects/*/memory folder (the docs don't say how the folder is
// named, so jarx doesn't guess which project it belongs to) and the user's
// agent memory.
func (r *reader) globalMemory(layers []*layer, cfg string) {
	entries, _ := r.c.Files.ReadDir(filepath.Join(cfg, "projects"))
	why := memoryOff(r.c.Env, layers)
	for _, e := range entries {
		if e.IsDir() {
			r.memoryDir(filepath.Join(cfg, "projects", e.Name(), "memory"), model.ScopeUser, why)
		}
	}
	r.agentMemoryIn(filepath.Join(cfg, "agent-memory"), model.ScopeUser)
}

// agentMemory adds the project's subagent memory.
func (r *reader) agentMemory() {
	base := filepath.Join(r.project.Path.Raw(), ".claude")
	r.agentMemoryIn(filepath.Join(base, "agent-memory"), model.ScopeProject)
	r.agentMemoryIn(filepath.Join(base, "agent-memory-local"), model.ScopeLocal)
}

// agentMemoryIn adds <dir>/<agent>/*.md: MEMORY.md when the subagent runs,
// the rest on demand.
func (r *reader) agentMemoryIn(dir string, scope model.Scope) {
	entries, _ := r.c.Files.ReadDir(dir)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		for _, f := range r.mdFiles(filepath.Join(dir, e.Name())) {
			load := model.LoadOnDemand
			if filepath.Base(f) == "MEMORY.md" {
				load = model.LoadSubagent
			}
			r.add(instrSource{kind: model.InstructionAgentMemory, path: f, load: load, scope: scope})
		}
	}
}

// instructionKey reads the settings keys the instruction reader needs.
func (r *layerReader) instructionKey(key string, raw json.RawMessage) {
	switch key {
	case "outputStyle":
		r.l.outputStyle = r.textValue(raw)
	case "claudeMd":
		r.l.claudeMd = r.textValue(raw)
	case "autoMemoryDirectory":
		_ = json.Unmarshal(raw, &r.l.memoryDir)
	case "autoMemoryEnabled":
		var v bool
		if json.Unmarshal(raw, &v) == nil {
			r.l.memoryOn = &v
		}
	case "pluginConfigs":
		r.l.instructionFiles = agentsPluginOption(raw)
	}
}

// textValue scrubs a JSON string, or returns nil when raw isn't a non-empty
// string.
func (r *layerReader) textValue(raw json.RawMessage) *redact.Text {
	var v string
	if json.Unmarshal(raw, &v) != nil || v == "" {
		return nil
	}
	t := r.scrub(v)
	return &t
}

// agentsPluginOption reads the AGENTS.md plugin's instructionFiles option,
// under its current id or the one before v2.1.285.
func agentsPluginOption(raw json.RawMessage) string {
	var cfgs map[string]struct {
		Options struct {
			InstructionFiles string `json:"instructionFiles"`
		} `json:"options"`
	}
	if json.Unmarshal(raw, &cfgs) != nil {
		return ""
	}
	for _, id := range []string{"cc-plugin-agents-md@builtin", "agents-md@builtin"} {
		if v := cfgs[id].Options.InstructionFiles; v != "" {
			return v
		}
	}
	return ""
}
