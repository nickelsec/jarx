package claude

import (
	"io/fs"
	"path/filepath"
	"slices"
	"strings"

	"github.com/nickelsec/jarx/internal/agent"
	"github.com/nickelsec/jarx/internal/model"
)

// Subagents, from code.claude.com/docs/en/sub-agents: Markdown files with
// frontmatter in the managed dir's .claude/agents, the project's
// .claude/agents and ~/.claude/agents, searched recursively. On a name
// clash, managed beats project beats user beats plugin. Claude skips a file
// with no name (it's documentation), a name with ':' or a leading '-' or
// over 256 characters, or no description.

// maxAgentName is the longest subagent name Claude accepts.
const maxAgentName = 256

// subagents adds every subagent and marks the ones a higher source shadows.
func (e *extReader) subagents(cfg string) {
	if m := managedDir(e.c.Env); m != "" {
		e.agentDir(filepath.Join(m, ".claude", "agents"), model.ScopeManaged)
	}
	e.agentDir(filepath.Join(e.project.Path.Raw(), ".claude", "agents"), model.ScopeProject)
	e.agentDir(filepath.Join(cfg, "agents"), model.ScopeUser)
	e.shadow(func(s model.Skill) bool { return s.Kind == model.SkillSubagent }, agentRank)
}

// agentDir adds every .md file under dir as a subagent.
func (e *extReader) agentDir(dir string, scope model.Scope) {
	var files []string
	_ = e.c.Files.Walk(dir, func(path string, _ fs.DirEntry) error {
		if strings.EqualFold(filepath.Ext(path), ".md") {
			files = append(files, path)
		}
		return nil
	})
	slices.Sort(files)
	for _, f := range files {
		e.addSubagent(f, scope, "")
	}
}

// addSubagent reads one subagent file and says whether Claude loads it.
// plugin is the plugin it comes from, or "".
func (e *extReader) addSubagent(file string, scope model.Scope, plugin string) {
	status, data := (&reader{c: e.c}).read(file)
	if status == model.ReadMissing {
		return
	}
	base := strings.TrimSuffix(filepath.Base(file), filepath.Ext(file))
	s := model.Skill{
		Kind: model.SkillSubagent, Path: model.NewPath(e.c.Scrub, file), Load: model.LoadInvoked, Read: status,
		Plugin: e.text(plugin),
		Origin: model.Origin{Agent: model.AgentClaude, File: model.NewPath(e.c.Scrub, file), Scope: scope, InEffect: true},
	}
	why := ""
	if status == model.ReadOK {
		text := string(data)
		e.fillSkill(&s, text, base, true)
		fm, _, _ := agent.Frontmatter(text)
		s.Mode = e.text(fm["permissionMode"])
		if plugin == "" {
			why = subagentSkipped(fm)
		}
	}
	if s.Name.IsZero() {
		s.Name = e.text(base)
	}
	if why != "" {
		s.Origin.InEffect, s.Origin.Why = false, e.text(why)
	}
	e.project.Skills = append(e.project.Skills, s)
}

// subagentSkipped says why Claude skips a subagent file, or "". Plugin
// subagents load under their file name instead.
func subagentSkipped(fm map[string]string) string {
	name := fm["name"]
	switch {
	case name == "":
		return "no name in its frontmatter, so Claude treats it as documentation"
	case strings.HasPrefix(name, "-"), strings.Contains(name, ":"), len(name) > maxAgentName:
		return "Claude skips it: the name can't start with '-', contain ':' or be over 256 characters"
	case fm["description"] == "":
		return "Claude skips it: it has no description"
	}
	return ""
}

// agentScopes is the clash order for subagents, best first. Plugin
// subagents come after all of them.
//
//nolint:gochecknoglobals // fixed list, read only
var agentScopes = []model.Scope{model.ScopeManaged, model.ScopeProject, model.ScopeUser}

// agentRank orders subagent sources for name clashes, lowest wins.
func agentRank(s model.Skill) int {
	if !s.Plugin.IsZero() {
		return len(agentScopes)
	}
	return slices.Index(agentScopes, s.Origin.Scope)
}
