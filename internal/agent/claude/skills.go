package claude

import (
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/nickelsec/jarx/internal/agent"
	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/model"
)

// Skills and commands, from code.claude.com/docs/en/skills: a skill is
// <name>/SKILL.md under the managed dir's .claude/skills, ~/.claude/skills or
// the project's .claude/skills (nested ones load once Claude works in their
// folder), and a command is a .md file in .claude/commands. On a name clash,
// enterprise beats personal beats project, and a skill beats a command.
// A skill's body can run shell commands before Claude sees it (!`cmd` and
// ```! blocks); jarx counts them and never runs them.

// ShellInjection is the finding for a skill or command whose body runs shell
// commands when it's invoked, before Claude sees it.
func ShellInjection() finding.Rule {
	return finding.Rule{
		ID:       "JARX-CLAUDE-003",
		Severity: finding.Medium,
		Title:    "a skill runs shell commands before Claude sees it",
		Fix:      "check each !`command` in it, or set disableSkillShellExecution in managed settings",
	}
}

// RepoSkillGrants is the finding for a skill or command from the repository
// that pre-approves tools or adds hooks, which Claude applies even in a
// folder you haven't trusted.
func RepoSkillGrants() finding.Rule {
	return finding.Rule{
		ID:       "JARX-CLAUDE-004",
		Severity: finding.Medium,
		Title:    "a repository skill grants tools or adds hooks without the trust check",
		Fix:      "review its allowed-tools and hooks before running Claude in this repository",
	}
}

// injectedInline is !`cmd` at the start of a line or after whitespace.
var injectedInline = regexp.MustCompile("(^|\\s)!`")

// shellCommands counts the shell commands a skill body runs before Claude
// sees it: each inline !`cmd` and each ```! block.
func shellCommands(body string) int {
	n := 0
	for line := range strings.SplitSeq(body, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if strings.HasPrefix(strings.TrimSpace(line), "```!") {
			n++
			continue
		}
		n += len(injectedInline.FindAllStringIndex(line, -1))
	}
	return n
}

// reservedSkill is a skill folder name Claude skips outside plugins.
func reservedSkill(name string) bool {
	lower := strings.ToLower(name)
	return lower == "synced" || lower == "anthropic-skills" || strings.HasPrefix(lower, "anthropic-skills:")
}

// skillScopes is the clash order for skills, best first.
//
//nolint:gochecknoglobals // fixed list, read only
var skillScopes = []model.Scope{model.ScopeManaged, model.ScopeUser, model.ScopeProject}

// kindsPerLevel is how many kinds share a level: a skill, then a command.
const kindsPerLevel = 2

// skillRank orders skill sources for name clashes, lowest wins: enterprise,
// personal, project, and a skill before a command at each level.
func skillRank(s model.Skill) int {
	rank := slices.Index(skillScopes, s.Origin.Scope) * kindsPerLevel
	if s.Kind == model.SkillCommand {
		rank++
	}
	return rank
}

// skills adds every skill and command, then marks the ones a higher source
// shadows.
func (e *extReader) skills(cfg string) {
	if m := managedDir(e.c.Env); m != "" {
		e.skillDir(filepath.Join(m, ".claude", "skills"), model.ScopeManaged)
	}
	e.skillDir(filepath.Join(cfg, "skills"), model.ScopeUser)
	e.skillDir(filepath.Join(e.project.Path.Raw(), ".claude", "skills"), model.ScopeProject)
	e.commandDir(filepath.Join(cfg, "commands"), model.ScopeUser)
	e.commandDir(filepath.Join(e.project.Path.Raw(), ".claude", "commands"), model.ScopeProject)
	e.nestedSkills()
	// Nested skills don't clash with others: both load.
	e.shadow(func(s model.Skill) bool {
		return s.Kind != model.SkillSubagent && s.Load != model.LoadOnDemand && s.Plugin.IsZero()
	}, skillRank)
	for _, s := range e.project.Skills {
		e.skillFindings(s)
	}
}

// skillDir adds <dir>/<name>/SKILL.md for every skill folder, following a
// symlinked folder to its target.
func (e *extReader) skillDir(dir string, scope model.Scope) {
	entries, err := e.c.Files.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		sub := filepath.Join(dir, entry.Name())
		if info, err := e.c.Files.Stat(sub); err != nil || !info.IsDir() || reservedSkill(entry.Name()) {
			continue
		}
		e.addSkill(model.SkillSkill, filepath.Join(sub, "SKILL.md"), entry.Name(), scope, model.LoadInvoked)
	}
}

// commandDir adds every .md file in dir as a command.
func (e *extReader) commandDir(dir string, scope model.Scope) {
	for _, f := range (&reader{c: e.c}).mdFiles(dir) {
		name := strings.TrimSuffix(filepath.Base(f), filepath.Ext(f))
		if reservedSkill(name) {
			continue
		}
		e.addSkill(model.SkillCommand, f, name, scope, model.LoadInvoked)
	}
}

// nestedSkills adds the skills in subfolders' .claude/skills, which load
// once Claude works on files there.
func (e *extReader) nestedSkills() {
	for _, f := range e.project.Files {
		rel := filepath.ToSlash(f.Raw())
		dir, base := path.Split(rel)
		parent := path.Base(strings.TrimSuffix(dir, "/"))
		if base != "SKILL.md" || strings.HasPrefix(rel, ".claude/") || !strings.Contains(rel, "/.claude/skills/"+parent+"/") || reservedSkill(parent) {
			continue
		}
		e.addSkill(model.SkillSkill, filepath.Join(e.project.Path.Raw(), filepath.FromSlash(rel)), parent, model.ScopeProject, model.LoadOnDemand)
	}
}

// addSkill reads one skill or command file. A missing SKILL.md isn't a
// skill, so it isn't listed.
func (e *extReader) addSkill(kind model.SkillKind, file, name string, scope model.Scope, load model.LoadWhen) {
	r := &reader{c: e.c}
	status, data := r.read(file)
	if status == model.ReadMissing {
		return
	}
	s := model.Skill{
		Kind: kind, Path: model.NewPath(e.c.Scrub, file), Load: load, Read: status,
		Origin: model.Origin{Agent: model.AgentClaude, File: model.NewPath(e.c.Scrub, file), Scope: scope, InEffect: true},
	}
	if status == model.ReadOK {
		e.fillSkill(&s, string(data), name, kind != model.SkillCommand)
	}
	if s.Name.IsZero() {
		s.Name = e.text(name)
	}
	e.project.Skills = append(e.project.Skills, s)
}

// fillSkill reads a skill file's frontmatter and body. Commands ignore the
// name field.
func (e *extReader) fillSkill(s *model.Skill, text, name string, nameField bool) {
	s.Text = e.text(text)
	fm, body, _ := agent.Frontmatter(text)
	if v := fm["name"]; nameField && v != "" {
		name = v
	}
	s.Name = e.text(name)
	tools := agent.ToolList(text, "allowed-tools")
	if s.Kind == model.SkillSubagent {
		tools = agent.ToolList(text, "tools")
	}
	for _, t := range tools {
		s.Tools = append(s.Tools, e.text(t))
	}
	if block, ok := agent.FrontmatterBlock(text, "hooks"); ok {
		s.Hooks = e.text(block)
	}
	if s.Kind != model.SkillSubagent {
		s.ShellCommands = shellCommands(body)
	}
}

// shadow marks every eligible skill not in effect when an eligible one with
// the same name and a lower rank exists.
func (e *extReader) shadow(eligible func(model.Skill) bool, rank func(model.Skill) int) {
	best := e.bestByName(eligible, rank)
	for i := range e.project.Skills {
		s := &e.project.Skills[i]
		j, ok := best[s.Name.String()]
		if !ok || j == i || !eligible(*s) || !s.Origin.InEffect {
			continue
		}
		w := e.project.Skills[j]
		s.Origin.InEffect = false
		s.Origin.Why = e.text("a " + string(w.Origin.Scope) + " " + string(w.Kind) + " named " + s.Name.String() + " takes precedence")
	}
}

// bestByName returns, per name, the index of the eligible in-effect skill
// with the lowest rank.
func (e *extReader) bestByName(eligible func(model.Skill) bool, rank func(model.Skill) int) map[string]int {
	best := map[string]int{}
	for i, s := range e.project.Skills {
		if !eligible(s) || !s.Origin.InEffect {
			continue
		}
		if j, ok := best[s.Name.String()]; !ok || rank(s) < rank(e.project.Skills[j]) {
			best[s.Name.String()] = i
		}
	}
	return best
}

// skillFindings raises the shell injection and repository grant findings.
func (e *extReader) skillFindings(s model.Skill) {
	if s.Kind == model.SkillSubagent {
		return
	}
	e.shellFinding(s)
	e.grantFinding(s)
}

// shellFinding flags a skill whose body runs shell commands, unless
// disableSkillShellExecution turns that off (it doesn't cover managed
// skills).
func (e *extReader) shellFinding(s model.Skill) {
	off, _ := effective(e.layers, func(l *layer) *bool { return l.skillShellOff })
	if s.ShellCommands == 0 || (off != nil && *off && s.Origin.Scope != model.ScopeManaged) {
		return
	}
	ev := e.text(s.Name.String() + " runs " + plural(s.ShellCommands, "shell command") + " when invoked")
	e.findings = append(e.findings, ShellInjection().New(s.Origin, ev))
}

// grantFinding flags a repository skill that pre-approves tools or adds
// hooks.
func (e *extReader) grantFinding(s model.Skill) {
	if s.Origin.Scope != model.ScopeProject || (len(s.Tools) == 0 && s.Hooks.IsZero()) {
		return
	}
	var what []string
	if len(s.Tools) > 0 {
		names := make([]string, 0, len(s.Tools))
		for _, t := range s.Tools {
			names = append(names, t.String())
		}
		what = append(what, "pre-approves "+strings.Join(names, ", "))
	}
	if !s.Hooks.IsZero() {
		what = append(what, "adds hooks")
	}
	e.findings = append(e.findings, RepoSkillGrants().New(s.Origin, e.text(s.Name.String()+" "+strings.Join(what, " and "))))
}

func plural(n int, one string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + one + "s"
}
