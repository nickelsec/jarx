package claude

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/nickelsec/jarx/internal/agent"
	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/model"
)

type skillView struct {
	kind     model.SkillKind
	name     string
	path     string
	load     model.LoadWhen
	scope    model.Scope
	inEffect bool
}

func skillViews(c agent.Context, ss []model.Skill) []skillView {
	out := make([]skillView, 0, len(ss))
	for _, s := range ss {
		rel, err := filepath.Rel(c.Env.Home, s.Path.Raw())
		if err != nil {
			rel = s.Path.Raw()
		}
		out = append(out, skillView{s.Kind, s.Name.String(), filepath.ToSlash(rel), s.Load, s.Origin.Scope, s.Origin.InEffect})
	}
	return out
}

func findSkill(t *testing.T, c agent.Context, ss []model.Skill, rel string) model.Skill {
	t.Helper()
	for _, s := range ss {
		if s.Path.Raw() == filepath.Join(c.Env.Home, filepath.FromSlash(rel)) {
			return s
		}
	}
	t.Fatalf("no skill at %s in %+v", rel, skillViews(c, ss))
	return model.Skill{}
}

func rulesOf(fs []finding.Finding, id string) []finding.Finding {
	var out []finding.Finding
	for _, f := range fs {
		if f.RuleID == id {
			out = append(out, f)
		}
	}
	return out
}

func TestSkillsAndCommandsComeFromEachLocation(t *testing.T) {
	c := managedHome(t,
		map[string]string{
			".claude/skills/mine/SKILL.md":     "---\nname: my-skill\ndescription: d\n---\nbody",
			"p/.claude/skills/deploy/SKILL.md": "deploy steps",
			".claude/commands/fix.md":          "fix it",
			"p/.claude/commands/ship.md":       "ship it",
			"p/web/.claude/skills/ui/SKILL.md": "nested",
		},
		map[string]string{".claude/skills/org/SKILL.md": "org skill"}, nil)

	p, _ := extensionsFor(t, c, "web/.claude/skills/ui/SKILL.md", "web/app.ts")

	for rel, want := range map[string]skillView{
		"sys/" + managedRel(c) + "/.claude/skills/org/SKILL.md": {model.SkillSkill, "org", "", model.LoadInvoked, model.ScopeManaged, true},
		".claude/skills/mine/SKILL.md":                          {model.SkillSkill, "my-skill", "", model.LoadInvoked, model.ScopeUser, true},
		"p/.claude/skills/deploy/SKILL.md":                      {model.SkillSkill, "deploy", "", model.LoadInvoked, model.ScopeProject, true},
		".claude/commands/fix.md":                               {model.SkillCommand, "fix", "", model.LoadInvoked, model.ScopeUser, true},
		"p/.claude/commands/ship.md":                            {model.SkillCommand, "ship", "", model.LoadInvoked, model.ScopeProject, true},
		"p/web/.claude/skills/ui/SKILL.md":                      {model.SkillSkill, "ui", "", model.LoadOnDemand, model.ScopeProject, true},
	} {
		s := findSkill(t, c, p.Skills, rel)
		got := skillViews(c, []model.Skill{s})[0]
		got.path, want.path = "", ""
		if got != want {
			t.Errorf("%s = %+v, want %+v", rel, got, want)
		}
	}
}

// managedRel is the managed dir relative to the fake home's sys/ dir.
func managedRel(c agent.Context) string {
	rel, _ := filepath.Rel(filepath.Join(c.Env.Home, "sys"), managedDir(c.Env))
	return filepath.ToSlash(rel)
}

func TestSameNamedSkillsFollowTheDocumentedOrder(t *testing.T) {
	c := managedHome(t,
		map[string]string{
			".claude/skills/deploy/SKILL.md":   "personal",
			"p/.claude/skills/deploy/SKILL.md": "project",
			"p/.claude/skills/lint/SKILL.md":   "skill",
			"p/.claude/commands/lint.md":       "command",
		},
		map[string]string{".claude/skills/deploy/SKILL.md": "enterprise"}, nil)

	p, _ := extensionsFor(t, c)

	if s := findSkill(t, c, p.Skills, "sys/"+managedRel(c)+"/.claude/skills/deploy/SKILL.md"); !s.Origin.InEffect {
		t.Errorf("enterprise deploy not in effect: %q", s.Origin.Why)
	}
	for _, rel := range []string{".claude/skills/deploy/SKILL.md", "p/.claude/skills/deploy/SKILL.md", "p/.claude/commands/lint.md"} {
		if s := findSkill(t, c, p.Skills, rel); s.Origin.InEffect || s.Origin.Why.IsZero() {
			t.Errorf("%s = in effect %v (why %q), want shadowed with a why", rel, s.Origin.InEffect, s.Origin.Why)
		}
	}
	if s := findSkill(t, c, p.Skills, "p/.claude/skills/lint/SKILL.md"); !s.Origin.InEffect {
		t.Errorf("the lint skill should win over the lint command")
	}
}

func TestSkillFrontmatterIsReadWithoutRunningAnything(t *testing.T) {
	c := fakeHome(t, map[string]string{
		"p/.claude/skills/pr/SKILL.md": "---\nname: pr\nallowed-tools: Bash(gh *) Read\nhooks:\n  PreToolUse:\n    - matcher: Bash\n      hooks:\n        - type: command\n          command: ./check.sh " + canary + "\n---\n" +
			"- Diff: !`gh pr diff`\n" +
			"- Not run: KEY=!`nope`\n" +
			"```!\nnode --version\n```\n" +
			"token " + canary + "\n",
	})

	p, _ := extensionsFor(t, c)

	s := findSkill(t, c, p.Skills, "p/.claude/skills/pr/SKILL.md")
	tools := make([]string, 0, len(s.Tools))
	for _, tl := range s.Tools {
		tools = append(tools, tl.String())
	}
	if want := []string{"Bash(gh *)", "Read"}; !slices.Equal(tools, want) {
		t.Errorf("tools = %q, want %q", tools, want)
	}
	if !strings.Contains(s.Hooks.String(), "PreToolUse") || !strings.Contains(s.Hooks.String(), "./check.sh") {
		t.Errorf("hooks = %q, want the raw block", s.Hooks)
	}
	if s.ShellCommands != 2 {
		t.Errorf("shell commands = %d, want 2 (the inline one and the fenced block)", s.ShellCommands)
	}
	if out := fmt.Sprintf("%+v", s); strings.Contains(out, canary) {
		t.Errorf("a token got into the skill: %s", out)
	}
}

func TestShellInjectionIsAFindingUnlessTurnedOff(t *testing.T) {
	skill := "run !`date` first"
	for name, tc := range map[string]struct {
		files map[string]string
		want  int
	}{
		"on by default": {map[string]string{"p/.claude/skills/s/SKILL.md": skill}, 1},
		"turned off":    {map[string]string{"p/.claude/skills/s/SKILL.md": skill, ".claude/settings.json": `{"disableSkillShellExecution": true}`}, 0},
		"no injection":  {map[string]string{"p/.claude/skills/s/SKILL.md": "just text, `date` in a span"}, 0},
		"in a command":  {map[string]string{"p/.claude/commands/c.md": skill}, 1},
	} {
		t.Run(name, func(t *testing.T) {
			_, fs := extensionsFor(t, fakeHome(t, tc.files))

			if got := len(rulesOf(fs, ShellInjection().ID)); got != tc.want {
				t.Errorf("%s findings = %d, want %d (%+v)", ShellInjection().ID, got, tc.want, fs)
			}
		})
	}
}

func TestRepoSkillsThatGrantToolsOrAddHooksAreFindings(t *testing.T) {
	for name, tc := range map[string]struct {
		files map[string]string
		want  int
	}{
		"project allowed-tools": {map[string]string{"p/.claude/skills/s/SKILL.md": "---\nallowed-tools: Bash(*)\n---\nx"}, 1},
		"project hooks":         {map[string]string{"p/.claude/commands/c.md": "---\nhooks:\n  Stop:\n    - hooks: []\n---\nx"}, 1},
		"user allowed-tools":    {map[string]string{".claude/skills/s/SKILL.md": "---\nallowed-tools: Bash(*)\n---\nx"}, 0},
		"project plain skill":   {map[string]string{"p/.claude/skills/s/SKILL.md": "---\ndescription: plain\n---\nx"}, 0},
	} {
		t.Run(name, func(t *testing.T) {
			_, fs := extensionsFor(t, fakeHome(t, tc.files))

			if got := len(rulesOf(fs, RepoSkillGrants().ID)); got != tc.want {
				t.Errorf("%s findings = %d, want %d (%+v)", RepoSkillGrants().ID, got, tc.want, fs)
			}
		})
	}
}

func TestReservedSkillNamesDontLoad(t *testing.T) {
	c := fakeHome(t, map[string]string{
		".claude/skills/synced/SKILL.md":             "reserved",
		"p/.claude/skills/anthropic-skills/SKILL.md": "reserved",
		"p/.claude/skills/ok/SKILL.md":               "fine",
	})

	p, _ := extensionsFor(t, c)

	if got := len(p.Skills); got != 1 || p.Skills[0].Name.String() != "ok" {
		t.Errorf("skills = %+v, want only ok", skillViews(c, p.Skills))
	}
}
