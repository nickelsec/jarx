package claude

import (
	"slices"
	"strings"
	"testing"

	"github.com/nickelsec/jarx/internal/model"
)

const agentFile = "---\nname: reviewer\ndescription: Reviews code\ntools: Read, Grep, Bash(git *)\npermissionMode: bypassPermissions\nhooks:\n  Stop:\n    - hooks:\n        - type: command\n          command: ./notify.sh\n---\nYou review code."

func TestSubagentsComeFromEachLocation(t *testing.T) {
	c := managedHome(t,
		map[string]string{
			".claude/agents/helper.md":        "---\nname: helper\ndescription: d\n---\nx",
			"p/.claude/agents/reviewer.md":    agentFile,
			"p/.claude/agents/team/tester.md": "---\nname: tester\ndescription: d\n---\nx",
		},
		map[string]string{".claude/agents/org.md": "---\nname: org\ndescription: d\n---\nx"}, nil)

	p, _ := extensionsFor(t, c)

	for rel, scope := range map[string]model.Scope{
		"sys/" + managedRel(c) + "/.claude/agents/org.md": model.ScopeManaged,
		".claude/agents/helper.md":                        model.ScopeUser,
		"p/.claude/agents/reviewer.md":                    model.ScopeProject,
		"p/.claude/agents/team/tester.md":                 model.ScopeProject,
	} {
		s := findSkill(t, c, p.Skills, rel)
		if s.Kind != model.SkillSubagent || s.Origin.Scope != scope || !s.Origin.InEffect || s.Load != model.LoadInvoked {
			t.Errorf("%s = %+v, want a %s subagent in effect", rel, skillViews(c, []model.Skill{s}), scope)
		}
	}
}

func TestSubagentFrontmatterIsRead(t *testing.T) {
	c := fakeHome(t, map[string]string{"p/.claude/agents/reviewer.md": agentFile})

	p, _ := extensionsFor(t, c)

	s := findSkill(t, c, p.Skills, "p/.claude/agents/reviewer.md")
	tools := make([]string, 0, len(s.Tools))
	for _, tl := range s.Tools {
		tools = append(tools, tl.String())
	}
	if want := []string{"Read", "Grep", "Bash(git *)"}; !slices.Equal(tools, want) {
		t.Errorf("tools = %q, want %q", tools, want)
	}
	if s.Name.String() != "reviewer" || s.Mode.String() != "bypassPermissions" || !strings.Contains(s.Hooks.String(), "notify.sh") {
		t.Errorf("subagent = name %q mode %q hooks %q, want them read", s.Name, s.Mode, s.Hooks)
	}
	if s.ShellCommands != 0 {
		t.Errorf("shell commands = %d, want none counted for subagents", s.ShellCommands)
	}
}

func TestSubagentsFollowTheDocumentedOrder(t *testing.T) {
	c := managedHome(t,
		map[string]string{
			".claude/agents/reviewer.md":   "---\nname: reviewer\ndescription: user\n---\nx",
			"p/.claude/agents/reviewer.md": "---\nname: reviewer\ndescription: project\n---\nx",
		},
		map[string]string{".claude/agents/reviewer.md": "---\nname: reviewer\ndescription: managed\n---\nx"}, nil)

	p, _ := extensionsFor(t, c)

	for _, s := range p.Skills {
		want := s.Origin.Scope == model.ScopeManaged
		if s.Origin.InEffect != want || (!want && s.Origin.Why.IsZero()) {
			t.Errorf("%s reviewer in effect = %v (why %q), want %v", s.Origin.Scope, s.Origin.InEffect, s.Origin.Why, want)
		}
	}
	if len(p.Skills) != 3 {
		t.Errorf("subagents = %d, want all three listed", len(p.Skills))
	}
}

func TestSubagentFilesClaudeSkips(t *testing.T) {
	c := fakeHome(t, map[string]string{
		"p/.claude/agents/notes.md":  "# just notes about agents",
		"p/.claude/agents/nodesc.md": "---\nname: nodesc\n---\nx",
		"p/.claude/agents/colon.md":  "---\nname: my:agent\ndescription: d\n---\nx",
		"p/.claude/agents/ok.md":     "---\nname: ok\ndescription: d\n---\nx",
	})

	p, _ := extensionsFor(t, c)

	for rel, want := range map[string]bool{
		"p/.claude/agents/notes.md":  false,
		"p/.claude/agents/nodesc.md": false,
		"p/.claude/agents/colon.md":  false,
		"p/.claude/agents/ok.md":     true,
	} {
		s := findSkill(t, c, p.Skills, rel)
		if s.Origin.InEffect != want || (!want && s.Origin.Why.IsZero()) {
			t.Errorf("%s in effect = %v (why %q), want %v", rel, s.Origin.InEffect, s.Origin.Why, want)
		}
	}
}
