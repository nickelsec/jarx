package llm

import (
	"strings"
	"testing"

	"github.com/nickelsec/jarx/internal/catalog"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/redact"
)

// scrubber is the real secret patterns with no fingerprint key, so a
// canary in a fixture is masked the way a scan masks it.
func scrubber(t *testing.T) *redact.Scrubber {
	t.Helper()
	patterns, err := catalog.Secrets()
	if err != nil {
		t.Fatal(err)
	}
	s, err := redact.New(patterns, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func txt(s *redact.Scrubber, v string) redact.Text {
	t, _ := s.Scrub(v)
	return t
}

func origin(s *redact.Scrubber, file string) model.Origin {
	return model.Origin{Agent: model.AgentClaude, Scope: model.ScopeProject, File: model.NewPath(s, file), InEffect: true}
}

// project has one of every artifact kind, plus things that must never be
// sent: memory, a skill that wasn't read, a hook that isn't in effect, and a
// prompt a server offers.
func project(s *redact.Scrubber) model.Project {
	off := origin(s, "/p/.claude/settings.json")
	off.InEffect = false
	return model.Project{
		Path: model.NewPath(s, "/p"),
		Instructions: []model.Instruction{
			{Kind: model.InstructionFile, Path: model.NewPath(s, "/p/CLAUDE.md"), Read: model.ReadOK, Text: txt(s, "use tabs"), Origin: origin(s, "/p/CLAUDE.md")},
			{Kind: model.InstructionMemory, Path: model.NewPath(s, "/h/.claude/projects/p/memory/MEMORY.md"), Read: model.ReadOK, Text: txt(s, "MEMORYMARKER from past sessions"), Origin: origin(s, "/h/.claude/projects/p/memory/MEMORY.md")},
			{Kind: model.InstructionAgentMemory, Path: model.NewPath(s, "/h/.claude/agent-memory/x.md"), Read: model.ReadOK, Text: txt(s, "AGENTMEMORYMARKER"), Origin: origin(s, "/h/.claude/agent-memory/x.md")},
		},
		Skills: []model.Skill{
			{Kind: model.SkillSkill, Name: txt(s, "release"), Path: model.NewPath(s, "/p/.claude/skills/release/SKILL.md"), Read: model.ReadOK, Text: txt(s, "ship it"), Origin: origin(s, "/p/.claude/skills/release/SKILL.md")},
			{Kind: model.SkillSkill, Name: txt(s, "unread"), Read: model.ReadTooLarge, Origin: origin(s, "/p/.claude/skills/unread/SKILL.md")},
		},
		Hooks: []model.Hook{
			{Event: txt(s, "PreToolUse"), Type: txt(s, "command"), Run: txt(s, "./check.sh"), Script: model.NewPath(s, "/p/check.sh"), ScriptRead: model.ReadOK, ScriptText: txt(s, "echo checked"), Origin: origin(s, "/p/.claude/settings.json")},
			{Event: txt(s, "Stop"), Type: txt(s, "command"), Run: txt(s, "OFFMARKER"), Origin: off},
		},
		Servers: []model.Server{{
			Name: txt(s, "notes"), Status: model.StatusListed, Origin: origin(s, "/p/.mcp.json"),
			Offers: []model.Offer{
				{Kind: model.OfferTool, Name: txt(s, "save_note"), Text: txt(s, `{"name":"save_note","description":"saves a note"}`)},
				{Kind: model.OfferPrompt, Name: txt(s, "a_prompt"), Text: txt(s, "PROMPTMARKER")},
			},
		}},
		Sessions: []model.Session{{ID: txt(s, "SESSIONMARKER")}},
	}
}

func TestCollectTakesOneOfEachKindTheAgentLoads(t *testing.T) {
	s := scrubber(t)

	arts := Collect(scrubber(t), []model.Project{project(s)})

	got := map[Kind]int{}
	for _, a := range arts {
		got[a.Kind]++
	}
	want := map[Kind]int{KindTool: 1, KindSkill: 1, KindInstructions: 1, KindHook: 1}
	if len(got) != len(want) {
		t.Fatalf("kinds = %v, want %v", got, want)
	}
	for k, n := range want {
		if got[k] != n {
			t.Errorf("%s = %d, want %d (all %v)", k, got[k], n, got)
		}
	}
}

func TestCollectNeverTakesMemoryHistoryPromptsOrWhatIsNotInEffect(t *testing.T) {
	s := scrubber(t)

	arts := Collect(scrubber(t), []model.Project{project(s)})

	for _, a := range arts {
		for _, marker := range []string{"MEMORYMARKER", "AGENTMEMORYMARKER", "SESSIONMARKER", "PROMPTMARKER", "OFFMARKER"} {
			if strings.Contains(a.Name.String()+a.Text.String(), marker) {
				t.Errorf("%s %s holds %s, which must never be sent", a.Kind, a.Name, marker)
			}
		}
	}
}

func TestCollectSendsAHookWithItsScript(t *testing.T) {
	s := scrubber(t)

	for _, a := range Collect(scrubber(t), []model.Project{project(s)}) {
		if a.Kind == KindHook && (!strings.Contains(a.Text.String(), "./check.sh") || !strings.Contains(a.Text.String(), "echo checked")) {
			t.Errorf("hook text = %q, want the command and its script", a.Text)
		}
	}
}

func TestCollectSendsTheSameArtifactOnce(t *testing.T) {
	s := scrubber(t)
	p := project(s)
	other := project(s)
	other.Path = model.NewPath(s, "/q")

	arts := Collect(scrubber(t), []model.Project{p, other})

	if len(arts) != 4 {
		t.Errorf("got %d artifacts, want 4: the same texts in two projects go once", len(arts))
	}
}

func TestCollectCutsAHugeArtifact(t *testing.T) {
	s := scrubber(t)
	p := model.Project{Instructions: []model.Instruction{{
		Kind: model.InstructionFile, Path: model.NewPath(s, "/p/AGENTS.md"), Read: model.ReadOK,
		Text: txt(s, strings.Repeat("a", MaxArtifactBytes+100)), Origin: origin(s, "/p/AGENTS.md"),
	}}}

	arts := Collect(scrubber(t), []model.Project{p})

	if len(arts) != 1 || len(arts[0].Text.String()) != MaxArtifactBytes || !arts[0].Cut {
		t.Errorf("got %d artifacts, first %d bytes cut=%v; want one cut to %d", len(arts), len(arts[0].Text.String()), arts[0].Cut, MaxArtifactBytes)
	}
}
