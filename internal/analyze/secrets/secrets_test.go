package secrets

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nickelsec/jarx/internal/catalog"
	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/redact"
)

type staticKey []byte

func (k staticKey) Key() ([]byte, error) { return k, nil }

// A made-up value with no known format, caught by its name. Real-token
// entropy, so it isn't a placeholder.
const fake = "Xq7Lm2Pz9Rw4Tb8Nc1VdKj5Hs3Fg6Yu"

type fixture struct {
	t     *testing.T
	scrub *redact.Scrubber
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	ps, err := catalog.Secrets()
	if err != nil {
		t.Fatal(err)
	}
	s, err := redact.New(ps, staticKey("test key"))
	if err != nil {
		t.Fatal(err)
	}
	return fixture{t: t, scrub: s}
}

func (f fixture) text(raw string) redact.Text {
	t, _ := f.scrub.Scrub(raw)
	return t
}

func (f fixture) origin(file string, scope model.Scope) model.Origin {
	return model.Origin{Agent: model.AgentClaude, File: model.NewPath(f.scrub, filepath.FromSlash(file)), Scope: scope, InEffect: true}
}

func (f fixture) instruction(file, raw string) model.Instruction {
	o := f.origin(file, model.ScopeProject)
	return model.Instruction{Kind: model.InstructionFile, Path: o.File, Read: model.ReadOK, Text: f.text(raw), Origin: o}
}

func (f fixture) config(file, raw string, scope model.Scope) model.Config {
	return model.Config{Origin: f.origin(file, scope), Text: f.text(raw)}
}

func ids(fs []finding.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, x := range fs {
		out = append(out, x.RuleID)
	}
	return out
}

func only(t *testing.T, fs []finding.Finding, id string) finding.Finding {
	t.Helper()
	if len(fs) != 1 || fs[0].RuleID != id {
		t.Fatalf("findings = %q, want one %s", ids(fs), id)
	}
	return fs[0]
}

func TestASecretInAnInstructionFileIsOneTheAgentSees(t *testing.T) {
	f := newFixture(t)
	p := model.Project{Instructions: []model.Instruction{f.instruction("/p/CLAUDE.md", "deploy with DEPLOY_TOKEN="+fake)}}

	got := only(t, Analyze(f.scrub, []model.Project{p}, nil), "JARX-SECRET-001")

	if ev := got.Evidence.String(); !strings.Contains(ev, "named_secret") || !strings.Contains(ev, "fingerprint") || strings.Contains(ev, fake) {
		t.Errorf("evidence = %q, want the kind and fingerprint, never the value", ev)
	}
	if got.Origin.File.Raw() != f.origin("/p/CLAUDE.md", model.ScopeProject).File.Raw() {
		t.Errorf("origin = %v, want the instruction file", got.Origin.File)
	}
}

func TestSkillBodiesAndGlobalInstructionsAreSeenToo(t *testing.T) {
	f := newFixture(t)
	skill := model.Skill{Kind: model.SkillSkill, Text: f.text("API_KEY=" + fake), Origin: f.origin("/p/.claude/skills/x/SKILL.md", model.ScopeProject)}
	global := f.instruction("/h/.claude/projects/m/memory/MEMORY.md", "the password: "+fake+"2")

	got := Analyze(f.scrub, []model.Project{{Skills: []model.Skill{skill}}}, []model.Instruction{global})

	if fmt.Sprint(ids(got)) != "[JARX-SECRET-001 JARX-SECRET-001]" {
		t.Errorf("findings = %q, want both seen", ids(got))
	}
}

func TestASecretInAConfigFileOrHookIsPlainText(t *testing.T) {
	f := newFixture(t)
	p := model.Project{
		Configs: []model.Config{f.config("/p/.claude/settings.json", `{"env": {"DEPLOY_TOKEN": "`+fake+`"}}`, model.ScopeProject)},
		Hooks: []model.Hook{{
			Run:        f.text("./deploy.sh"),
			Script:     f.origin("/p/deploy.sh", model.ScopeProject).File,
			ScriptText: f.text("curl -H 'Authorization: Bearer " + fake + "x'"),
			Origin:     f.origin("/p/.codex/hooks.json", model.ScopeProject),
		}},
	}

	got := Analyze(f.scrub, []model.Project{p}, nil)

	if fmt.Sprint(ids(got)) != "[JARX-SECRET-002 JARX-SECRET-002]" {
		t.Fatalf("findings = %q, want the config and the hook script", ids(got))
	}
	if got[1].Origin.File.Raw() != filepath.FromSlash("/p/deploy.sh") {
		t.Errorf("script finding is in %q, want the script itself", got[1].Origin.File.Raw())
	}
}

func TestAnInstructionNotInEffectIsntSeen(t *testing.T) {
	f := newFixture(t)
	in := f.instruction("/p/AGENTS.md", "TOKEN="+fake)
	in.Origin.InEffect = false

	only(t, Analyze(f.scrub, []model.Project{{Instructions: []model.Instruction{in}}}, nil), "JARX-SECRET-002")
}

func TestAPlaceholderIsInfoWhereverItIs(t *testing.T) {
	f := newFixture(t)
	p := model.Project{Instructions: []model.Instruction{f.instruction("/p/CLAUDE.md", "set API_KEY=your-api-key-here")}}

	got := only(t, Analyze(f.scrub, []model.Project{p}, nil), "JARX-SECRET-003")

	if got.Severity != finding.Info || !strings.Contains(got.Evidence.String(), "agent sees") {
		t.Errorf("finding = %+v, want info that still says where it is", got)
	}
}

func TestAFileSharedByProjectsIsReportedOnce(t *testing.T) {
	f := newFixture(t)
	user := f.config("/h/.claude/settings.json", `{"env": {"DEPLOY_TOKEN": "`+fake+`"}}`, model.ScopeUser)

	got := Analyze(f.scrub, []model.Project{{Configs: []model.Config{user}}, {Configs: []model.Config{user}}}, nil)

	only(t, got, "JARX-SECRET-002")
}

func TestAHookFromASettingsFileIsntCountedTwice(t *testing.T) {
	f := newFixture(t)
	file := "/p/.claude/settings.json"
	raw := `{"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "notify --token=` + fake + `"}]}]}}`
	p := model.Project{
		Configs: []model.Config{f.config(file, raw, model.ScopeProject)},
		Hooks:   []model.Hook{{Run: f.text("notify --token=" + fake), Origin: f.origin(file, model.ScopeProject)}},
	}

	only(t, Analyze(f.scrub, []model.Project{p}, nil), "JARX-SECRET-002")
}

func TestTheSameSecretInTwoPlacesSaysSo(t *testing.T) {
	f := newFixture(t)
	p := model.Project{
		Instructions: []model.Instruction{f.instruction("/p/CLAUDE.md", "DEPLOY_TOKEN="+fake)},
		Configs:      []model.Config{f.config("/p/.claude/settings.json", `{"env": {"DEPLOY_TOKEN": "`+fake+`"}}`, model.ScopeProject)},
	}

	got := Analyze(f.scrub, []model.Project{p}, nil)

	if len(got) != 2 {
		t.Fatalf("findings = %q, want two", ids(got))
	}
	for _, x := range got {
		if !strings.Contains(x.Evidence.String(), "also in 1 other file") {
			t.Errorf("%s evidence = %q, want the other place counted", x.RuleID, x.Evidence)
		}
	}
}

func TestNoSecretsNoFindings(t *testing.T) {
	f := newFixture(t)
	p := model.Project{
		Instructions: []model.Instruction{f.instruction("/p/CLAUDE.md", "run go test ./...")},
		Configs:      []model.Config{f.config("/p/.claude/settings.json", `{"apiKeyHelper": "/bin/get-key"}`, model.ScopeProject)},
	}

	if got := Analyze(f.scrub, []model.Project{p}, nil); len(got) != 0 {
		t.Errorf("findings = %q, want none", ids(got))
	}
}

func TestRulesAreValid(t *testing.T) {
	if _, err := finding.NewRegistry(Rules()...); err != nil {
		t.Fatal(err)
	}
}

func TestSecretsInServerDefinitionsAreFound(t *testing.T) {
	f := newFixture(t)
	for name, s := range map[string]model.Server{
		"env value": {Env: []model.Pair{{Key: f.text("API_TOKEN"), Value: f.secret(fake)}}},
		"header":    {Headers: []model.Pair{{Key: f.text("Authorization"), Value: f.text("Bearer " + fake)}}},
		"url":       {URL: f.text("https://x.example.com/mcp?api_token=" + fake)},
		"arg":       {Args: []redact.Text{f.text("--api-key=" + fake)}},
	} {
		t.Run(name, func(t *testing.T) {
			s.Name, s.Origin = f.text("srv"), f.origin("/home/dev/.claude.json", model.ScopeUser)
			p := model.Project{Path: model.NewPath(f.scrub, "/home/dev/app"), Servers: []model.Server{s}}

			got := only(t, Analyze(f.scrub, []model.Project{p}, nil), PlainText().ID)

			if got.Origin.File.Raw() != filepath.FromSlash("/home/dev/.claude.json") {
				t.Errorf("finding is in %s, want ~/.claude.json", got.Origin.File.Raw())
			}
		})
	}
}

func TestAUserServerSecretIsReportedOnceAcrossProjects(t *testing.T) {
	f := newFixture(t)
	s := model.Server{Name: f.text("srv"), URL: f.text("https://x.example.com/mcp?api_token=" + fake), Origin: f.origin("/home/dev/.claude.json", model.ScopeUser)}
	ps := []model.Project{{Servers: []model.Server{s}}, {Servers: []model.Server{s}}}

	only(t, Analyze(f.scrub, ps, nil), PlainText().ID)
}

// secret masks a value the way an adapter does for one it knows is secret.
func (f fixture) secret(raw string) redact.Text {
	t, _ := f.scrub.Secret("named_secret", raw)
	return t
}
