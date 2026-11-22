package report

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/redact"
)

const canary = "tok_Xq7Lm2Pz9Rw4Tb8Nc1Vd" // made up for tests

func setup(t *testing.T) (*Printer, *redact.Scrubber, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	s, err := redact.New([]redact.Pattern{
		{Kind: "test_token", Re: regexp.MustCompile(`tok_[A-Za-z0-9]{16,}`)},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var out, errw bytes.Buffer
	return New(&out, &errw, s), s, &out, &errw
}

func TestOutPrintfWritesMaskedTextToStdout(t *testing.T) {
	p, s, out, errw := setup(t)
	v, _ := s.Scrub("key " + canary)

	p.Out.Printf("value: %s\n", v)

	if out.String() != "value: key REDACTED:test_token\n" {
		t.Errorf("stdout = %q, want the masked value", out.String())
	}
	if errw.Len() != 0 {
		t.Errorf("stderr = %q, want empty", errw.String())
	}
}

func TestErrPrintfWritesToStderr(t *testing.T) {
	p, s, out, errw := setup(t)
	v, _ := s.Scrub("frobnicate")

	p.Err.Printf("jarx: unknown command %q\n", v)

	if errw.String() != "jarx: unknown command \"frobnicate\"\n" {
		t.Errorf("stderr = %q", errw.String())
	}
	if out.Len() != 0 {
		t.Errorf("stdout = %q, want empty", out.String())
	}
}

func TestErrorScrubsTheErrorText(t *testing.T) {
	// A parser error can quote the offending line, secret and all.
	p, _, _, errw := setup(t)
	err := fmt.Errorf("reading config: %w", errors.New(`line 3: bad value "`+canary+`"`))

	p.Error(err)

	if strings.Contains(errw.String(), canary) {
		t.Errorf("stderr = %q, leaks the secret from the error", errw.String())
	}
	if errw.String() != "jarx: reading config: line 3: bad value \"REDACTED:test_token\"\n" {
		t.Errorf("stderr = %q, want the scrubbed error", errw.String())
	}
}

func TestProjectsListing(t *testing.T) {
	p, s, out, _ := setup(t)
	path := func(raw string) model.Path { return model.NewPath(s, raw) }
	claude := model.Origin{Agent: model.AgentClaude}
	codex := model.Origin{Agent: model.AgentCodex}

	p.Projects([]model.Project{
		{
			Path: path("/projects/app"), Status: model.ProjectOK,
			Origins: []model.Origin{claude, codex},
			Trust:   []model.Trust{{Level: model.TrustTrusted, Origin: codex}},
			Files:   []model.Path{path("a.go"), path("b.go")},
			Walk:    model.WalkGit,
		},
		{
			Path: path("/projects/one"), Status: model.ProjectOK, Origins: []model.Origin{codex},
			Files: []model.Path{path("README.md")}, Walk: model.WalkFallback,
		},
		{Path: path("/projects/old"), Status: model.ProjectStale, Origins: []model.Origin{claude, claude}},
		{Path: path("/" + canary), Status: model.ProjectOutsideHome, Origins: []model.Origin{{Agent: model.AgentJarx}}},
	})

	want := "projects (4)\n" +
		"  /projects/app  claude, codex (trusted)  2 files (git)\n" +
		"  /projects/one  codex  1 file (walk)\n" +
		"  /projects/old  claude  stale\n" +
		"  /REDACTED:test_token  jarx  outside fake home\n"
	if out.String() != want {
		t.Errorf("stdout =\n%s\nwant\n%s", out.String(), want)
	}
}

func TestFindingsListingIsWorstFirstWithTitles(t *testing.T) {
	p, s, out, _ := setup(t)
	reg, err := finding.NewRegistry(finding.Rules()...)
	if err != nil {
		t.Fatal(err)
	}
	ev, _ := s.Scrub("not valid TOML " + canary)
	at := func(file string, line int) model.Origin {
		return model.Origin{File: model.NewPath(s, file), Line: line}
	}
	high := finding.Rule{ID: "JARX-TEST-001", Severity: finding.High, Title: "t", Fix: "f"}

	p.Findings([]finding.Finding{
		finding.UnreadableRecord().New(at("/h/.codex/config.toml", 3), ev),
		high.New(at("/h/x", 0), redact.Text{}),
	}, reg)

	want := "findings (2)\n" +
		"  high  JARX-TEST-001  /h/x\n" +
		"  info  JARX-SCAN-002  /h/.codex/config.toml:3  couldn't read an agent's records: not valid TOML REDACTED:test_token\n"
	if out.String() != want {
		t.Errorf("stdout =\n%s\nwant\n%s", out.String(), want)
	}
}

func TestEmptyListings(t *testing.T) {
	p, _, out, _ := setup(t)
	reg, _ := finding.NewRegistry()

	p.Projects(nil)
	p.Findings(nil, reg)

	if out.String() != "projects (0)\nfindings (0)\n" {
		t.Errorf("stdout = %q", out.String())
	}
}

func TestProjectsListingShowsPermissions(t *testing.T) {
	p, s, out, _ := setup(t)
	text := func(raw string) redact.Text { v, _ := s.Scrub(raw); return v }
	at := func(scope model.Scope) model.Origin {
		return model.Origin{Agent: model.AgentClaude, Scope: scope, InEffect: true}
	}
	held := at(model.ScopeProject)
	held.InEffect, held.Why = false, text("project allow waits for trust: the folder isn't trusted")
	ignored := at(model.ScopeProject)
	ignored.InEffect, ignored.Why = false, text("defaultMode auto is ignored from project files")

	p.Projects([]model.Project{{
		Path: model.NewPath(s, "/projects/app"), Status: model.ProjectOK,
		Origins: []model.Origin{{Agent: model.AgentClaude}},
		Permissions: []model.Permissions{{
			Agent: model.AgentClaude,
			DefaultMode: model.Setting[redact.Text]{Layers: []model.Layer[redact.Text]{
				{Value: text("auto"), Origin: ignored},
				{Value: text("plan"), Origin: at(model.ScopeUser)},
			}},
			Rules: []model.PermissionRule{
				{Action: model.RuleAllow, Rule: text("Bash(*)"), Origin: held},
				{Action: model.RuleDeny, Rule: text("Read(" + canary + ")"), Origin: at(model.ScopeUser)},
			},
			AdditionalDirectories: []model.Layer[redact.Text]{{Value: text("../shared"), Origin: at(model.ScopeLocal)}},
		}},
	}})

	want := "projects (1)\n" +
		"  /projects/app  claude\n" +
		"    claude permissions\n" +
		"      mode   auto  project  not in effect: defaultMode auto is ignored from project files\n" +
		"      mode   plan  user\n" +
		"      allow  Bash(*)  project  not in effect: project allow waits for trust: the folder isn't trusted\n" +
		"      deny   Read(REDACTED:test_token)  user\n" +
		"      dir    ../shared  local\n"
	if out.String() != want {
		t.Errorf("stdout =\n%s\nwant\n%s", out.String(), want)
	}
}

func TestUnknownSettingsListing(t *testing.T) {
	p, s, out, _ := setup(t)
	key := func(raw string) redact.Text { v, _ := s.Scrub(raw); return v }
	origin := model.Origin{Agent: model.AgentClaude, Scope: model.ScopeProject, File: model.NewPath(s, "/projects/app/.claude/settings.json")}

	p.Unknown([]model.Unknown{
		{Key: key("notARealSetting"), Origin: origin},
		{Key: key(canary), Origin: origin},
	})

	want := "unknown settings (2)\n" +
		"  notARealSetting  claude project  /projects/app/.claude/settings.json\n" +
		"  REDACTED:test_token  claude project  /projects/app/.claude/settings.json\n"
	if out.String() != want {
		t.Errorf("stdout =\n%s\nwant\n%s", out.String(), want)
	}
}

func TestUnknownSettingsShowTheNearKeyOrNote(t *testing.T) {
	p, s, out, _ := setup(t)
	key := func(raw string) redact.Text { v, _ := s.Scrub(raw); return v }
	origin := model.Origin{Agent: model.AgentClaude, Scope: model.ScopeUser, File: model.NewPath(s, "/h/.claude/settings.json")}

	p.Unknown([]model.Unknown{
		{Key: key("permisions"), Near: key("permissions"), Origin: origin},
		{Key: key("ignorePatterns"), Note: key("deprecated: replaced by permissions.deny"), Origin: origin},
	})

	want := "unknown settings (2)\n" +
		"  permisions  claude user  /h/.claude/settings.json  did you mean permissions?\n" +
		"  ignorePatterns  claude user  /h/.claude/settings.json  deprecated: replaced by permissions.deny\n"
	if out.String() != want {
		t.Errorf("stdout =\n%s\nwant\n%s", out.String(), want)
	}
}

func TestProjectsListingShowsInstructions(t *testing.T) {
	p, s, out, _ := setup(t)
	text := func(raw string) redact.Text { v, _ := s.Scrub(raw); return v }
	path := func(raw string) model.Path { return model.NewPath(s, raw) }
	at := func(scope model.Scope) model.Origin {
		return model.Origin{Agent: model.AgentClaude, Scope: scope, InEffect: true}
	}
	waits := at(model.ScopeProject)
	waits.InEffect, waits.Why = false, text("external import: needs approval")

	p.Projects([]model.Project{{
		Path: path("/projects/app"), Status: model.ProjectOK, Origins: []model.Origin{{Agent: model.AgentClaude}},
		Instructions: []model.Instruction{
			{Kind: model.InstructionFile, Path: path("/projects/app/CLAUDE.md"), Load: model.LoadLaunch, Read: model.ReadOK, Origin: at(model.ScopeProject)},
			{Kind: model.InstructionImport, Path: path("/projects/shared.md"), Load: model.LoadLaunch, Read: model.ReadOK,
				ImportedBy: path("/projects/app/CLAUDE.md"), Depth: 1, Origin: waits},
			{Kind: model.InstructionImport, Path: path("/projects/app/.env"), Load: model.LoadLaunch, Read: model.ReadCredential,
				ImportedBy: path("/projects/app/CLAUDE.md"), Depth: 1, Origin: at(model.ScopeProject)},
		},
	}})

	want := "projects (1)\n" +
		"  /projects/app  claude\n" +
		"    claude instructions\n" +
		"      instructions  CLAUDE.md  project, at launch\n" +
		"      import  /projects/shared.md  project, at launch, via CLAUDE.md  not in effect: external import: needs approval\n" +
		"      import  .env  project, at launch, via CLAUDE.md, credential file, not read\n"
	if out.String() != want {
		t.Errorf("stdout =\n%s\nwant\n%s", out.String(), want)
	}
}

func TestUnboundInstructionsListing(t *testing.T) {
	p, s, out, _ := setup(t)
	origin := model.Origin{Agent: model.AgentClaude, Scope: model.ScopeUser, InEffect: true}

	p.Instructions([]model.Instruction{
		{Kind: model.InstructionMemory, Path: model.NewPath(s, "/home/.claude/projects/x/memory/MEMORY.md"), Load: model.LoadLaunch, Read: model.ReadOK, Origin: origin},
	})

	want := "instructions not tied to a project (1)\n" +
		"  claude memory  /home/.claude/projects/x/memory/MEMORY.md  user, at launch\n"
	if out.String() != want {
		t.Errorf("stdout =\n%s\nwant\n%s", out.String(), want)
	}
}

func TestProjectsListingShowsExtensions(t *testing.T) {
	p, s, out, _ := setup(t)
	text := func(raw string) redact.Text { v, _ := s.Scrub(raw); return v }
	path := func(raw string) model.Path { return model.NewPath(s, raw) }
	at := func(scope model.Scope) model.Origin {
		return model.Origin{Agent: model.AgentClaude, Scope: scope, InEffect: true}
	}
	off := at(model.ScopeProject)
	off.InEffect, off.Why = false, text("disableAllHooks is on in user settings")

	p.Projects([]model.Project{{
		Path: path("/projects/app"), Status: model.ProjectOK, Origins: []model.Origin{{Agent: model.AgentClaude}},
		Hooks: []model.Hook{
			{Event: text("PostToolUse"), Matcher: text("Edit|Write"), Type: text("command"), Run: text("${CLAUDE_PROJECT_DIR}/check.sh"),
				Script: path("/projects/app/check.sh"), ScriptRead: model.ReadOK, Origin: at(model.ScopeUser)},
			{Event: text("Stop"), Type: text("http"), Run: text("http://localhost:8080/hook"), Origin: off},
		},
		Skills: []model.Skill{
			{Kind: model.SkillSkill, Name: text("deploy"), Path: path("/projects/app/.claude/skills/deploy/SKILL.md"), Load: model.LoadInvoked,
				Read: model.ReadOK, Tools: []redact.Text{text("Bash(*)")}, Hooks: text("Stop: []"), ShellCommands: 2, Origin: at(model.ScopeProject)},
			{Kind: model.SkillSubagent, Name: text("fmt:rev"), Path: path("/home/.claude/plugins/rev.md"), Load: model.LoadInvoked,
				Read: model.ReadOK, Mode: text("bypassPermissions"), Plugin: text("fmt@m"), Origin: at(model.ScopePlugin)},
		},
		Plugins: []model.Plugin{
			{ID: text("fmt@m"), Version: text("1.0.0"), Path: path("/home/.claude/plugins/cache/fmt"), Origin: at(model.ScopeUser)},
		},
	}})

	want := "projects (1)\n" +
		"  /projects/app  claude\n" +
		"    claude hooks\n" +
		"      PostToolUse (Edit|Write)  command  ${CLAUDE_PROJECT_DIR}/check.sh  user, script check.sh\n" +
		"      Stop  http  http://localhost:8080/hook  project  not in effect: disableAllHooks is on in user settings\n" +
		"    claude skills\n" +
		"      skill  deploy  .claude/skills/deploy/SKILL.md  project, when invoked, pre-approves Bash(*), declares hooks, runs 2 shell commands\n" +
		"      subagent  fmt:rev  /home/.claude/plugins/rev.md  plugin, when invoked, from fmt@m, mode bypassPermissions\n" +
		"    claude plugins\n" +
		"      fmt@m  user, version 1.0.0, /home/.claude/plugins/cache/fmt\n"
	if out.String() != want {
		t.Errorf("stdout =\n%s\nwant\n%s", out.String(), want)
	}
}

func TestPermissionsListingShowsOptions(t *testing.T) {
	p, s, out, _ := setup(t)
	text := func(raw string) redact.Text { v, _ := s.Scrub(raw); return v }
	at := func(scope model.Scope) model.Origin {
		return model.Origin{Agent: model.AgentCodex, Scope: scope, InEffect: true}
	}
	off := at(model.ScopeUser)
	off.InEffect, off.Why = false, text("sandbox_mode is set in .codex/config.toml, so Codex ignores default_permissions")

	p.Projects([]model.Project{{
		Path: model.NewPath(s, "/projects/app"), Status: model.ProjectOK, Origins: []model.Origin{{Agent: model.AgentCodex}},
		Permissions: []model.Permissions{{
			Agent: model.AgentCodex,
			Options: []model.Option{
				{Key: text("sandbox_mode"), Setting: model.Setting[redact.Text]{Layers: []model.Layer[redact.Text]{{Value: text("danger-full-access"), Origin: at(model.ScopeProject)}}}},
				{Key: text("default_permissions"), Setting: model.Setting[redact.Text]{Layers: []model.Layer[redact.Text]{{Value: text("locked"), Origin: off}}}},
			},
			Rules: []model.PermissionRule{{Action: model.RuleDeny, Rule: text("locked ~/.ssh"), Origin: off}},
		}},
	}})

	want := "projects (1)\n" +
		"  /projects/app  codex\n" +
		"    codex permissions\n" +
		"      sandbox_mode = danger-full-access  project\n" +
		"      default_permissions = locked  user  not in effect: sandbox_mode is set in .codex/config.toml, so Codex ignores default_permissions\n" +
		"      deny   locked ~/.ssh  user  not in effect: sandbox_mode is set in .codex/config.toml, so Codex ignores default_permissions\n"
	if out.String() != want {
		t.Errorf("stdout =\n%s\nwant\n%s", out.String(), want)
	}
}

func TestListingsShowLimitsAndNotes(t *testing.T) {
	p, s, out, _ := setup(t)
	text := func(raw string) redact.Text { v, _ := s.Scrub(raw); return v }
	at := model.Origin{Agent: model.AgentCodex, Scope: model.ScopeProject, InEffect: true}

	p.Projects([]model.Project{{
		Path: model.NewPath(s, "/projects/app"), Status: model.ProjectOK, Origins: []model.Origin{{Agent: model.AgentCodex}},
		Instructions: []model.Instruction{{Kind: model.InstructionFile, Path: model.NewPath(s, "/projects/app/AGENTS.md"),
			Load: model.LoadLaunch, Read: model.ReadOK, Limit: 100, Note: text("cut under the combined reading"), Origin: at}},
		Hooks: []model.Hook{{Event: text("Stop"), Type: text("command"), Run: text("notify"), Note: text("waits for review in /hooks"), Origin: at}},
	}})

	want := "projects (1)\n" +
		"  /projects/app  codex\n" +
		"    codex instructions\n" +
		"      instructions  AGENTS.md  project, at launch, first 100 bytes  note: cut under the combined reading\n" +
		"    codex hooks\n" +
		"      Stop  command  notify  project  note: waits for review in /hooks\n"
	if out.String() != want {
		t.Errorf("stdout =\n%s\nwant\n%s", out.String(), want)
	}
}
