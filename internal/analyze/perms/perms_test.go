package perms

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/nickelsec/jarx/internal/catalog"
	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/platform"
	"github.com/nickelsec/jarx/internal/redact"
)

func TestCommandPatternsAreClassified(t *testing.T) {
	cmds, err := catalog.Commands()
	if err != nil {
		t.Fatal(err)
	}
	for pattern, want := range map[string]catalog.CommandClass{
		"python *":                    catalog.RunsAnything,
		"python:*":                    catalog.RunsAnything,
		"/usr/bin/python3.12 *":       catalog.RunsAnything,
		"python3 -c *":                catalog.RunsAnything,
		"C:\\Python312\\python.exe *": catalog.RunsAnything,
		"sudo *":                      catalog.RunsAnything,
		"env *":                       catalog.RunsAnything,
		"npm *":                       catalog.RunsAnything,
		"npm exec *":                  catalog.RunsAnything,
		"docker run *":                catalog.RunsAnything,
		"python scripts/build.py *":   catalog.RunsRepoCode,
		"python -m pytest *":          catalog.RunsRepoCode,
		"npm run *":                   catalog.RunsRepoCode,
		"npm test":                    catalog.RunsRepoCode,
		"make *":                      catalog.RunsRepoCode,
		"make test":                   catalog.RunsRepoCode,
		"cargo test *":                catalog.RunsRepoCode,
		"docker compose up *":         catalog.RunsRepoCode,
		"./scripts/test.sh *":         catalog.RunsRepoCode,
		"scripts/lint":                catalog.RunsRepoCode,
		"git *":                       catalog.HasEscape,
		"git:*":                       catalog.HasEscape,
		"python --version":            "",
		"python":                      "",
		"npm ls":                      "",
		"git status":                  "",
		"git log *":                   "",
		"docker ps":                   "",
		"timeout *":                   "",
		"echo *":                      "",
		"npx prettier *":              "",
		"* --help":                    "",
	} {
		if got, _ := classify(cmds, pattern); got != want {
			t.Errorf("classify(%q) = %q, want %q", pattern, got, want)
		}
	}
}

// fixture builds model values with a scrubber and a fake home.
type fixture struct {
	t    *testing.T
	s    *redact.Scrubber
	env  platform.Env
	proj string
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	s, err := redact.New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	env, err := platform.FromHome(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return fixture{t: t, s: s, env: env, proj: filepath.Join(env.Home, "code", "app")}
}

func (f fixture) text(v string) redact.Text {
	t, _ := f.s.Scrub(v)
	return t
}

func (f fixture) origin(agent model.Agent, scope model.Scope, file string) model.Origin {
	return model.Origin{Agent: agent, Scope: scope, File: model.NewPath(f.s, file), InEffect: true}
}

func (f fixture) userFile() string { return filepath.Join(f.env.Home, ".claude", "settings.json") }

func (f fixture) projectFile() string { return filepath.Join(f.proj, ".claude", "settings.json") }

// claudeRule is a Claude rule from the user's settings.
func (f fixture) claudeRule(action model.RuleAction, rule string) model.PermissionRule {
	target := ""
	if i := strings.IndexByte(rule, '('); i >= 0 && strings.HasSuffix(rule, ")") {
		target = rule[i+1 : len(rule)-1]
	}
	return model.PermissionRule{Action: action, Rule: f.text(rule), Target: f.text(target), Origin: f.origin(model.AgentClaude, model.ScopeUser, f.userFile())}
}

func (f fixture) project(perms ...model.Permissions) model.Project {
	return model.Project{Path: model.NewPath(f.s, f.proj), Status: model.ProjectOK, Permissions: perms}
}

func (f fixture) claude(rules ...model.PermissionRule) model.Permissions {
	return model.Permissions{Agent: model.AgentClaude, Rules: rules}
}

func (f fixture) option(agent model.Agent, key, value string, scope model.Scope, file string) model.Option {
	return model.Option{Key: f.text(key), Setting: model.Setting[redact.Text]{Layers: []model.Layer[redact.Text]{
		{Value: f.text(value), Origin: f.origin(agent, scope, file)},
	}}}
}

func (f fixture) analyze(ps ...model.Project) []finding.Finding {
	f.t.Helper()
	got, err := Analyze(f.s, f.env, ps)
	if err != nil {
		f.t.Fatal(err)
	}
	return got
}

func ids(fs []finding.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, x := range fs {
		out = append(out, x.RuleID)
	}
	slices.Sort(out)
	return out
}

func findID(fs []finding.Finding, id string) (finding.Finding, bool) {
	for _, x := range fs {
		if x.RuleID == id {
			return x, true
		}
	}
	return finding.Finding{}, false
}

func TestAllowsThatRunMoreThanTheyLook(t *testing.T) {
	f := newFixture(t)
	for rule, want := range map[string]string{
		"Bash":                   "JARX-PERMS-004",
		"Bash(*)":                "JARX-PERMS-004",
		"PowerShell":             "JARX-PERMS-004",
		"Bash(python *)":         "JARX-PERMS-008",
		"PowerShell(node *)":     "JARX-PERMS-008",
		"Bash(npm run *)":        "JARX-PERMS-009",
		"Bash(git *)":            "JARX-PERMS-010",
		"Bash(git status)":       "",
		"Read(./src/**)":         "",
		"mcp__github__get_issue": "",
	} {
		got := f.analyze(f.project(f.claude(f.claudeRule(model.RuleAllow, rule))))
		switch {
		case want == "" && len(got) != 0:
			t.Errorf("%s: findings = %q, want none", rule, ids(got))
		case want != "" && !slices.Equal(ids(got), []string{want}):
			t.Errorf("%s: findings = %q, want [%s]", rule, ids(got), want)
		}
	}
}

func TestTheWhyComesFromTheCommandTable(t *testing.T) {
	f := newFixture(t)

	got := f.analyze(f.project(f.claude(f.claudeRule(model.RuleAllow, "Bash(git *)"))))

	if x, ok := findID(got, "JARX-PERMS-010"); !ok || !strings.Contains(x.Evidence.String(), "git -c and aliases") {
		t.Errorf("evidence = %q, want git's own why", x.Evidence)
	}
}

func TestOnlyAllowsInEffectCount(t *testing.T) {
	f := newFixture(t)
	r := f.claudeRule(model.RuleAllow, "Bash(*)")
	r.Origin.InEffect, r.Origin.Why = false, f.text("project allow waits for trust")
	deny := f.claudeRule(model.RuleDeny, "Bash(python *)")

	if got := f.analyze(f.project(f.claude(r, deny))); len(got) != 0 {
		t.Errorf("findings = %q, want none: the allow isn't in effect and denies don't grant", ids(got))
	}
}

func TestSkillAllowedToolsCount(t *testing.T) {
	f := newFixture(t)
	p := f.project()
	p.Skills = []model.Skill{{
		Kind: model.SkillSkill, Name: f.text("release"), Tools: []redact.Text{f.text("Bash(git *)"), f.text("Read")},
		Origin: f.origin(model.AgentClaude, model.ScopeProject, filepath.Join(f.proj, ".claude", "skills", "release", "SKILL.md")),
	}}

	got := f.analyze(p)

	if !slices.Equal(ids(got), []string{"JARX-PERMS-005", "JARX-PERMS-010"}) {
		t.Errorf("findings = %q, want git's escape and Read covering credential files", ids(got))
	}
	if x, _ := findID(got, "JARX-PERMS-010"); !strings.Contains(x.Evidence.String(), "release") {
		t.Errorf("evidence = %q, want the skill named", x.Evidence)
	}
}

func TestGrantsThatCoverCredentialFiles(t *testing.T) {
	f := newFixture(t)
	for name, tc := range map[string]struct {
		rule model.PermissionRule
		hit  bool
		sees string
	}{
		"home aws":            {f.claudeRule(model.RuleAllow, "Read(~/.aws/**)"), true, "credentials"},
		"whole read tool":     {f.claudeRule(model.RuleAllow, "Read"), true, ""},
		"read anything":       {f.claudeRule(model.RuleAllow, "Read(**)"), true, ".env"},
		"absolute home":       {f.claudeRule(model.RuleAllow, "Read(//"+filepath.ToSlash(strings.TrimPrefix(f.env.Home, "/"))+"/**)"), true, ""},
		"edit ssh":            {f.claudeRule(model.RuleAllow, "Edit(~/.ssh/*)"), true, "id_ed25519"},
		"a dir with no glob":  {f.claudeRule(model.RuleAllow, "Read(~/.ssh)"), true, "id_ed25519"},
		"project src":         {f.claudeRule(model.RuleAllow, "Read(./src/**)"), false, ""},
		"home docs":           {f.claudeRule(model.RuleAllow, "Read(~/Documents/**)"), false, ""},
		"a deny isn't access": {f.claudeRule(model.RuleDeny, "Read(~/.aws/**)"), false, ""},
		// /path in user settings is from ~/.claude, per the permissions docs.
		"user settings root": {f.claudeRule(model.RuleAllow, "Read(/.credentials.json)"), true, "claude_login"},
		// ** crosses dirs: .config/gh/hosts.yml is two levels under ~.
		"deep glob": {f.claudeRule(model.RuleAllow, "Read(~/**/hosts.yml)"), true, "hosts.yml"},
	} {
		got := f.analyze(f.project(f.claude(tc.rule)))
		x, ok := findID(got, "JARX-PERMS-005")
		if ok != tc.hit || (ok && !strings.Contains(x.Evidence.String(), tc.sees)) {
			t.Errorf("%s: 005 = %v (%q), want %v mentioning %q", name, ok, x.Evidence, tc.hit, tc.sees)
		}
	}
}

func TestOtherGrantsCanCoverCredentialFiles(t *testing.T) {
	f := newFixture(t)
	home := f.origin(model.AgentClaude, model.ScopeUser, f.userFile())
	codexFile := filepath.Join(f.env.Home, ".codex", "config.toml")
	cases := map[string]model.Permissions{
		"additional dir": {Agent: model.AgentClaude, AdditionalDirectories: []model.Layer[redact.Text]{{Value: f.text("~"), Origin: home}}},
		"sandbox write": {Agent: model.AgentClaude, Rules: []model.PermissionRule{{
			Action: model.RuleWrite, Rule: f.text("sandbox.filesystem.allowWrite ~/.docker"), Target: f.text("~/.docker"), Origin: home,
		}}},
		"codex profile": {Agent: model.AgentCodex, Rules: []model.PermissionRule{{
			Action: model.RuleRead, Rule: f.text("dev " + filepath.Join(f.env.Home, ".kube")), Target: f.text(filepath.Join(f.env.Home, ".kube")),
			Origin: f.origin(model.AgentCodex, model.ScopeUser, codexFile),
		}}},
	}
	for name, perm := range cases {
		if _, ok := findID(f.analyze(f.project(perm)), "JARX-PERMS-005"); !ok {
			t.Errorf("%s: no 005, want the grant to cover a credential file", name)
		}
	}
}

func TestModeAndSandboxSettings(t *testing.T) {
	f := newFixture(t)
	codexFile := filepath.Join(f.env.Home, ".codex", "config.toml")
	for name, tc := range map[string]struct {
		perm model.Permissions
		want []string
	}{
		"claude bypass": {model.Permissions{Agent: model.AgentClaude, DefaultMode: model.Setting[redact.Text]{
			Layers: []model.Layer[redact.Text]{{Value: f.text("bypassPermissions"), Origin: f.origin(model.AgentClaude, model.ScopeUser, f.userFile())}},
		}}, []string{"JARX-PERMS-001"}},
		"codex no sandbox": {model.Permissions{Agent: model.AgentCodex, Options: []model.Option{
			f.option(model.AgentCodex, "sandbox_mode", "danger-full-access", model.ScopeUser, codexFile),
		}}, []string{"JARX-PERMS-002"}},
		"codex full access profile": {model.Permissions{Agent: model.AgentCodex, Options: []model.Option{
			f.option(model.AgentCodex, "default_permissions", ":danger-full-access", model.ScopeUser, codexFile),
		}}, []string{"JARX-PERMS-002"}},
		"codex never": {model.Permissions{Agent: model.AgentCodex, Options: []model.Option{
			f.option(model.AgentCodex, "approval_policy", "never", model.ScopeUser, codexFile),
		}}, []string{"JARX-PERMS-003"}},
		"codex retired policy": {model.Permissions{Agent: model.AgentCodex, Options: []model.Option{
			f.option(model.AgentCodex, "approval_policy", "untrusted", model.ScopeUser, codexFile),
		}}, []string{"JARX-PERMS-007"}},
		"codex deprecated policy": {model.Permissions{Agent: model.AgentCodex, Options: []model.Option{
			f.option(model.AgentCodex, "approval_policy", "on-failure", model.ScopeUser, codexFile),
		}}, []string{"JARX-PERMS-007"}},
		"all project servers": {model.Permissions{Agent: model.AgentClaude, Options: []model.Option{
			f.option(model.AgentClaude, "enableAllProjectMcpServers", "true", model.ScopeProject, f.projectFile()),
		}}, []string{"JARX-PERMS-006"}},
		"codex on-request": {model.Permissions{Agent: model.AgentCodex, Options: []model.Option{
			f.option(model.AgentCodex, "approval_policy", "on-request", model.ScopeUser, codexFile),
		}}, nil},
	} {
		if got := ids(f.analyze(f.project(tc.perm))); !slices.Equal(got, tc.want) {
			t.Errorf("%s: findings = %q, want %q", name, got, tc.want)
		}
	}
}

func TestAShadowedAllowIsntInEffect(t *testing.T) {
	f := newFixture(t)
	for name, tc := range map[string]struct {
		other model.PermissionRule
		why   string
	}{
		"same rule denied":  {f.claudeRule(model.RuleDeny, "Bash(python *)"), "deny"},
		"whole tool denied": {f.claudeRule(model.RuleDeny, "Bash"), "deny"},
		"same rule asked":   {f.claudeRule(model.RuleAsk, "Bash(python *)"), "ask"},
		"star asked":        {f.claudeRule(model.RuleAsk, "Bash(*)"), "ask"},
	} {
		p := f.project(f.claude(f.claudeRule(model.RuleAllow, "Bash(python *)"), tc.other))
		ps := []model.Project{p}

		Settle(f.s, ps)

		a := ps[0].Permissions[0].Rules[0]
		if a.Origin.InEffect || !strings.Contains(a.Origin.Why.String(), tc.why) {
			t.Errorf("%s: allow in effect = %v (%q), want off because of the %s rule", name, a.Origin.InEffect, a.Origin.Why, tc.why)
		}
		if got := f.analyze(ps...); len(got) != 0 {
			t.Errorf("%s: findings = %q, want none for a shadowed allow", name, ids(got))
		}
	}
}

func TestANarrowerDenyDoesntShadowABroadAllow(t *testing.T) {
	f := newFixture(t)
	ps := []model.Project{f.project(f.claude(f.claudeRule(model.RuleAllow, "Bash(*)"), f.claudeRule(model.RuleDeny, "Bash(rm *)")))}

	Settle(f.s, ps)

	if a := ps[0].Permissions[0].Rules[0]; !a.Origin.InEffect {
		t.Errorf("Bash(*) off (%q), want in effect: the deny only covers rm", a.Origin.Why)
	}
}

func TestASharedFileIsReportedOnce(t *testing.T) {
	f := newFixture(t)
	p := f.project(f.claude(f.claudeRule(model.RuleAllow, "Bash(python *)")))

	if got := f.analyze(p, p); len(got) != 1 {
		t.Errorf("findings = %q, want one", ids(got))
	}
}

func TestRulesAreValid(t *testing.T) {
	if _, err := finding.NewRegistry(Rules()...); err != nil {
		t.Fatal(err)
	}
}
