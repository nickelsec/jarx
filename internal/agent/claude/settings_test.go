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

// project builds an ok project at the fake home's /p with the given trust.
func project(c agent.Context, trust model.TrustLevel) model.Project {
	p := model.Project{Path: model.NewPath(c.Scrub, c.Env.MapPath("/p")), Status: model.ProjectOK}
	if trust != "" {
		p.Trust = []model.Trust{{Level: trust, Origin: model.Origin{Agent: model.AgentClaude}}}
	}
	return p
}

func settingsFor(t *testing.T, c agent.Context, trust model.TrustLevel) (model.Permissions, []model.Unknown, []finding.Finding) {
	t.Helper()
	ps := []model.Project{project(c, trust)}
	unknown, fs := Adapter{}.Settings(c, ps)
	for _, perm := range ps[0].Permissions {
		if perm.Agent == model.AgentClaude {
			return perm, unknown, fs
		}
	}
	return model.Permissions{}, unknown, fs
}

type ruleView struct {
	action   model.RuleAction
	rule     string
	scope    model.Scope
	inEffect bool
}

func rules(p model.Permissions) []ruleView {
	out := make([]ruleView, 0, len(p.Rules))
	for _, r := range p.Rules {
		out = append(out, ruleView{r.Action, r.Rule.String(), r.Origin.Scope, r.Origin.InEffect})
	}
	return out
}

func findRule(t *testing.T, p model.Permissions, rule string, scope model.Scope) model.PermissionRule {
	t.Helper()
	for _, r := range p.Rules {
		if r.Rule.String() == rule && r.Origin.Scope == scope {
			return r
		}
	}
	t.Fatalf("no %s rule %q in %+v", scope, rule, rules(p))
	return model.PermissionRule{}
}

func TestUserSettingsRulesApplyEverywhere(t *testing.T) {
	c := fakeHome(t, map[string]string{
		".claude/settings.json": `{"permissions": {
			"allow": ["Bash(git *)"], "ask": ["Bash(rm *)"], "deny": ["Read(./.env)"]
		}}`,
	})

	perm, _, fs := settingsFor(t, c, model.TrustUntrusted)

	want := []ruleView{
		{model.RuleAllow, "Bash(git *)", model.ScopeUser, true},
		{model.RuleAsk, "Bash(rm *)", model.ScopeUser, true},
		{model.RuleDeny, "Read(./.env)", model.ScopeUser, true},
	}
	if got := rules(perm); !slices.Equal(got, want) {
		t.Errorf("rules = %+v, want %+v", got, want)
	}
	if f := perm.Rules[0].Origin.File.Raw(); f != filepath.Join(c.Env.Home, ".claude", "settings.json") {
		t.Errorf("origin file = %s, want ~/.claude/settings.json", f)
	}
	if len(fs) != 0 {
		t.Errorf("findings = %+v, want none", fs)
	}
}

func TestClaudeConfigDirMovesUserSettings(t *testing.T) {
	c := fakeHome(t, map[string]string{
		".jarx-env":             "CLAUDE_CONFIG_DIR=/cfg\n",
		"cfg/settings.json":     `{"permissions": {"deny": ["Read(from-config-dir)"]}}`,
		".claude/settings.json": `{"permissions": {"deny": ["Read(from-home)"]}}`,
	})

	perm, _, _ := settingsFor(t, c, model.TrustTrusted)

	want := []ruleView{{model.RuleDeny, "Read(from-config-dir)", model.ScopeUser, true}}
	if got := rules(perm); !slices.Equal(got, want) {
		t.Errorf("rules = %+v, want only the CLAUDE_CONFIG_DIR one", got)
	}
}

func TestDefaultModeLayersGoLocalProjectUser(t *testing.T) {
	c := fakeHome(t, map[string]string{
		".claude/settings.json":         `{"permissions": {"defaultMode": "plan"}}`,
		"p/.claude/settings.json":       `{"permissions": {"defaultMode": "acceptEdits"}}`,
		"p/.claude/settings.local.json": `{"permissions": {"defaultMode": "default"}}`,
	})

	perm, _, _ := settingsFor(t, c, model.TrustTrusted)

	got := make([]string, 0, len(perm.DefaultMode.Layers))
	for _, l := range perm.DefaultMode.Layers {
		got = append(got, string(l.Origin.Scope)+"="+l.Value.String())
	}
	if want := []string{"local=default", "project=acceptEdits", "user=plan"}; !slices.Equal(got, want) {
		t.Errorf("layers = %q, want %q", got, want)
	}
	if eff, ok := perm.DefaultMode.Effective(); !ok || eff.Value.String() != "default" {
		t.Errorf("effective = %+v, want the local default", eff)
	}
}

func TestBypassAndAutoAreIgnoredFromProjectAndLocalFiles(t *testing.T) {
	for _, mode := range []string{"bypassPermissions", "auto"} {
		for _, file := range []string{"p/.claude/settings.json", "p/.claude/settings.local.json"} {
			t.Run(mode+" in "+file, func(t *testing.T) {
				c := fakeHome(t, map[string]string{
					".claude/settings.json": `{"permissions": {"defaultMode": "plan"}}`,
					file:                    `{"permissions": {"defaultMode": "` + mode + `"}}`,
				})

				perm, _, _ := settingsFor(t, c, model.TrustTrusted)

				top := perm.DefaultMode.Layers[0]
				if top.Value.String() != mode || top.Origin.InEffect || !strings.Contains(top.Origin.Why.String(), "ignored") {
					t.Errorf("top layer = %+v, want %s listed, not in effect, with why", top, mode)
				}
				if eff, _ := perm.DefaultMode.Effective(); eff.Value.String() != "plan" {
					t.Errorf("effective = %q, want the user plan", eff.Value.String())
				}
			})
		}
	}
}

func TestBypassFromUserSettingsIsInEffect(t *testing.T) {
	c := fakeHome(t, map[string]string{
		".claude/settings.json": `{"permissions": {"defaultMode": "bypassPermissions"}}`,
	})

	perm, _, _ := settingsFor(t, c, model.TrustUntrusted)

	if eff, ok := perm.DefaultMode.Effective(); !ok || eff.Value.String() != "bypassPermissions" {
		t.Errorf("effective = %+v, want bypassPermissions from user", eff)
	}
}

func TestProjectAndLocalAllowsWaitForTrust(t *testing.T) {
	files := map[string]string{
		"p/.claude/settings.json": `{"permissions": {
			"allow": ["Bash(*)"], "ask": ["Bash(curl *)"], "deny": ["Read(~/.ssh/**)"],
			"additionalDirectories": ["../shared"]
		}}`,
		"p/.claude/settings.local.json": `{"permissions": {"allow": ["Bash(make *)"]}}`,
	}
	for _, tc := range []struct {
		trust    model.TrustLevel
		allowsOn bool
	}{
		{model.TrustTrusted, true},
		{model.TrustUntrusted, false},
		{model.TrustUnknown, false},
		{"", false}, // no record at all
	} {
		t.Run(string(tc.trust), func(t *testing.T) {
			perm, _, _ := settingsFor(t, fakeHome(t, files), tc.trust)

			for _, r := range []model.PermissionRule{
				findRule(t, perm, "Bash(*)", model.ScopeProject),
				findRule(t, perm, "Bash(make *)", model.ScopeLocal),
			} {
				if r.Origin.InEffect != tc.allowsOn {
					t.Errorf("%s allow in effect = %v, want %v", r.Origin.Scope, r.Origin.InEffect, tc.allowsOn)
				}
				if !tc.allowsOn && !strings.Contains(r.Origin.Why.String(), "trust") {
					t.Errorf("%s allow why = %q, want it to name trust", r.Origin.Scope, r.Origin.Why)
				}
			}
			for _, rule := range []string{"Bash(curl *)", "Read(~/.ssh/**)"} {
				if r := findRule(t, perm, rule, model.ScopeProject); !r.Origin.InEffect {
					t.Errorf("%s in effect = false, want ask and deny to apply right away", rule)
				}
			}
			if len(perm.AdditionalDirectories) != 1 || perm.AdditionalDirectories[0].Origin.InEffect != tc.allowsOn {
				t.Errorf("additionalDirectories = %+v, want one, in effect %v", perm.AdditionalDirectories, tc.allowsOn)
			}
		})
	}
}

func TestLocalAllowsInTheConfigHomeSkipTrust(t *testing.T) {
	c := fakeHome(t, map[string]string{
		".claude/settings.local.json": `{"permissions": {"allow": ["Bash(ls)"]}}`,
	})
	ps := []model.Project{{Path: model.NewPath(c.Scrub, c.Env.Home), Status: model.ProjectOK}}

	Adapter{}.Settings(c, ps)

	if len(ps[0].Permissions) != 1 {
		t.Fatalf("permissions = %+v, want claude's", ps[0].Permissions)
	}
	r := findRule(t, ps[0].Permissions[0], "Bash(ls)", model.ScopeLocal)
	if !r.Origin.InEffect {
		t.Errorf("home local allow = %+v, want in effect without trust", r.Origin)
	}
}

func TestProjectsThatAreNotOKAreNotRead(t *testing.T) {
	c := fakeHome(t, map[string]string{
		"p/.claude/settings.json": `{"permissions": {"allow": ["Bash(*)"]}}`,
	})
	ps := []model.Project{project(c, model.TrustTrusted)}
	ps[0].Status = model.ProjectStale

	Adapter{}.Settings(c, ps)

	if len(ps[0].Permissions) != 0 {
		t.Errorf("permissions = %+v, want none for a stale project", ps[0].Permissions)
	}
}

func TestSecretsInRulesAreMasked(t *testing.T) {
	c := fakeHome(t, map[string]string{
		"p/.claude/settings.json": `{"permissions": {"allow": ["Bash(curl -H 'x: ` + canary + `' *)"]}}`,
	})

	perm, _, _ := settingsFor(t, c, model.TrustTrusted)

	if out := fmt.Sprintf("%+v", perm); strings.Contains(out, canary) || !strings.Contains(out, "REDACTED:test_token") {
		t.Errorf("permissions = %s, want the token masked", out)
	}
}

func TestUnknownKeysAreReportedWithTheirFile(t *testing.T) {
	c := fakeHome(t, map[string]string{
		"p/.claude/settings.json": `{"notARealSetting": 1, "model": "x", "permissions": {"bogus": [], "allow": []}}`,
	})

	_, unknown, _ := settingsFor(t, c, model.TrustTrusted)

	got := make([]string, 0, len(unknown))
	for _, u := range unknown {
		got = append(got, u.Key.String()+"@"+string(u.Origin.Scope))
	}
	slices.Sort(got)
	if want := []string{"notARealSetting@project", "permissions.bogus@project"}; !slices.Equal(got, want) {
		t.Errorf("unknown = %q, want %q", got, want)
	}
}

func TestUserSettingsUnknownKeysAreReportedOnce(t *testing.T) {
	c := fakeHome(t, map[string]string{".claude/settings.json": `{"notARealSetting": 1}`})
	ps := []model.Project{project(c, model.TrustTrusted), project(c, model.TrustTrusted)}

	unknown, _ := Adapter{}.Settings(c, ps)

	if len(unknown) != 1 {
		t.Errorf("unknown = %+v, want the user key once", unknown)
	}
}

func TestBrokenSettingsAreAFindingWithoutContent(t *testing.T) {
	for name, body := range map[string]string{
		"comment":        "{\n  // " + plainSecret + "\n  \"model\": \"x\"\n}",
		"trailing comma": `{"permissions": {"allow": ["` + plainSecret + `",]}}`,
		"not an object":  `["` + plainSecret + `"]`,
	} {
		t.Run(name, func(t *testing.T) {
			c := fakeHome(t, map[string]string{"p/.claude/settings.json": body})

			perm, _, fs := settingsFor(t, c, model.TrustTrusted)

			if len(perm.Rules) != 0 {
				t.Errorf("rules = %+v, want none from a broken file", rules(perm))
			}
			if len(fs) != 1 || fs[0].RuleID != finding.UnreadableRecord().ID {
				t.Fatalf("findings = %+v, want one %s", fs, finding.UnreadableRecord().ID)
			}
			if out := fmt.Sprintf("%+v", fs); strings.Contains(out, plainSecret) {
				t.Errorf("finding leaks file content: %s", out)
			}
		})
	}
}

func TestBadValuesAreSkippedWithAFinding(t *testing.T) {
	c := fakeHome(t, map[string]string{
		"p/.claude/settings.json": `{"permissions": {
			"allow": "Bash(*)", "deny": ["Read(a)", 7], "defaultMode": 3
		}}`,
	})

	perm, _, fs := settingsFor(t, c, model.TrustTrusted)

	want := []ruleView{{model.RuleDeny, "Read(a)", model.ScopeProject, true}}
	if got := rules(perm); !slices.Equal(got, want) {
		t.Errorf("rules = %+v, want only the good entry", got)
	}
	if len(perm.DefaultMode.Layers) != 0 {
		t.Errorf("defaultMode = %+v, want none", perm.DefaultMode.Layers)
	}
	if len(fs) != 3 {
		t.Errorf("findings = %+v, want one per bad value", fs)
	}
}

func TestNoSettingsFilesMeansOnlyTheStartMode(t *testing.T) {
	c := fakeHome(t, nil)
	ps := []model.Project{project(c, model.TrustTrusted)}

	unknown, fs := Adapter{}.Settings(c, ps)

	if len(ps[0].Permissions) != 1 || len(unknown) != 0 || len(fs) != 0 {
		t.Fatalf("Settings() = %+v, %+v, %+v; want one Claude permissions entry and nothing else", ps[0].Permissions, unknown, fs)
	}
	perm := ps[0].Permissions[0]
	if len(perm.Rules) != 0 || len(perm.DefaultMode.Layers) != 0 || len(perm.Options) != 0 || len(perm.Env) != 0 || perm.StartMode.String() != "auto" {
		t.Errorf("permissions = %+v, want no rules or layers, and a session that starts in auto", perm)
	}
}

func TestEachSettingsFileIsKeptScrubbedForTheSecretsScan(t *testing.T) {
	c := fakeHome(t, map[string]string{
		".claude/settings.json":   `{"env": {"DEPLOY": "` + canary + `"}}`,
		"p/.claude/settings.json": `{"permissions": {"allow": ["Read"]}}`,
	})
	ps := []model.Project{project(c, model.TrustTrusted)}

	Adapter{}.Settings(c, ps)

	got := map[model.Scope]model.Config{}
	for _, cfg := range ps[0].Configs {
		got[cfg.Origin.Scope] = cfg
	}
	user, project := got[model.ScopeUser], got[model.ScopeProject]
	if strings.Contains(user.Text.String(), canary) || len(user.Text.Secrets()) != 1 {
		t.Errorf("user config = %q with %d secrets, want the token masked and counted", user.Text, len(user.Text.Secrets()))
	}
	if !strings.Contains(project.Text.String(), `"Read"`) || len(ps[0].Configs) != 2 {
		t.Errorf("configs = %+v, want the user and project files", ps[0].Configs)
	}
}

func TestRulesKeepWhatTheyApplyTo(t *testing.T) {
	c := fakeHome(t, map[string]string{
		".claude/settings.json": `{"permissions": {"allow": ["Read(~/.aws/**)", "Bash", "Bash(npm run:*)", "mcp__github__get_issue"]}}`,
	})

	perm, _, _ := settingsFor(t, c, model.TrustTrusted)

	for rule, want := range map[string]string{
		"Read(~/.aws/**)":        "~/.aws/**",
		"Bash":                   "",
		"Bash(npm run:*)":        "npm run:*",
		"mcp__github__get_issue": "",
	} {
		if got := findRule(t, perm, rule, model.ScopeUser).Target.String(); got != want {
			t.Errorf("%s target = %q, want %q", rule, got, want)
		}
	}
}
