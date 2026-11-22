package claude

import (
	"strings"
	"testing"

	"github.com/nickelsec/jarx/internal/model"
)

const sandboxUser = `{"sandbox": {"enabled": true, "autoAllowBashIfSandboxed": true,
	"filesystem": {"denyRead": ["~/.ssh"], "allowWrite": ["~/build"], "allowRead": ["~/.ssh/config"], "denyWrite": ["/etc"]}}}`

func TestSandboxPathsAreRulesWhenItRuns(t *testing.T) {
	c := fakeHome(t, map[string]string{".claude/settings.json": sandboxUser})
	c.Env.GOOS = "linux"

	perm, _, _ := settingsFor(t, c, model.TrustTrusted)

	for rule, want := range map[string]struct {
		action model.RuleAction
		target string
	}{
		"sandbox.filesystem.denyRead ~/.ssh":         {model.RuleDeny, "~/.ssh"},
		"sandbox.filesystem.allowWrite ~/build":      {model.RuleWrite, "~/build"},
		"sandbox.filesystem.allowRead ~/.ssh/config": {model.RuleRead, "~/.ssh/config"},
		"sandbox.filesystem.denyWrite /etc":          {model.RuleDeny, "/etc"},
	} {
		r := findRule(t, perm, rule, model.ScopeUser)
		if r.Action != want.action || r.Target.String() != want.target || !r.Origin.InEffect {
			t.Errorf("%s = %+v, want %s on %s, in effect", rule, r, want.action, want.target)
		}
	}
	if o, ok := optionNamed(perm, "sandbox.autoAllowBashIfSandboxed"); !ok || len(o.Setting.InEffect()) != 1 {
		t.Errorf("autoAllowBashIfSandboxed option = %+v, want in effect", o)
	}
}

func TestSandboxPathsDontApplyWhenItIsOff(t *testing.T) {
	for name, tc := range map[string]struct {
		goos, body, why string
	}{
		"not enabled":    {"linux", `{"sandbox": {"filesystem": {"denyRead": ["~/.ssh"]}}}`, "sandbox.enabled"},
		"native windows": {"windows", sandboxUser, "Windows"},
	} {
		c := fakeHome(t, map[string]string{".claude/settings.json": tc.body})
		c.Env.GOOS = tc.goos

		perm, _, _ := settingsFor(t, c, model.TrustTrusted)

		r := findRule(t, perm, "sandbox.filesystem.denyRead ~/.ssh", model.ScopeUser)
		if r.Origin.InEffect || !strings.Contains(r.Origin.Why.String(), tc.why) {
			t.Errorf("%s: denyRead in effect = %v (%q), want off with a reason about %s", name, r.Origin.InEffect, r.Origin.Why, tc.why)
		}
	}
}

func TestTheHighestSandboxEnabledWins(t *testing.T) {
	c := fakeHome(t, map[string]string{
		".claude/settings.json":   sandboxUser,
		"p/.claude/settings.json": `{"sandbox": {"enabled": false}}`,
	})
	c.Env.GOOS = "linux"

	perm, _, _ := settingsFor(t, c, model.TrustTrusted)

	if r := findRule(t, perm, "sandbox.filesystem.denyRead ~/.ssh", model.ScopeUser); r.Origin.InEffect {
		t.Error("denyRead in effect, want off: the project turns the sandbox off")
	}
}

func TestEnableAllProjectMcpServersIsAnOptionThatWaitsForTrust(t *testing.T) {
	c := fakeHome(t, map[string]string{"p/.claude/settings.json": `{"enableAllProjectMcpServers": true}`})

	trusted, _, _ := settingsFor(t, c, model.TrustTrusted)
	untrusted, _, _ := settingsFor(t, c, model.TrustUntrusted)

	if o, ok := optionNamed(trusted, "enableAllProjectMcpServers"); !ok || len(o.Setting.InEffect()) != 1 {
		t.Errorf("trusted option = %+v, want in effect", o)
	}
	if o, ok := optionNamed(untrusted, "enableAllProjectMcpServers"); !ok || len(o.Setting.InEffect()) != 0 {
		t.Errorf("untrusted option = %+v, want it to wait for trust", o)
	}
}

func TestRepoSandboxGrantsWaitForTrust(t *testing.T) {
	c := fakeHome(t, map[string]string{
		".claude/settings.json":   `{"sandbox": {"enabled": true}}`,
		"p/.claude/settings.json": `{"sandbox": {"filesystem": {"allowWrite": ["~"], "denyRead": ["~/.aws"]}}}`,
	})
	c.Env.GOOS = "linux"

	perm, _, _ := settingsFor(t, c, model.TrustUntrusted)

	if r := findRule(t, perm, "sandbox.filesystem.allowWrite ~", model.ScopeProject); r.Origin.InEffect {
		t.Error("an untrusted repo's allowWrite is in effect, want it to wait for trust")
	}
	if r := findRule(t, perm, "sandbox.filesystem.denyRead ~/.aws", model.ScopeProject); !r.Origin.InEffect {
		t.Errorf("denyRead off (%q), want it to apply right away like other deny rules", r.Origin.Why)
	}
}
