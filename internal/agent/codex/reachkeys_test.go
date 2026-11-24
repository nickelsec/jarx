package codex

import (
	"testing"

	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/platform"
)

// effective is an option's value in effect, or "".
func effective(perm model.Permissions, key string) string {
	for _, o := range perm.Options {
		if o.Key.String() == key {
			if eff, ok := o.Setting.Effective(); ok {
				return eff.Value.String()
			}
		}
	}
	return ""
}

func TestTheSettingsReachNeedsAreRead(t *testing.T) {
	c := fakeHome(t, map[string]string{".codex/config.toml": `
default_permissions = "tight"
approval_policy = { granular = { sandbox_approval = false } }

[permissions.tight]
extends = ":workspace"
[permissions.tight.filesystem]
"~/.aws" = "deny"

[shell_environment_policy]
inherit = "all"
exclude = ["*_TOKEN"]
include_only = ["PATH", "HOME", "GITHUB_TOKEN"]
[shell_environment_policy.filters]
"AWS_*" = "exclude"
"PATH" = "include"
`})

	perm, _ := settingsFor(t, c, model.TrustTrusted)

	for key, want := range map[string]string{
		"permissions.tight.extends":                 ":workspace",
		"approval_policy.granular.sandbox_approval": "false",
		"shell_environment_policy.inherit":          "all",
	} {
		if got := effective(perm, key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	want := map[string]model.RuleAction{
		"shell_environment_policy.exclude *_TOKEN":           model.RuleDeny,
		"shell_environment_policy.include_only PATH":         model.RuleAllow,
		"shell_environment_policy.include_only GITHUB_TOKEN": model.RuleAllow,
		"shell_environment_policy.filters AWS_*":             model.RuleDeny,
		"shell_environment_policy.filters PATH":              model.RuleAllow,
	}
	for _, r := range perm.Rules {
		if a, ok := want[r.Rule.String()]; ok {
			if r.Action != a || !r.Origin.InEffect {
				t.Errorf("%s = %s, in effect %v; want %s, in effect", r.Rule, r.Action, r.Origin.InEffect, a)
			}
			delete(want, r.Rule.String())
		}
	}
	for rule := range want {
		t.Errorf("no rule %s", rule)
	}
}

func TestTheHighestLayersEnvPolicyListsWin(t *testing.T) {
	c := fakeHome(t, map[string]string{
		".codex/config.toml":   "[shell_environment_policy]\nexclude = [\"*_TOKEN\"]\n",
		"p/.codex/config.toml": "[shell_environment_policy]\nexclude = [\"*_SECRET\"]\n",
	})

	perm, _ := settingsFor(t, c, model.TrustTrusted)

	for _, r := range perm.Rules {
		switch r.Rule.String() {
		case "shell_environment_policy.exclude *_SECRET":
			if !r.Origin.InEffect {
				t.Error("the project's list isn't in effect")
			}
		case "shell_environment_policy.exclude *_TOKEN":
			if r.Origin.InEffect {
				t.Error("the user's list is in effect under the project's")
			}
		}
	}
}

func TestTheLegacySandboxIgnoresAProfilesExtends(t *testing.T) {
	c := fakeHome(t, map[string]string{
		".codex/config.toml":   "default_permissions = \"locked\"\n[permissions.locked]\nextends = \":workspace\"\n",
		"p/.codex/config.toml": "sandbox_mode = \"workspace-write\"\n",
	})

	perm, _ := settingsFor(t, c, model.TrustTrusted)

	if got := effective(perm, "permissions.locked.extends"); got != "" {
		t.Errorf("extends is in effect (%q) though sandbox_mode makes Codex ignore profiles", got)
	}
}

func TestTheWindowsSandboxSettingsAreRead(t *testing.T) {
	c := systemHome(t,
		map[string]string{".codex/config.toml": "[windows]\nsandbox = \"elevated\"\n"},
		func(env platform.Env) map[string]string {
			return map[string]string{requirementsFile(env): "[windows]\nallowed_sandbox_implementations = [\"elevated\"]\nallow_mxc = false\n"}
		})

	perm, _ := settingsFor(t, c, model.TrustTrusted)

	for key, want := range map[string]string{
		"windows.sandbox":                         "elevated",
		"windows.allowed_sandbox_implementations": "elevated",
		"windows.allow_mxc":                       "false",
	} {
		if got := effective(perm, key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
}

func TestARequirementThatRulesOutTheConfiguredSandboxWins(t *testing.T) {
	c := systemHome(t,
		map[string]string{".codex/config.toml": "[windows]\nsandbox = \"unelevated\"\n"},
		func(env platform.Env) map[string]string {
			return map[string]string{requirementsFile(env): "[windows]\nallowed_sandbox_implementations = [\"elevated\"]\n"}
		})

	perm, _ := settingsFor(t, c, model.TrustTrusted)

	if got := effective(perm, "windows.sandbox"); got != "" {
		t.Errorf("windows.sandbox = %q in effect, want the requirements to rule unelevated out", got)
	}
}
