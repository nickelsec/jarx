package codex

import (
	"strings"
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

// egressConfig sets every key where Codex talks to.
const egressConfig = `
model_provider = "proxy"
openai_base_url = "https://llm.example.com/v1"
chatgpt_base_url = "https://chat.example.com"
cli_auth_credentials_store = "keyring"
forced_login_method = "api"
web_search = "live"
default_permissions = "net"

[model_providers.proxy]
base_url = "https://proxy.example.com/v1"
env_key = "PROXY_API_KEY"
[model_providers.proxy.auth]
command = "get-token"

[features.network_proxy]
enabled = true
proxy_url = "http://127.0.0.1:3128"
[features.network_proxy.domains]
"api.openai.com" = "allow"
"evil.example" = "deny"

[permissions.net]
extends = ":workspace"
[permissions.net.network]
enabled = true
[permissions.net.network.domains]
"github.com" = "allow"
`

func TestTheSettingsEgressNeedsAreRead(t *testing.T) {
	c := fakeHome(t, map[string]string{".codex/config.toml": egressConfig})

	perm, _ := settingsFor(t, c, model.TrustTrusted)

	for key, want := range map[string]string{
		"model_provider":                     "proxy",
		"openai_base_url":                    "https://llm.example.com/v1",
		"chatgpt_base_url":                   "https://chat.example.com",
		"cli_auth_credentials_store":         "keyring",
		"forced_login_method":                "api",
		"web_search":                         "live",
		"model_providers.proxy.base_url":     "https://proxy.example.com/v1",
		"model_providers.proxy.env_key":      "PROXY_API_KEY",
		"model_providers.proxy.auth.command": "get-token",
		"features.network_proxy.enabled":     "true",
		"features.network_proxy.proxy_url":   "http://127.0.0.1:3128",
		"permissions.net.network.enabled":    "true",
	} {
		if got := effective(perm, key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	rules := map[string]model.RuleAction{}
	for _, r := range perm.Rules {
		rules[r.Rule.String()] = r.Action
	}
	for rule, want := range map[string]model.RuleAction{
		"features.network_proxy.domains api.openai.com": model.RuleAllow,
		"features.network_proxy.domains evil.example":   model.RuleDeny,
		"permissions.net.network.domains github.com":    model.RuleAllow,
	} {
		if got, ok := rules[rule]; !ok || got != want {
			t.Errorf("%s = %q (%v), want %s", rule, got, ok, want)
		}
	}
}

func TestAProjectConfigCantRedirectTheModelEndpoint(t *testing.T) {
	c := fakeHome(t, map[string]string{
		".codex/config.toml":   "openai_base_url = \"https://mine.example.com\"\n",
		"p/.codex/config.toml": "openai_base_url = \"https://repo.example.com\"\nmodel_provider = \"repo\"\n[model_providers.repo]\nbase_url = \"https://repo.example.com\"\n",
	})

	perm, _ := settingsFor(t, c, model.TrustTrusted)

	if got := effective(perm, "openai_base_url"); got != "https://mine.example.com" {
		t.Errorf("openai_base_url = %q, want the user's: Codex ignores it in project config", got)
	}
	for _, key := range []string{"model_provider", "model_providers.repo.base_url"} {
		if got := effective(perm, key); got != "" {
			t.Errorf("%s = %q in effect, want the project's ignored", key, got)
		}
		for _, o := range perm.Options {
			if o.Key.String() == key && (len(o.Setting.Layers) == 0 || !strings.Contains(o.Setting.Layers[0].Origin.Why.String(), "ignores")) {
				t.Errorf("%s layers = %+v, want a reason saying Codex ignores it", key, o.Setting.Layers)
			}
		}
	}
}

func TestTheWebSearchRequirementIsAnOption(t *testing.T) {
	c := systemHome(t, map[string]string{".codex/config.toml": "web_search = \"live\"\n"},
		func(env platform.Env) map[string]string {
			return map[string]string{requirementsFile(env): "allowed_web_search_modes = [\"cached\"]\n"}
		})

	perm, _ := settingsFor(t, c, model.TrustTrusted)

	if got := effective(perm, "requirements.allowed_web_search_modes"); got != "cached" {
		t.Errorf("requirements.allowed_web_search_modes = %q, want cached", got)
	}
	if got := effective(perm, "web_search"); got != "" {
		t.Errorf("web_search = %q in effect, want live ruled out by the requirement", got)
	}
}
