package claude

import (
	"slices"
	"strings"
	"testing"

	"github.com/nickelsec/jarx/internal/model"
)

// The settings reach needs beyond phase 3's: what keeps file tools inside
// the working dirs, what the sandbox exempts, the sandbox's credential
// entries, and the env vars settings put in Claude's environment.
const reachUser = `{
	"permissions": {"blockReadsOutsideWorkingDirectories": true},
	"env": {"DEPLOY_TOKEN": "demo-not-a-real-token", "EDITOR": "vim"},
	"sandbox": {
		"enabled": true,
		"excludedCommands": ["docker compose *"],
		"filesystem": {"disabled": false},
		"credentials": {
			"files": [{"path": "~/.ssh", "mode": "deny"}, {"path": "~/.aws/credentials", "mode": "mask"}],
			"envVars": [{"name": "GITHUB_TOKEN", "mode": "deny"}, {"name": "NPM_TOKEN", "mode": "mask"}]
		}
	}
}`

func TestTheSettingsReachNeedsAreRead(t *testing.T) {
	c := fakeHome(t, map[string]string{".claude/settings.json": reachUser})
	c.Env.GOOS = "linux"

	perm, _, _ := settingsFor(t, c, model.TrustTrusted)

	for key, want := range map[string]string{
		"permissions.blockReadsOutsideWorkingDirectories": "true",
		"sandbox.filesystem.disabled":                     "false",
	} {
		o, ok := optionNamed(perm, key)
		if eff, has := o.Setting.Effective(); !ok || !has || eff.Value.String() != want {
			t.Errorf("%s = %+v, want %s in effect", key, o, want)
		}
	}
	for rule, want := range map[string]struct {
		action model.RuleAction
		target string
	}{
		"sandbox.excludedCommands docker compose *":    {model.RuleExclude, "docker compose *"},
		"sandbox.credentials.files ~/.ssh":             {model.RuleDeny, "~/.ssh"},
		"sandbox.credentials.files ~/.aws/credentials": {model.RuleMask, "~/.aws/credentials"},
		"sandbox.credentials.envVars GITHUB_TOKEN":     {model.RuleDeny, "GITHUB_TOKEN"},
		"sandbox.credentials.envVars NPM_TOKEN":        {model.RuleMask, "NPM_TOKEN"},
	} {
		r := findRule(t, perm, rule, model.ScopeUser)
		if r.Action != want.action || r.Target.String() != want.target || !r.Origin.InEffect {
			t.Errorf("%s = %+v, want %s on %s, in effect", rule, r, want.action, want.target)
		}
	}
}

func TestTheEnvBlockGivesNamesOnly(t *testing.T) {
	c := fakeHome(t, map[string]string{".claude/settings.json": reachUser})

	perm, _, _ := settingsFor(t, c, model.TrustTrusted)

	names := make([]string, 0, len(perm.Env))
	for _, l := range perm.Env {
		names = append(names, l.Value.String())
	}
	if !slices.Equal(names, []string{"DEPLOY_TOKEN", "EDITOR"}) {
		t.Errorf("env names = %q, want DEPLOY_TOKEN and EDITOR, in order", names)
	}
	if strings.Contains(strings.Join(names, " "), "demo-not-a-real-token") {
		t.Error("an env value reached the model; only names should")
	}
}

func TestSandboxCredentialEntriesAreOffWithTheSandbox(t *testing.T) {
	c := fakeHome(t, map[string]string{".claude/settings.json": reachUser})
	c.Env.GOOS = "windows"

	perm, _, _ := settingsFor(t, c, model.TrustTrusted)

	for _, rule := range []string{"sandbox.credentials.files ~/.ssh", "sandbox.credentials.envVars GITHUB_TOKEN", "sandbox.excludedCommands docker compose *"} {
		if r := findRule(t, perm, rule, model.ScopeUser); r.Origin.InEffect {
			t.Errorf("%s is in effect on native Windows, where the sandbox doesn't run", rule)
		}
	}
}

func TestFilesystemDisabledIsOnlyReadFromUserOrManagedFiles(t *testing.T) {
	c := fakeHome(t, map[string]string{"p/.claude/settings.json": `{"sandbox": {"enabled": true, "filesystem": {"disabled": true}}}`})
	c.Env.GOOS = "linux"

	perm, _, _ := settingsFor(t, c, model.TrustTrusted)

	if o, ok := optionNamed(perm, "sandbox.filesystem.disabled"); ok {
		if _, in := o.Setting.Effective(); in {
			t.Errorf("a project file's sandbox.filesystem.disabled is in effect: %+v", o)
		}
	}
}

func TestTheStartModeFollowsTheDocs(t *testing.T) {
	for name, tc := range map[string]struct {
		files map[string]string
		mode  string
		why   string
	}{
		"nothing set":                 {map[string]string{}, "auto", "2.1.283"},
		"auto turned off":             {map[string]string{".claude/settings.json": `{"permissions": {"disableAutoMode": "disable"}}`}, "default", "disableAutoMode"},
		"defaultMode set":             {map[string]string{".claude/settings.json": `{"permissions": {"defaultMode": "acceptEdits"}}`}, "acceptEdits", "defaultMode"},
		"a repo's auto doesn't count": {map[string]string{"p/.claude/settings.json": `{"permissions": {"defaultMode": "bypassPermissions"}}`}, "auto", "2.1.283"},
	} {
		t.Run(name, func(t *testing.T) {
			c := fakeHome(t, tc.files)

			perm, _, _ := settingsFor(t, c, model.TrustTrusted)

			if perm.StartMode.String() != tc.mode || !strings.Contains(perm.StartWhy.String(), tc.why) {
				t.Errorf("start mode = %q (%q), want %q with a reason naming %s", perm.StartMode, perm.StartWhy, tc.mode, tc.why)
			}
		})
	}
}

func TestTheBuiltInStartSaysClaudePStartsInDefault(t *testing.T) {
	c := fakeHome(t, map[string]string{})

	perm, _, _ := settingsFor(t, c, model.TrustTrusted)

	if !strings.Contains(perm.StartWhy.String(), "claude -p starts in default") {
		t.Errorf("start reason = %q, want it to say claude -p starts in default, since auto only applies to interactive sessions", perm.StartWhy)
	}
}

// optionValue is an option's value in effect, or "".
func optionValue(perm model.Permissions, key string) string {
	if o, ok := optionNamed(perm, key); ok {
		if eff, in := o.Setting.Effective(); in {
			return eff.Value.String()
		}
	}
	return ""
}

func TestTheSettingsEgressNeedsAreRead(t *testing.T) {
	c := fakeHome(t, map[string]string{".claude/settings.json": `{
		"apiKeyHelper": "~/bin/get-key.sh",
		"forceLoginMethod": "console",
		"awsAuthRefresh": "aws sso login",
		"env": {"ANTHROPIC_BASE_URL": "https://llm.example.com", "HTTPS_PROXY": "http://proxy.example.com:3128",
			"DEPLOY_TOKEN": "demo-not-a-real-token", "NODE_EXTRA_CA_CERTS": "/etc/ca.pem"},
		"sandbox": {"network": {"allowedDomains": ["github.com", "*.npmjs.org"], "deniedDomains": ["evil.example"], "httpProxyPort": 8080}}
	}`})

	perm, _, _ := settingsFor(t, c, model.TrustTrusted)

	for key, want := range map[string]string{ //nolint:gosec // G101: setting names and made-up values
		"apiKeyHelper":                  "~/bin/get-key.sh",
		"forceLoginMethod":              "console",
		"awsAuthRefresh":                "aws sso login",
		"env.ANTHROPIC_BASE_URL":        "https://llm.example.com",
		"env.HTTPS_PROXY":               "http://proxy.example.com:3128",
		"env.NODE_EXTRA_CA_CERTS":       "/etc/ca.pem",
		"sandbox.network.httpProxyPort": "8080",
	} {
		if got := optionValue(perm, key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	if got := optionValue(perm, "env.DEPLOY_TOKEN"); got != "" {
		t.Errorf("env.DEPLOY_TOKEN = %q: a secret's value became an option", got)
	}
	for rule, want := range map[string]model.RuleAction{
		"sandbox.network.allowedDomains github.com":  model.RuleAllow,
		"sandbox.network.allowedDomains *.npmjs.org": model.RuleAllow,
		"sandbox.network.deniedDomains evil.example": model.RuleDeny,
	} {
		if r := findRule(t, perm, rule, model.ScopeUser); r.Action != want {
			t.Errorf("%s = %s, want %s", rule, r.Action, want)
		}
	}
}

func TestAProxyWithUserInfoIsMasked(t *testing.T) {
	c := fakeHome(t, map[string]string{".claude/settings.json": `{"env": {"HTTPS_PROXY": "http://me:hunter2-demo-pass@proxy.example.com:3128"}}`}) //nolint:gosec // G101: a made-up password

	perm, _, _ := settingsFor(t, c, model.TrustTrusted)

	if got := optionValue(perm, "env.HTTPS_PROXY"); strings.Contains(got, "hunter2") || got == "" {
		t.Errorf("env.HTTPS_PROXY = %q, want it there with the password masked", got)
	}
}
