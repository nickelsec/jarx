package codex

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nickelsec/jarx/internal/agent"
	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/platform"
)

// systemHome is a fake home with system roots inside it and files written to
// the Codex system paths for this OS.
func systemHome(t *testing.T, files map[string]string, system func(env platform.Env) map[string]string) agent.Context {
	t.Helper()
	c := fakeHome(t, files)
	c.Env = c.Env.WithSystemRoots(platform.Roots{
		Etc:          filepath.Join(c.Env.Home, "sys", "etc"),
		ProgramData:  filepath.Join(c.Env.Home, "sys", "pd"),
		ProgramFiles: filepath.Join(c.Env.Home, "sys", "pf"),
	})
	if system != nil {
		for path, body := range system(c.Env) {
			if path == "" {
				t.Skip("no such system file on this OS")
			}
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	return c
}

// settingsFor runs Settings on one ok project at /p with the given trust.
func settingsFor(t *testing.T, c agent.Context, trust model.TrustLevel) (model.Permissions, []finding.Finding) {
	t.Helper()
	p := model.Project{Path: model.NewPath(c.Scrub, c.Env.MapPath("/p")), Status: model.ProjectOK}
	if trust != "" {
		p.Trust = []model.Trust{{Level: trust, Origin: model.Origin{Agent: model.AgentCodex}}}
	}
	ps := []model.Project{p}
	_, fs := Adapter{}.Settings(c, ps)
	for _, perm := range ps[0].Permissions {
		if perm.Agent == model.AgentCodex {
			return perm, fs
		}
	}
	return model.Permissions{}, fs
}

func option(t *testing.T, p model.Permissions, key string) model.Option {
	t.Helper()
	for _, o := range p.Options {
		if o.Key.String() == key {
			return o
		}
	}
	t.Fatalf("no option %s in %+v", key, p.Options)
	return model.Option{}
}

// layers renders an option's layers as scope=value, with a * on the one in
// effect.
func layers(o model.Option) string {
	out := make([]string, 0, len(o.Setting.Layers))
	for _, l := range o.Setting.Layers {
		s := string(l.Origin.Scope) + "=" + l.Value.String()
		if l.Origin.InEffect {
			s += "*"
		}
		out = append(out, s)
	}
	return strings.Join(out, " ")
}

func ruleIDs(fs []finding.Finding) map[string]int {
	out := map[string]int{}
	for _, f := range fs {
		out[f.RuleID]++
	}
	return out
}

func TestSystemPathsPerOS(t *testing.T) {
	roots := platform.Roots{Etc: "/etc", ProgramData: `C:\ProgramData`}
	for goos, want := range map[string][3]string{
		"linux":   {filepath.Join("/etc", "codex", "config.toml"), filepath.Join("/etc", "codex", "requirements.toml"), filepath.Join("/etc", "codex", "managed_config.toml")},
		"darwin":  {filepath.Join("/etc", "codex", "config.toml"), filepath.Join("/etc", "codex", "requirements.toml"), filepath.Join("/etc", "codex", "managed_config.toml")},
		"windows": {"", filepath.Join(`C:\ProgramData`, "OpenAI", "Codex", "requirements.toml"), filepath.Join("home", ".codex", "managed_config.toml")},
	} {
		got := [3]string{systemConfigFor(goos, roots), requirementsFor(goos, roots), managedConfigFor(goos, roots, filepath.Join("home", ".codex"))}
		if got != want {
			t.Errorf("%s paths = %q, want %q", goos, got, want)
		}
	}
}

func TestLayersFollowTheDocumentedOrder(t *testing.T) {
	c := systemHome(t,
		map[string]string{
			".codex/config.toml":   `approval_policy = "on-request"` + "\n" + `sandbox_mode = "read-only"`,
			"p/.codex/config.toml": `approval_policy = "never"`,
		},
		func(env platform.Env) map[string]string {
			return map[string]string{systemConfigFile(env): `approval_policy = "on-request"` + "\n" + `web_search = "cached"`}
		})

	perm, _ := settingsFor(t, c, model.TrustTrusted)

	if got := layers(option(t, perm, "approval_policy")); got != "project=never* user=on-request system=on-request" {
		t.Errorf("approval_policy = %s", got)
	}
	if got := layers(option(t, perm, "web_search")); got != "system=cached*" {
		t.Errorf("web_search = %s", got)
	}
}

func TestUntrustedProjectLayersDontLoad(t *testing.T) {
	for _, trust := range []model.TrustLevel{model.TrustUntrusted, model.TrustUnknown, ""} {
		c := fakeHome(t, map[string]string{
			".codex/config.toml":   `approval_policy = "on-request"`,
			"p/.codex/config.toml": `approval_policy = "never"`,
		})

		perm, _ := settingsFor(t, c, trust)

		o := option(t, perm, "approval_policy")
		if got := layers(o); got != "project=never user=on-request*" || o.Setting.Layers[0].Origin.Why.IsZero() {
			t.Errorf("trust %q: approval_policy = %s (why %q), want the project layer listed but not loaded", trust, got, o.Setting.Layers[0].Origin.Why)
		}
	}
}

func TestProjectLayersLoadFromTheRootMarkerDown(t *testing.T) {
	c := fakeHome(t, map[string]string{
		"mono/.git/HEAD":              "ref: refs/heads/main",
		"mono/.codex/config.toml":     `approval_policy = "on-request"` + "\n" + `web_search = "live"`,
		"mono/pkg/.codex/config.toml": `approval_policy = "never"`,
		"outside/.codex/config.toml":  `web_search = "disabled"`,
	})
	p := model.Project{Path: model.NewPath(c.Scrub, c.Env.MapPath("/mono/pkg")), Status: model.ProjectOK,
		Trust: []model.Trust{{Level: model.TrustTrusted, Origin: model.Origin{Agent: model.AgentCodex}}}}
	ps := []model.Project{p}

	Adapter{}.Settings(c, ps)

	perm := ps[0].Permissions[0]
	if got := layers(option(t, perm, "approval_policy")); got != "project=never* project=on-request" {
		t.Errorf("approval_policy = %s, want the closest file first", got)
	}
	if got := layers(option(t, perm, "web_search")); got != "project=live*" {
		t.Errorf("web_search = %s, want only layers under the root marker", got)
	}
}

func TestProfileFilesApplyOnlyWithTheFlag(t *testing.T) {
	c := fakeHome(t, map[string]string{
		".codex/config.toml":             `approval_policy = "on-request"`,
		".codex/deep-review.config.toml": `approval_policy = "never"`,
	})

	perm, _ := settingsFor(t, c, model.TrustTrusted)

	o := option(t, perm, "approval_policy")
	if got := layers(o); got != "profile=never user=on-request*" ||
		!strings.Contains(o.Setting.Layers[0].Origin.Why.String(), "--profile deep-review") {
		t.Errorf("approval_policy = %s (why %q), want the profile listed for --profile deep-review only", got, o.Setting.Layers[0].Origin.Why)
	}
}

func TestLegacyProfilesAreIgnoredWithAFinding(t *testing.T) {
	c := fakeHome(t, map[string]string{
		".codex/config.toml": "profile = \"old\"\n\n[profiles.old]\napproval_policy = \"never\"\n",
	})

	perm, fs := settingsFor(t, c, model.TrustTrusted)

	if got := ruleIDs(fs)[LegacyProfiles().ID]; got != 1 {
		t.Errorf("%s findings = %d, want 1 (%+v)", LegacyProfiles().ID, got, fs)
	}
	for _, o := range perm.Options {
		if o.Key.String() == "approval_policy" {
			t.Errorf("a legacy profile's value got used: %s", layers(o))
		}
	}
}

func TestKeysCodexIgnoresInProjectConfig(t *testing.T) {
	c := fakeHome(t, map[string]string{
		".codex/config.toml":   `approval_policy = "on-request"`,
		"p/.codex/config.toml": "profile = \"x\"\n" + `approval_policy = "never"`,
	})

	_, fs := settingsFor(t, c, model.TrustTrusted)

	if got := ruleIDs(fs)[LegacyProfiles().ID]; got != 0 {
		t.Errorf("a project profile key is ignored by Codex with a warning, not a legacy profile: %+v", fs)
	}
}

func TestARepoTurningOffYourPermissionProfileIsHigh(t *testing.T) {
	c := fakeHome(t, map[string]string{
		".codex/config.toml": "default_permissions = \"locked\"\n\n" +
			"[permissions.locked]\nextends = \":workspace\"\n\n" +
			"[permissions.locked.filesystem]\n\"~/.ssh\" = \"deny\"\n\"~/code\" = \"write\"\n",
		"p/.codex/config.toml": `sandbox_mode = "danger-full-access"`,
	})

	perm, fs := settingsFor(t, c, model.TrustTrusted)

	if got := ruleIDs(fs)[RepoDropsPermissions().ID]; got != 1 {
		t.Fatalf("%s findings = %d, want 1 (%+v)", RepoDropsPermissions().ID, got, fs)
	}
	if f := fs[0]; f.Severity != finding.High || !strings.Contains(f.Evidence.String(), "locked") {
		t.Errorf("finding = %+v, want high and naming the profile it turned off", f)
	}
	dp := option(t, perm, "default_permissions")
	if dp.Setting.Layers[0].Origin.InEffect || !strings.Contains(dp.Setting.Layers[0].Origin.Why.String(), "sandbox_mode") {
		t.Errorf("default_permissions = %s (why %q), want it overridden by sandbox_mode", layers(dp), dp.Setting.Layers[0].Origin.Why)
	}
	for _, r := range perm.Rules {
		if r.Origin.InEffect {
			t.Errorf("profile rule %s %s still in effect, want every rule of the dropped profile off", r.Action, r.Rule)
		}
	}
}

func TestYourOwnSandboxModeOverridingYourProfileIsMedium(t *testing.T) {
	c := fakeHome(t, map[string]string{
		".codex/config.toml": "default_permissions = \":workspace\"\nsandbox_mode = \"workspace-write\"\n",
	})

	_, fs := settingsFor(t, c, model.TrustTrusted)

	ids := ruleIDs(fs)
	if ids[OwnSandboxModeWins().ID] != 1 || ids[RepoDropsPermissions().ID] != 0 {
		t.Errorf("findings = %v, want one %s and no %s", ids, OwnSandboxModeWins().ID, RepoDropsPermissions().ID)
	}
}

func TestManagedProfileAllowlistKeepsProfilesOn(t *testing.T) {
	c := systemHome(t,
		map[string]string{
			".codex/config.toml":   `default_permissions = ":workspace"`,
			"p/.codex/config.toml": `sandbox_mode = "danger-full-access"`,
		},
		func(env platform.Env) map[string]string {
			return map[string]string{requirementsFile(env): "[allowed_permission_profiles]\n\":workspace\" = true\n"}
		})

	perm, fs := settingsFor(t, c, model.TrustTrusted)

	if ids := ruleIDs(fs); ids[RepoDropsPermissions().ID] != 0 {
		t.Errorf("findings = %v, want none: the managed allowlist keeps permission profiles in use", ids)
	}
	if sm := option(t, perm, "sandbox_mode"); sm.Setting.Layers[0].Origin.InEffect {
		t.Errorf("sandbox_mode = %s, want it set aside by the managed profile allowlist", layers(sm))
	}
}

func TestARepoExtendingYourProfileIsAFinding(t *testing.T) {
	c := fakeHome(t, map[string]string{
		".codex/config.toml":   "default_permissions = \"dev\"\n\n[permissions.dev.filesystem]\n\"~/.aws\" = \"deny\"\n",
		"p/.codex/config.toml": "[permissions.dev.filesystem]\n\"~/.aws\" = \"read\"\n",
	})

	perm, fs := settingsFor(t, c, model.TrustTrusted)

	if got := ruleIDs(fs)[RepoWidensProfile().ID]; got != 1 {
		t.Errorf("%s findings = %d, want 1 (%+v)", RepoWidensProfile().ID, got, fs)
	}
	var on []string
	for _, r := range perm.Rules {
		if r.Origin.InEffect {
			on = append(on, string(r.Origin.Scope)+":"+string(r.Action)+":"+r.Rule.String())
		}
	}
	if len(on) != 1 || on[0] != "project:read:dev ~/.aws" {
		t.Errorf("rules in effect = %q, want the project's read to replace the user's deny for the same path", on)
	}
}

func TestRequirementsRejectDisallowedValues(t *testing.T) {
	c := systemHome(t,
		map[string]string{".codex/config.toml": `approval_policy = "never"`},
		func(env platform.Env) map[string]string {
			return map[string]string{requirementsFile(env): `allowed_approval_policies = ["on-request"]`}
		})

	perm, _ := settingsFor(t, c, model.TrustTrusted)

	o := option(t, perm, "approval_policy")
	if l := o.Setting.Layers[0]; l.Origin.InEffect || !strings.Contains(l.Origin.Why.String(), "requirements") {
		t.Errorf("approval_policy = %s (why %q), want it rejected by requirements", layers(o), l.Origin.Why)
	}
}

func TestLegacyManagedConfigSitsOnTopWithAFinding(t *testing.T) {
	c := systemHome(t,
		map[string]string{".codex/config.toml": `approval_policy = "never"`},
		func(env platform.Env) map[string]string {
			return map[string]string{managedConfigFile(env): `approval_policy = "on-request"`}
		})

	perm, fs := settingsFor(t, c, model.TrustTrusted)

	if got := layers(option(t, perm, "approval_policy")); got != "managed=on-request* user=never" {
		t.Errorf("approval_policy = %s, want the legacy managed file on top", got)
	}
	if ruleIDs(fs)[LegacyManagedConfig().ID] != 1 {
		t.Errorf("findings = %+v, want one %s", fs, LegacyManagedConfig().ID)
	}
}

func TestShellEnvironmentPolicyIsRecorded(t *testing.T) {
	c := fakeHome(t, map[string]string{
		".codex/config.toml": "[shell_environment_policy]\ninherit = \"all\"\nignore_default_excludes = true\n",
	})

	perm, _ := settingsFor(t, c, model.TrustTrusted)

	for key, want := range map[string]string{
		"shell_environment_policy.inherit":                 "user=all*",
		"shell_environment_policy.ignore_default_excludes": "user=true*",
	} {
		if got := layers(option(t, perm, key)); got != want {
			t.Errorf("%s = %s, want %s", key, got, want)
		}
	}
}

func TestSecretsInValuesAreMaskedAndBrokenFilesAreFindings(t *testing.T) {
	c := fakeHome(t, map[string]string{
		".codex/config.toml":   `default_permissions = "` + canary + `"`,
		"p/.codex/config.toml": "approval_policy = \"" + plainSecret + "\" oops",
	})

	perm, fs := settingsFor(t, c, model.TrustTrusted)

	if out := fmt.Sprintf("%+v %+v", perm, fs); strings.Contains(out, canary) || strings.Contains(out, plainSecret) {
		t.Errorf("a secret got out: %s", out)
	}
	if ruleIDs(fs)[finding.UnreadableRecord().ID] != 1 {
		t.Errorf("findings = %+v, want the broken project file reported", fs)
	}
}

func TestEachConfigFileIsKeptScrubbedForTheSecretsScan(t *testing.T) {
	c := systemHome(t, map[string]string{
		".codex/config.toml":   "[mcp_servers.x.env]\nTOKEN = \"" + canary + "\"\n",
		"p/.git/HEAD":          "ref: refs/heads/main\n",
		"p/.codex/config.toml": "model = \"o3\"\n",
	}, func(env platform.Env) map[string]string {
		return map[string]string{requirementsFile(env): "allowed_sandbox_modes = [\"read-only\"]\n"}
	})
	p := model.Project{Path: model.NewPath(c.Scrub, c.Env.MapPath("/p")), Status: model.ProjectOK,
		Trust: []model.Trust{{Level: model.TrustTrusted, Origin: model.Origin{Agent: model.AgentCodex}}}}
	ps := []model.Project{p}

	Adapter{}.Settings(c, ps)

	got := map[model.Scope]model.Config{}
	for _, cfg := range ps[0].Configs {
		got[cfg.Origin.Scope] = cfg
	}
	if user := got[model.ScopeUser]; strings.Contains(user.Text.String(), canary) || len(user.Text.Secrets()) != 1 {
		t.Errorf("user config = %q, want the token masked and counted", user.Text)
	}
	if len(ps[0].Configs) != 3 || got[model.ScopeProject].Text.IsZero() || got[model.ScopeRequirements].Text.IsZero() {
		t.Errorf("configs = %+v, want user, project and requirements", ps[0].Configs)
	}
}
