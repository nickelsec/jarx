package codex

import (
	"strings"
	"testing"

	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/platform"
)

func findingIDs(fs []finding.Finding) map[string]finding.Finding {
	out := map[string]finding.Finding{}
	for _, f := range fs {
		out[f.RuleID] = f
	}
	return out
}

func TestWorkspaceWriteIsIgnoredUnderProfiles(t *testing.T) {
	// The permissions guide: configure profiles or the older sandbox
	// settings, not both; only sandbox_mode switches Codex back.
	c := fakeHome(t, map[string]string{".codex/config.toml": "default_permissions = \":workspace\"\n" +
		"[sandbox_workspace_write]\nnetwork_access = true\n"})

	perm, fs := settingsFor(t, c, model.TrustTrusted)

	o := option(t, perm, "sandbox_workspace_write.network_access")
	if len(o.Setting.InEffect()) != 0 || !strings.Contains(o.Setting.Layers[0].Origin.Why.String(), "permission profiles") {
		t.Errorf("network_access = %+v, want not in effect because profiles are in use", o.Setting.Layers)
	}
	got := findingIDs(fs)
	if f, ok := got["JARX-CODEX-007"]; !ok || !strings.Contains(f.Evidence.String(), "network_access") {
		t.Errorf("findings = %v, want CODEX-007 naming the ignored keys", ruleIDs(fs))
	}
	if _, ok := got["JARX-CODEX-008"]; ok {
		t.Error("CODEX-008 raised, want info only: nothing ignored here restricts the sandbox")
	}
}

func TestAnIgnoredRestrictionIsMedium(t *testing.T) {
	for _, key := range []string{"exclude_slash_tmp", "exclude_tmpdir_env_var"} {
		c := fakeHome(t, map[string]string{".codex/config.toml": "default_permissions = \":workspace\"\n" +
			"[sandbox_workspace_write]\n" + key + " = true\n"})

		_, fs := settingsFor(t, c, model.TrustTrusted)

		got := findingIDs(fs)
		if f, ok := got["JARX-CODEX-008"]; !ok || !strings.Contains(f.Evidence.String(), key+" = true") {
			t.Errorf("%s: findings = %v, want CODEX-008 naming it", key, ruleIDs(fs))
		}
		if _, ok := got["JARX-CODEX-007"]; ok {
			t.Errorf("%s: both 007 and 008 raised, want just the medium one", key)
		}
	}
}

func TestAnExcludeSetToFalseRestrictsNothing(t *testing.T) {
	c := fakeHome(t, map[string]string{".codex/config.toml": "default_permissions = \":workspace\"\n" +
		"[sandbox_workspace_write]\nexclude_slash_tmp = false\n"})

	_, fs := settingsFor(t, c, model.TrustTrusted)

	if got := findingIDs(fs); got["JARX-CODEX-007"].RuleID == "" || got["JARX-CODEX-008"].RuleID != "" {
		t.Errorf("findings = %v, want CODEX-007 only", ruleIDs(fs))
	}
}

func TestWorkspaceWriteAppliesWithoutProfiles(t *testing.T) {
	for name, cfg := range map[string]string{
		"no profile at all":   "[sandbox_workspace_write]\nnetwork_access = true\n",
		"sandbox_mode is set": "default_permissions = \":workspace\"\nsandbox_mode = \"workspace-write\"\n[sandbox_workspace_write]\nnetwork_access = true\n",
	} {
		c := fakeHome(t, map[string]string{".codex/config.toml": cfg})

		perm, fs := settingsFor(t, c, model.TrustTrusted)

		if o := option(t, perm, "sandbox_workspace_write.network_access"); len(o.Setting.InEffect()) != 1 {
			t.Errorf("%s: network_access not in effect (%+v), want it to apply", name, o.Setting.Layers)
		}
		if _, ok := findingIDs(fs)["JARX-CODEX-007"]; ok {
			t.Errorf("%s: CODEX-007 raised, want none", name)
		}
	}
}

func TestManagedProfilesIgnoreWorkspaceWriteToo(t *testing.T) {
	c := systemHome(t, map[string]string{
		".codex/config.toml": "sandbox_mode = \"workspace-write\"\n[sandbox_workspace_write]\nnetwork_access = true\n",
	}, func(env platform.Env) map[string]string {
		return map[string]string{requirementsFile(env): "[allowed_permission_profiles]\n\":workspace\" = true\n"}
	})

	perm, fs := settingsFor(t, c, model.TrustTrusted)

	if o := option(t, perm, "sandbox_workspace_write.network_access"); len(o.Setting.InEffect()) != 0 {
		t.Errorf("network_access in effect, want not: managed profiles make Codex use profiles")
	}
	if _, ok := findingIDs(fs)["JARX-CODEX-007"]; !ok {
		t.Errorf("findings = %v, want CODEX-007", ruleIDs(fs))
	}
}
