package claude

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/nickelsec/jarx/internal/agent"
	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/platform"
)

type fakeRegistry map[string]string

func (f fakeRegistry) String(h platform.Hive, key, name string) (string, error) {
	if v, ok := f[h.String()+`\`+key+`\`+name]; ok {
		return v, nil
	}
	return "", fs.ErrNotExist
}

const (
	hklmSettings = `HKLM\SOFTWARE\Policies\ClaudeCode\Settings`
	hkcuSettings = `HKCU\SOFTWARE\Policies\ClaudeCode\Settings`
)

// managedHome is a fake home with system roots inside it, managed files
// (relative to the managed dir) and a fake registry.
func managedHome(t *testing.T, files, managed map[string]string, reg fakeRegistry) agent.Context {
	t.Helper()
	c := fakeHome(t, files)
	h := c.Env.Home
	c.Env = c.Env.WithSystemRoots(platform.Roots{
		Etc:               filepath.Join(h, "sys", "etc"),
		LibraryAppSupport: filepath.Join(h, "sys", "las"),
		ProgramData:       filepath.Join(h, "sys", "pd"),
		ProgramFiles:      filepath.Join(h, "sys", "pf"),
	}).WithRegistry(reg)
	dir := managedDir(c.Env)
	for rel, body := range managed {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return c
}

func TestManagedDirPerOS(t *testing.T) {
	roots := platform.Roots{Etc: "/etc", LibraryAppSupport: "/Library/Application Support", ProgramFiles: `C:\Program Files`}
	for goos, want := range map[string]string{
		"linux":   filepath.Join("/etc", "claude-code"),
		"darwin":  filepath.Join("/Library/Application Support", "ClaudeCode"),
		"windows": filepath.Join(`C:\Program Files`, "ClaudeCode"),
	} {
		if got := managedDirFor(goos, roots); got != want {
			t.Errorf("%s managed dir = %q, want %q", goos, got, want)
		}
	}
	if got := managedDirFor("windows", platform.Roots{}); got != "" {
		t.Errorf("windows with no ProgramFiles = %q, want none", got)
	}
}

func TestFakeHomeReadsNoManagedSettings(t *testing.T) {
	c := fakeHome(t, map[string]string{"sys/etc/claude-code/managed-settings.json": `{"permissions": {"deny": ["Read(x)"]}}`})

	perm, _, _ := settingsFor(t, c, model.TrustTrusted)

	if len(perm.Rules) != 0 {
		t.Errorf("rules = %+v, want none without system roots", rules(perm))
	}
}

func TestManagedFileSitsAboveEveryOtherScope(t *testing.T) {
	c := managedHome(t,
		map[string]string{".claude/settings.json": `{"permissions": {"defaultMode": "bypassPermissions", "allow": ["Bash(*)"]}}`},
		map[string]string{"managed-settings.json": `{"permissions": {"defaultMode": "plan", "deny": ["Read(./.env)"]}}`},
		nil)

	perm, _, fs := settingsFor(t, c, model.TrustTrusted)

	if eff, _ := perm.DefaultMode.Effective(); eff.Value.String() != "plan" || eff.Origin.Scope != model.ScopeManaged {
		t.Errorf("effective mode = %+v, want the managed plan", eff)
	}
	want := []ruleView{
		{model.RuleDeny, "Read(./.env)", model.ScopeManaged, true},
		{model.RuleAllow, "Bash(*)", model.ScopeUser, true},
	}
	if got := rules(perm); !slices.Equal(got, want) {
		t.Errorf("rules = %+v, want %+v", got, want)
	}
	if len(fs) != 0 {
		t.Errorf("findings = %+v, want none", fs)
	}
}

func TestManagedDropInsMergeInNameOrder(t *testing.T) {
	c := managedHome(t, nil, map[string]string{
		"managed-settings.json":              `{"permissions": {"defaultMode": "plan", "deny": ["Read(base)"]}}`,
		"managed-settings.d/20-b.json":       `{"permissions": {"defaultMode": "default"}}`,
		"managed-settings.d/10-a.json":       `{"permissions": {"defaultMode": "acceptEdits", "deny": ["Read(a)"]}}`,
		"managed-settings.d/.hidden.json":    `{"permissions": {"deny": ["Read(hidden)"]}}`,
		"managed-settings.d/notes.txt":       `{"permissions": {"deny": ["Read(txt)"]}}`,
		"managed-settings.d/sub/deeper.json": `{"permissions": {"deny": ["Read(deeper)"]}}`,
	}, nil)

	perm, _, _ := settingsFor(t, c, model.TrustTrusted)

	got := make([]string, 0, len(perm.DefaultMode.Layers))
	for _, l := range perm.DefaultMode.Layers {
		got = append(got, filepath.Base(l.Origin.File.Raw())+"="+l.Value.String())
	}
	if want := []string{"20-b.json=default", "10-a.json=acceptEdits", "managed-settings.json=plan"}; !slices.Equal(got, want) {
		t.Errorf("mode layers = %q, want %q (later file wins)", got, want)
	}
	var denies []string
	for _, r := range perm.Rules {
		if r.Origin.InEffect {
			denies = append(denies, r.Rule.String())
		}
	}
	slices.Sort(denies)
	if want := []string{"Read(a)", "Read(base)"}; !slices.Equal(denies, want) {
		t.Errorf("denies = %q, want %q (no hidden, non-json or nested files)", denies, want)
	}
}

func TestRegistryPolicyWinsOverFilesByDefault(t *testing.T) {
	c := managedHome(t, nil,
		map[string]string{"managed-settings.json": `{"permissions": {"deny": ["Read(file)"]}}`},
		fakeRegistry{hklmSettings: `{"permissions": {"deny": ["Read(hklm)"]}}`})

	perm, _, _ := settingsFor(t, c, model.TrustTrusted)

	if r := findRule(t, perm, "Read(hklm)", model.ScopeManaged); !r.Origin.InEffect || r.Origin.File.Raw() != hklmSettings {
		t.Errorf("hklm rule = %+v, want in effect from the HKLM value", r.Origin)
	}
	if r := findRule(t, perm, "Read(file)", model.ScopeManaged); r.Origin.InEffect || !strings.Contains(r.Origin.Why.String(), "first-wins") {
		t.Errorf("file rule = %+v, want not in effect under first-wins", r.Origin)
	}
}

func TestMergeCombinesAdminSourcesButModeComesFromTheTop(t *testing.T) {
	c := managedHome(t, nil,
		map[string]string{"managed-settings.json": `{"permissions": {"defaultMode": "plan", "deny": ["Read(file)"]}}`},
		fakeRegistry{hklmSettings: `{"managedSourcesBehavior": "merge", "permissions": {"deny": ["Read(hklm)"]}}`})

	perm, _, _ := settingsFor(t, c, model.TrustTrusted)

	for _, rule := range []string{"Read(hklm)", "Read(file)"} {
		if r := findRule(t, perm, rule, model.ScopeManaged); !r.Origin.InEffect {
			t.Errorf("%s = %+v, want in effect under merge", rule, r.Origin)
		}
	}
	if len(perm.DefaultMode.Layers) != 1 || perm.DefaultMode.Layers[0].Origin.InEffect {
		t.Errorf("mode layers = %+v, want the file's plan listed but not in effect", perm.DefaultMode.Layers)
	}
}

func TestMergeSetInALowerSourceDoesNothing(t *testing.T) {
	c := managedHome(t, nil,
		map[string]string{"managed-settings.json": `{"managedSourcesBehavior": "merge", "permissions": {"deny": ["Read(file)"]}}`},
		fakeRegistry{hklmSettings: `{"permissions": {"deny": ["Read(hklm)"]}}`})

	perm, _, _ := settingsFor(t, c, model.TrustTrusted)

	if r := findRule(t, perm, "Read(file)", model.ScopeManaged); r.Origin.InEffect {
		t.Errorf("file rule in effect, want the file's own merge ignored")
	}
}

func TestHKCUCountsOnlyWithoutAnAdminSource(t *testing.T) {
	hkcu := `{"permissions": {"deny": ["Read(hkcu)"]}}`
	for name, tc := range map[string]struct {
		managed map[string]string
		reg     fakeRegistry
		on      bool
	}{
		"alone":                   {nil, fakeRegistry{hkcuSettings: hkcu}, true},
		"under a file":            {map[string]string{"managed-settings.json": `{"model": "x"}`}, fakeRegistry{hkcuSettings: hkcu}, false},
		"under hklm":              {nil, fakeRegistry{hkcuSettings: hkcu, hklmSettings: `{"model": "x"}`}, false},
		"under a broken file":     {map[string]string{"managed-settings.json": `{oops`}, fakeRegistry{hkcuSettings: hkcu}, false},
		"under control keys only": {map[string]string{"managed-settings.json": `{"managedSourcesBehavior": "merge"}`}, fakeRegistry{hkcuSettings: hkcu}, true},
		"under null policy keys":  {map[string]string{"managed-settings.json": `{"model": null}`}, fakeRegistry{hkcuSettings: hkcu}, true},
	} {
		t.Run(name, func(t *testing.T) {
			perm, _, _ := settingsFor(t, managedHome(t, nil, tc.managed, tc.reg), model.TrustTrusted)

			r := findRule(t, perm, "Read(hkcu)", model.ScopeManaged)
			if r.Origin.InEffect != tc.on {
				t.Errorf("hkcu rule in effect = %v, want %v (why %q)", r.Origin.InEffect, tc.on, r.Origin.Why)
			}
		})
	}
}

func TestHKCUNeverMerges(t *testing.T) {
	c := managedHome(t, nil,
		map[string]string{"managed-settings.json": `{"managedSourcesBehavior": "merge", "permissions": {"deny": ["Read(file)"]}}`},
		fakeRegistry{hkcuSettings: `{"permissions": {"deny": ["Read(hkcu)"]}}`})

	perm, _, _ := settingsFor(t, c, model.TrustTrusted)

	if r := findRule(t, perm, "Read(hkcu)", model.ScopeManaged); r.Origin.InEffect {
		t.Errorf("hkcu rule in effect, want it left out of the merge")
	}
}

func TestManagedRulesOnlyDropsEveryOtherRule(t *testing.T) {
	c := managedHome(t,
		map[string]string{
			".claude/settings.json":         `{"permissions": {"deny": ["Read(user)"]}}`,
			"p/.claude/settings.json":       `{"permissions": {"ask": ["Bash(project)"]}}`,
			"p/.claude/settings.local.json": `{"permissions": {"allow": ["Bash(local)"]}}`,
		},
		map[string]string{"managed-settings.json": `{"allowManagedPermissionRulesOnly": true, "permissions": {"allow": ["Bash(managed)"]}}`},
		nil)

	perm, _, _ := settingsFor(t, c, model.TrustTrusted)

	if r := findRule(t, perm, "Bash(managed)", model.ScopeManaged); !r.Origin.InEffect {
		t.Errorf("managed rule = %+v, want in effect", r.Origin)
	}
	for rule, scope := range map[string]model.Scope{"Read(user)": model.ScopeUser, "Bash(project)": model.ScopeProject, "Bash(local)": model.ScopeLocal} {
		r := findRule(t, perm, rule, scope)
		if r.Origin.InEffect || !strings.Contains(r.Origin.Why.String(), "allowManagedPermissionRulesOnly") {
			t.Errorf("%s = %+v, want not in effect, naming allowManagedPermissionRulesOnly", rule, r.Origin)
		}
	}
}

func TestManagedRulesOnlyFromAUserFileDoesNothing(t *testing.T) {
	c := fakeHome(t, map[string]string{
		".claude/settings.json": `{"allowManagedPermissionRulesOnly": true, "permissions": {"deny": ["Read(user)"]}}`,
	})

	perm, _, _ := settingsFor(t, c, model.TrustTrusted)

	if r := findRule(t, perm, "Read(user)", model.ScopeUser); !r.Origin.InEffect {
		t.Errorf("user rule = %+v, want in effect: the key is managed only", r.Origin)
	}
}

func TestPolicyHelperMakesManagedSettingsUnknown(t *testing.T) {
	helper := `{"policyHelper": {"path": "/opt/helper"}}`
	for name, tc := range map[string]struct {
		managed map[string]string
		reg     fakeRegistry
		want    bool
	}{
		"in the file":    {map[string]string{"managed-settings.json": helper}, nil, true},
		"in hklm":        {nil, fakeRegistry{hklmSettings: helper}, true},
		"in hkcu":        {nil, fakeRegistry{hkcuSettings: helper}, false},
		"in a loser":     {map[string]string{"managed-settings.json": helper}, fakeRegistry{hklmSettings: `{"model": "x"}`}, false},
		"not set at all": {map[string]string{"managed-settings.json": `{"model": "x"}`}, nil, false},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, fs := settingsFor(t, managedHome(t, nil, tc.managed, tc.reg), model.TrustTrusted)

			got := slices.ContainsFunc(fs, func(f finding.Finding) bool { return f.RuleID == PolicyHelperSet().ID })
			if got != tc.want {
				t.Errorf("policy helper finding = %v, want %v (findings %+v)", got, tc.want, fs)
			}
		})
	}
}

func TestBrokenRegistryJSONIsAFindingWithoutContent(t *testing.T) {
	c := managedHome(t, nil, nil, fakeRegistry{hklmSettings: `{"x": "` + plainSecret + `" oops}`})

	_, _, fs := settingsFor(t, c, model.TrustTrusted)

	if len(fs) != 1 || fs[0].RuleID != finding.UnreadableRecord().ID {
		t.Fatalf("findings = %+v, want one %s", fs, finding.UnreadableRecord().ID)
	}
	if out := fmt.Sprintf("%+v", fs); strings.Contains(out, plainSecret) || !strings.Contains(out, "HKLM") {
		t.Errorf("finding = %s, want it to name HKLM and not leak content", out)
	}
}

func TestManagedUnknownKeysAreReportedOnce(t *testing.T) {
	c := managedHome(t, nil, map[string]string{"managed-settings.json": `{"notARealSetting": 1}`}, nil)
	ps := []model.Project{project(c, model.TrustTrusted), project(c, model.TrustTrusted)}

	unknown, _ := Adapter{}.Settings(c, ps)

	if len(unknown) != 1 || unknown[0].Origin.Scope != model.ScopeManaged {
		t.Errorf("unknown = %+v, want the managed key once", unknown)
	}
}
