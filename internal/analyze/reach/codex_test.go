package reach

import (
	"strings"
	"testing"

	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/redact"
)

// codexWorld is a project only Codex knows, on Linux.
func codexWorld(t *testing.T, jarxEnv string) *world {
	t.Helper()
	return codexWorldOn(t, "linux", jarxEnv)
}

// codexWorldOn is a project only Codex knows, on goos.
func codexWorldOn(t *testing.T, goos, jarxEnv string) *world {
	t.Helper()
	w := newWorld(t, goos, jarxEnv)
	w.proj.Origins = []model.Origin{{Agent: model.AgentCodex, InEffect: true}}
	w.perm = model.Permissions{Agent: model.AgentCodex}
	return w
}

func (w *world) codexOrigin() model.Origin {
	return model.Origin{Agent: model.AgentCodex, Scope: model.ScopeUser, File: model.NewPath(w.s, w.home(".codex/config.toml")), InEffect: true}
}

func (w *world) codexOption(key, value string) *world {
	w.perm.Options = append(w.perm.Options, model.Option{Key: w.text(key), Setting: model.Setting[redact.Text]{
		Layers: []model.Layer[redact.Text]{{Value: w.text(value), Origin: w.codexOrigin()}},
	}})
	return w
}

// profile is the custom profile the tests use.
const profile = "tight"

// profileRule adds a filesystem entry to the tests' permission profile.
func (w *world) profileRule(path string, action model.RuleAction) *world {
	w.perm.Rules = append(w.perm.Rules, model.PermissionRule{Action: action, Rule: w.text(profile + " " + path), Target: w.text(path), Origin: w.codexOrigin()})
	return w
}

func (w *world) envRule(list, pattern string, action model.RuleAction) {
	w.perm.Rules = append(w.perm.Rules, model.PermissionRule{
		Action: action, Rule: w.text("shell_environment_policy." + list + " " + pattern), Target: w.text(pattern), Origin: w.codexOrigin(),
	})
}

func (w *world) codexVerdict(what string) (model.ReachVerdict, string) {
	w.t.Helper()
	for _, r := range w.settle()[0].Reach {
		label := r.Name.String()
		if !r.Path.IsZero() {
			label = r.Path.Raw()
		}
		if r.Agent == model.AgentCodex && r.Channel == model.ChannelShell && (label == what || label == w.home(what)) {
			why := make([]string, 0, len(r.Why))
			for _, y := range r.Why {
				why = append(why, y.String())
			}
			return r.Verdict, strings.Join(why, "; ")
		}
	}
	w.t.Fatalf("no codex shell verdict for %s", what)
	return "", ""
}

func TestCodexShell(t *testing.T) {
	for name, tc := range map[string]struct {
		set  func(*world)
		want model.ReachVerdict
		why  string
	}{
		"the default sandbox doesn't limit reads": {func(*world) {}, model.ReachSilent, "reads"},
		"legacy read-only still reads":            {func(w *world) { w.codexOption("sandbox_mode", "read-only") }, model.ReachSilent, "read-only"},
		"no sandbox":                              {func(w *world) { w.codexOption("sandbox_mode", "danger-full-access") }, model.ReachSilent, "danger-full-access"},
		"a built-in profile":                      {func(w *world) { w.codexOption("default_permissions", ":workspace") }, model.ReachSilent, ":workspace"},
		"a custom profile that doesn't grant it": {func(w *world) {
			w.codexOption("default_permissions", "tight").profileRule(":minimal", model.RuleRead)
		}, model.ReachApproval, "doesn't grant"},
		"a custom profile that grants it": {func(w *world) {
			w.codexOption("default_permissions", "tight").profileRule("~/.aws", model.RuleRead)
		}, model.ReachSilent, "~/.aws"},
		"a custom profile reading the root": {func(w *world) {
			w.codexOption("default_permissions", "tight").profileRule(":root", model.RuleRead)
		}, model.ReachSilent, ":root"},
		"a deny in a profile that extends a built-in": {func(w *world) {
			w.codexOption("default_permissions", "tight").codexOption("permissions.tight.extends", ":workspace").
				profileRule("~/.aws", model.RuleDeny)
		}, model.ReachApproval, "deny"},
		"extends keeps the built-in's reads": {func(w *world) {
			w.codexOption("default_permissions", "tight").codexOption("permissions.tight.extends", ":workspace").
				profileRule(":minimal", model.RuleRead)
		}, model.ReachSilent, "extends"},
		"a narrower grant reopens a deny": {func(w *world) {
			w.codexOption("default_permissions", "tight").profileRule("~/", model.RuleDeny).profileRule("~/.aws", model.RuleRead)
		}, model.ReachSilent, "~/.aws"},
		"a deny wins an equal grant": {func(w *world) {
			w.codexOption("default_permissions", "tight").profileRule("~/.aws", model.RuleRead).profileRule("~/.aws", model.RuleDeny)
		}, model.ReachApproval, "deny"},
	} {
		t.Run(name, func(t *testing.T) {
			w := codexWorld(t, "")
			w.proj.Credentials = []model.Credential{{Kind: "env_file", Path: model.NewPath(w.s, w.proj.Path.Raw()+"/.env"), Read: model.ReadOK}}
			tc.set(w)
			target := awsCreds
			if strings.Contains(name, "workspace roots") {
				target = w.proj.Path.Raw() + "/.env"
			}
			if got, why := w.codexVerdict(target); got != tc.want || !strings.Contains(why, tc.why) {
				t.Errorf("codex shell = %s (%q), want %s with a reason naming %q", got, why, tc.want, tc.why)
			}
		})
	}
}

func TestCodexEscalation(t *testing.T) {
	for name, tc := range map[string]struct {
		set  func(*world)
		want model.ReachVerdict
		why  string
	}{
		"never auto-rejects the escalation": {func(w *world) {
			w.codexOption("default_permissions", "tight").profileRule(":minimal", model.RuleRead).codexOption("approval_policy", "never")
		}, model.ReachBlocked, "never"},
		"granular sandbox_approval false": {func(w *world) {
			w.codexOption("default_permissions", "tight").profileRule(":minimal", model.RuleRead).
				codexOption("approval_policy.granular.sandbox_approval", "false")
		}, model.ReachBlocked, "sandbox_approval"},
		"auto_review isn't you": {func(w *world) {
			w.codexOption("default_permissions", "tight").profileRule(":minimal", model.RuleRead).
				codexOption("approvals_reviewer", "auto_review")
		}, model.ReachSilent, "auto_review"},
		"workspace roots subpath deny": {func(w *world) {
			w.codexOption("default_permissions", "tight").codexOption("permissions.tight.extends", ":workspace").
				profileRule(":workspace_roots/**/.env", model.RuleDeny).codexOption("approval_policy", "never")
		}, model.ReachBlocked, ":workspace_roots"},
	} {
		t.Run(name, func(t *testing.T) {
			w := codexWorld(t, "")
			w.proj.Credentials = []model.Credential{{Kind: "env_file", Path: model.NewPath(w.s, w.proj.Path.Raw()+"/.env"), Read: model.ReadOK}}
			tc.set(w)
			target := awsCreds
			if strings.Contains(name, "workspace roots") {
				target = w.proj.Path.Raw() + "/.env"
			}
			if got, why := w.codexVerdict(target); got != tc.want || !strings.Contains(why, tc.why) {
				t.Errorf("codex shell = %s (%q), want %s with a reason naming %q", got, why, tc.want, tc.why)
			}
		})
	}
}

func TestCodexLegacySandboxDropsTheProfilesDenies(t *testing.T) {
	w := codexWorld(t, "")
	w.codexOption("sandbox_mode", "workspace-write")
	off := model.PermissionRule{Action: model.RuleDeny, Rule: w.text("tight ~/.aws"), Target: w.text("~/.aws"), Origin: w.codexOrigin()}
	off.Origin.InEffect, off.Origin.Why = false, w.text("sandbox_mode is set in ~/.codex/config.toml, so Codex ignores permission profiles")
	w.perm.Rules = append(w.perm.Rules, off)

	got, why := w.codexVerdict(awsCreds)
	if got != model.ReachSilent || !strings.Contains(why, "ignores") {
		t.Errorf("codex shell = %s (%q), want readable silently with a note that the profile's deny is ignored", got, why)
	}
}

func TestCodexEnv(t *testing.T) {
	for name, tc := range map[string]struct {
		set  func(*world)
		want model.ReachVerdict
		why  string
	}{
		"inherited by default":          {func(*world) {}, model.ReachSilent, "ignore_default_excludes"},
		"inherit none":                  {func(w *world) { w.codexOption("shell_environment_policy.inherit", "none") }, model.ReachBlocked, "inherit"},
		"inherit core":                  {func(w *world) { w.codexOption("shell_environment_policy.inherit", "core") }, model.ReachBlocked, "core"},
		"default excludes on":           {func(w *world) { w.codexOption("shell_environment_policy.ignore_default_excludes", "false") }, model.ReachBlocked, "KEY, SECRET or TOKEN"},
		"an exclude pattern":            {func(w *world) { w.envRule("exclude", "*_token", model.RuleDeny) }, model.ReachBlocked, "*_token"},
		"an include list leaves it out": {func(w *world) { w.envRule("include_only", "PATH", model.RuleAllow) }, model.ReachBlocked, "include"},
		"an include list keeps it":      {func(w *world) { w.envRule("filters", "NPM_*", model.RuleAllow) }, model.ReachSilent, "NPM_*"},
	} {
		t.Run(name, func(t *testing.T) {
			w := codexWorld(t, "NPM_TOKEN=x\n")
			w.creds = append(w.creds, model.Credential{Kind: "env_var", Name: w.text("NPM_TOKEN"), Via: w.text("environment"), Read: model.ReadExistsOnly})
			tc.set(w)
			if got, why := w.codexVerdict("NPM_TOKEN"); got != tc.want || !strings.Contains(why, tc.why) {
				t.Errorf("codex env = %s (%q), want %s with a reason naming %q", got, why, tc.want, tc.why)
			}
		})
	}
}

func TestBothAgentsGetVerdictsInAProjectBothKnow(t *testing.T) {
	w := newWorld(t, "linux", "")
	w.proj.Origins = append(w.proj.Origins, model.Origin{Agent: model.AgentCodex, InEffect: true})

	agents := map[model.Agent]bool{}
	for _, r := range w.settle()[0].Reach {
		agents[r.Agent] = true
	}
	if !agents[model.AgentClaude] || !agents[model.AgentCodex] {
		t.Errorf("agents with verdicts = %v, want both", agents)
	}
}

// denyAWS is a custom profile that denies ~/.aws and extends :workspace.
func (w *world) denyAWS() {
	w.codexOption("default_permissions", profile).codexOption("permissions."+profile+".extends", ":workspace").
		profileRule("~/.aws", model.RuleDeny)
}

func TestCodexDenyOnNativeWindows(t *testing.T) {
	for name, tc := range map[string]struct {
		goos string
		set  func(*world)
		want model.ReachVerdict
		why  string
	}{
		"no implementation set: unelevated may run": {"windows", func(*world) {}, model.ReachBypassable, "unelevated"},
		"mxc pinned":                {"windows", func(w *world) { w.codexOption("windows.sandbox", "mxc") }, model.ReachApproval, "denies it"},
		"mxc pinned but prohibited": {"windows", func(w *world) { w.codexOption("windows.sandbox", "mxc").codexOption("windows.allow_mxc", "false") }, model.ReachBypassable, "unelevated"},
		"requirements rule unelevated out": {"windows", func(w *world) {
			w.codexOption("windows.allowed_sandbox_implementations", "elevated")
		}, model.ReachApproval, "denies it"},
		"elevated chosen, unelevated still allowed": {"windows", func(w *world) {
			w.codexOption("windows.sandbox", "elevated").codexOption("windows.allowed_sandbox_implementations", "elevated, unelevated")
		}, model.ReachBypassable, "falls back"},
		"linux enforces it": {"linux", func(*world) {}, model.ReachApproval, "denies it"},
	} {
		t.Run(name, func(t *testing.T) {
			w := codexWorldOn(t, tc.goos, "")
			w.denyAWS()
			tc.set(w)
			if got, why := w.codexVerdict(awsCreds); got != tc.want || !strings.Contains(why, tc.why) {
				t.Errorf("codex shell = %s (%q), want %s with a reason naming %q", got, why, tc.want, tc.why)
			}
		})
	}
}

func TestACodexGlobDenyNotesItsSnapshot(t *testing.T) {
	w := codexWorld(t, "")
	env := w.proj.Path.Raw() + "/.env"
	w.proj.Credentials = []model.Credential{{Kind: "env_file", Path: model.NewPath(w.s, env), Read: model.ReadOK}}
	w.codexOption("default_permissions", profile).codexOption("permissions."+profile+".extends", ":workspace").
		profileRule(":workspace_roots/**/.env", model.RuleDeny).codexOption("approval_policy", "never")

	if got, why := w.codexVerdict(env); got != model.ReachBlocked || !strings.Contains(why, "created later") {
		t.Errorf("codex shell = %s (%q), want blocked with the snapshot note", got, why)
	}
}

func TestACodexDenyTheUnelevatedSandboxIgnoresIsFlagged(t *testing.T) {
	w := codexWorldOn(t, "windows", "")
	w.denyAWS()

	var found bool
	for _, f := range w.analyze() {
		if f.RuleID == BypassableDeny().ID && f.Origin.Agent == model.AgentCodex {
			found = strings.Contains(f.Evidence.String(), "~/.aws") && strings.Contains(f.Origin.File.Raw(), "config.toml")
		}
	}
	if !found {
		t.Error("want REACH-002 for codex on the profile deny's file")
	}
}

func TestACodexDenyOnLinuxIsntFlagged(t *testing.T) {
	w := codexWorld(t, "")
	w.denyAWS()

	for _, f := range w.analyze() {
		if f.RuleID == BypassableDeny().ID {
			t.Errorf("REACH-002 on Linux, where the sandbox enforces the deny: %+v", f)
		}
	}
}
