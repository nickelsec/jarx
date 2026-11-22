package codex

import (
	"testing"

	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/platform"
)

func unknownsFor(t *testing.T, files map[string]string, system func(platform.Env) map[string]string, projects int) map[string]model.Unknown {
	t.Helper()
	c := systemHome(t, files, system)
	ps := make([]model.Project, 0, projects)
	for range projects {
		ps = append(ps, model.Project{
			Path: model.NewPath(c.Scrub, c.Env.MapPath("/p")), Status: model.ProjectOK,
			Trust: []model.Trust{{Level: model.TrustTrusted, Origin: model.Origin{Agent: model.AgentCodex}}},
		})
	}
	unknown, _ := Adapter{}.Settings(c, ps)
	out := map[string]model.Unknown{}
	for _, u := range unknown {
		if _, dup := out[u.Key.String()]; dup {
			t.Errorf("%s reported twice", u.Key)
		}
		out[u.Key.String()] = u
	}
	return out
}

const knownConfig = `model = "o3"
approval_policy = "on-request"
profile = "old"
[profiles.old]
model = "o3"
[features]
codex_hooks = true
[mcp_servers.gh]
command = "gh-mcp"
[mcp_servers.gh.env]
ANY_NAME_YOU_LIKE = "x"
[projects."/p"]
trust_level = "trusted"
[[hooks.PreToolUse]]
matcher = "Bash"
[[hooks.PreToolUse.hooks]]
type = "command"
command = "echo hi"
command_windows = "echo hi"
`

func TestDocumentedCodexKeysArentUnknown(t *testing.T) {
	got := unknownsFor(t, map[string]string{".codex/config.toml": knownConfig}, nil, 1)

	if len(got) != 0 {
		t.Errorf("unknown = %+v, want none: every key here is in the config reference, or a legacy profile key CODEX-004 covers", got)
	}
}

func TestCodexTyposGetTheKeyTheyWereMeantToBe(t *testing.T) {
	got := unknownsFor(t, map[string]string{
		".codex/config.toml": `aproval_policy = "never"
brand_new_key = true
[sandbox_workspace_write]
network_acess = true
[mcp_servers.gh]
comand = "gh-mcp"
`,
	}, nil, 1)

	for key, near := range map[string]string{
		"aproval_policy":                        "approval_policy",
		"brand_new_key":                         "",
		"sandbox_workspace_write.network_acess": "sandbox_workspace_write.network_access",
		"mcp_servers.gh.comand":                 "mcp_servers.gh.command",
	} {
		u, ok := got[key]
		if !ok || u.Near.String() != near {
			t.Errorf("%s = %+v (found %v), want near %q; all: %v", key, u, ok, near, got)
		}
	}
}

func TestHooksAreLeftToTheHooksGuide(t *testing.T) {
	// The reference says [hooks] uses the hooks.json schema from the Hooks
	// guide and doesn't list the handler fields, so jarx doesn't judge them.
	got := unknownsFor(t, map[string]string{".codex/config.toml": `[[hooks.PreToolUse]]
matcher = "Bash"
[[hooks.PreToolUse.hooks]]
type = "command"
comand = "echo hi"
`}, nil, 1)

	if len(got) != 0 {
		t.Errorf("unknown = %v, want nothing reported inside [hooks]", got)
	}
}

func TestRequirementsKeysUseTheirOwnTable(t *testing.T) {
	got := unknownsFor(t, map[string]string{}, func(env platform.Env) map[string]string {
		return map[string]string{requirementsFile(env): "allowed_sandbox_mode = [\"read-only\"]\nallowed_approval_policies = [\"on-request\"]\n"}
	}, 1)

	u, ok := got["allowed_sandbox_mode"]
	if !ok || u.Near.String() != "allowed_sandbox_modes" || u.Origin.Scope != model.ScopeRequirements {
		t.Errorf("unknown = %+v, want the requirements typo with its near key and scope", got)
	}
	if _, ok := got["allowed_approval_policies"]; ok {
		t.Error("allowed_approval_policies reported, want it known")
	}
}

func TestAFileSharedByProjectsIsReportedOnce(t *testing.T) {
	// unknownsFor fails on a key reported twice.
	got := unknownsFor(t, map[string]string{".codex/config.toml": "aproval_policy = \"never\"\n"}, nil, 2)

	if _, ok := got["aproval_policy"]; !ok {
		t.Errorf("unknown = %v, want the typo once", got)
	}
}
