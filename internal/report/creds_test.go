package report

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/redact"
)

func (f scanFixture) cred(kind, rel string, read model.ReadStatus, via string, facts ...[2]string) model.Credential {
	cr := model.Credential{Kind: model.CredentialKind(kind), Path: f.path(rel), Read: read}
	if via != "" {
		cr.Via = f.text(via)
	}
	for _, fa := range facts {
		cr.Facts = append(cr.Facts, model.Pair{Key: f.text(fa[0]), Value: f.text(fa[1])})
	}
	return cr
}

func TestCredentialLocationsAreCountedWithWhatCouldntBeRead(t *testing.T) {
	f := newScanFixture(t)
	v := f.view()
	v.Credentials = []model.Credential{
		f.cred("aws", ".aws/credentials", model.ReadOK, "default", [2]string{"profile dev", "static keys"}),
		f.cred("gh", ".config/gh/hosts.yml", model.ReadFailed, "default"),
	}
	v.Projects[0].Credentials = []model.Credential{f.cred("env_file", "app/.env", model.ReadOK, "", [2]string{"key", "API_KEY"})}

	out := render(Style{Width: 80}, v)

	if want := "+- 3 credential locations            1 couldn't read\n"; !strings.Contains(out, want) {
		t.Errorf("output =\n%s\nwant the scanned row %q", out, want)
	}
}

func TestTheInventoryListsEachCredentialWithItsFacts(t *testing.T) {
	f := newScanFixture(t)
	v := f.view()
	v.All = true
	v.Credentials = []model.Credential{
		f.cred("aws", ".aws/credentials", model.ReadOK, "default", [2]string{"profile dev", "static keys"}, [2]string{"profile ci", ""}),
		f.cred("gh", "cfg/gh/hosts.yml", model.ReadOK, "GH_CONFIG_DIR", [2]string{"host github.com", "user octocat, no token in the file"}),
		f.cred("claude_login", ".claude/.credentials.json", model.ReadExistsOnly, "default"),
	}
	v.Projects[0].Credentials = []model.Credential{f.cred("env_file", "app/.env", model.ReadOK, "", [2]string{"key", "API_KEY"}, [2]string{"key", "DB_URL"})}

	out := render(Style{Width: 200}, v)

	for _, want := range []string{
		"credentials (3)\n",
		"  aws  " + filepath.FromSlash("~/.aws/credentials") + "  profile dev: static keys; profile ci\n",
		"  gh  " + filepath.FromSlash("~/cfg/gh/hosts.yml") + "  via GH_CONFIG_DIR  host github.com: user octocat, no token in the file\n",
		"  claude_login  " + filepath.FromSlash("~/.claude/.credentials.json") + "  existence only\n",
		"    credentials\n      env_file  " + filepath.FromSlash("~/app/.env") + "  key: API_KEY; key: DB_URL\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output =\n%s\nwant it to contain %q", out, want)
		}
	}
}

func TestAnEnvVarCredentialShowsItsName(t *testing.T) {
	f := newScanFixture(t)
	v := f.view()
	v.All = true
	v.Credentials = []model.Credential{{Kind: "env_var", Name: f.text("GITHUB_TOKEN"), Via: f.text("environment"), Read: model.ReadExistsOnly}}

	if out := render(Style{Width: 200}, v); !strings.Contains(out, "  env_var  GITHUB_TOKEN  via environment  existence only\n") {
		t.Errorf("output =\n%s\nwant the env var by name", out)
	}
}

func TestEachEnvVarCountsAsALocation(t *testing.T) {
	f := newScanFixture(t)
	v := f.view()
	v.Credentials = []model.Credential{
		{Kind: "env_var", Name: f.text("GITHUB_TOKEN"), Read: model.ReadExistsOnly},
		{Kind: "env_var", Name: f.text("NPM_TOKEN"), Read: model.ReadExistsOnly},
	}

	if out := render(Style{Width: 80}, v); !strings.Contains(out, "+- 2 credential locations\n") {
		t.Errorf("output =\n%s\nwant both env vars counted", out)
	}
}

func TestTheInventoryListsEachProjectsReach(t *testing.T) {
	f := newScanFixture(t)
	v := f.view()
	v.All = true
	v.Projects[0].Reach = []model.Reach{
		{Agent: model.AgentClaude, Kind: "aws", Path: f.path(".aws/credentials"), Channel: model.ChannelFileTools, Verdict: model.ReachApproval,
			Why: []redact.Text{f.text("it's outside the working dirs, where Read asks")}},
		{Agent: model.AgentClaude, Kind: "aws", Path: f.path(".aws/credentials"), Channel: model.ChannelShell, Verdict: model.ReachSilent,
			Why: []redact.Text{f.text("cat and grep are in the read-only set"), f.text("the sandbox is off")}},
		{Agent: model.AgentClaude, Kind: "env_var", Name: f.text("GITHUB_TOKEN"), Channel: model.ChannelShell, Verdict: model.ReachSilent,
			Why: []redact.Text{f.text("Bash inherits Claude's env")}},
	}

	out := render(Style{Width: 200}, v)

	for _, want := range []string{
		"    claude reach\n      aws  " + filepath.FromSlash("~/.aws/credentials") + "\n" +
			"        file tools  needs approval: it's outside the working dirs, where Read asks\n" +
			"        shell  readable silently: cat and grep are in the read-only set; the sandbox is off\n",
		"      env_var  GITHUB_TOKEN\n        shell  readable silently: Bash inherits Claude's env\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output =\n%s\nwant it to contain %q", out, want)
		}
	}
}

func (f scanFixture) exposure(a model.Agent, kind, rel string, via string, ss ...model.CredentialState) model.Exposure {
	e := model.Exposure{Agent: a, Kind: model.CredentialKind(kind), Path: f.path(rel), States: ss}
	if via != "" {
		e.Via = []redact.Text{f.text(via)}
	}
	return e
}

func TestEachProjectSaysWhatItsCredentialsAre(t *testing.T) {
	f := newScanFixture(t)
	v := f.view()
	v.Projects[0].Exposure = []model.Exposure{
		f.exposure(model.AgentClaude, "aws", ".aws/credentials", "", model.StateCanRead),
		f.exposure(model.AgentClaude, "env_var", "", "MCP server notes holds it", model.StateCanRead, model.StateCanUse),
		f.exposure(model.AgentClaude, "secret_in_text", "app/CLAUDE.md", "github_pat", model.StateSees),
		f.exposure(model.AgentCodex, "aws", ".aws/credentials", "", model.StateUnreachable),
	}

	out := render(Style{Width: 120}, v)

	if want := `\- credentials: claude 1 sees - 2 can read - 1 can use - codex 1 not reachable` + "\n"; !strings.Contains(out, want) {
		t.Errorf("output =\n%s\nwant the project's credential line %q", out, want)
	}
}

func TestTheInventoryHasTheCredentialView(t *testing.T) {
	f := newScanFixture(t)
	v := f.view()
	v.All = true
	v.Projects[0].Exposure = []model.Exposure{
		f.exposure(model.AgentClaude, "secret_in_text", "app/CLAUDE.md", "github_pat, fingerprint FP", model.StateSees),
		f.exposure(model.AgentClaude, "aws", ".aws/credentials", "", model.StateCanRead, model.StateCanUse),
	}

	out := render(Style{Width: 200}, v)

	want := "    claude credential view\n" +
		"      secret_in_text  " + filepath.FromSlash("~/app/CLAUDE.md") + "  sees: github_pat, fingerprint FP\n" +
		"      aws  " + filepath.FromSlash("~/.aws/credentials") + "  can read, can use\n"
	if !strings.Contains(out, want) {
		t.Errorf("output =\n%s\nwant it to contain %q", out, want)
	}
}
