package codex

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/nickelsec/jarx/internal/agent"
	"github.com/nickelsec/jarx/internal/catalog"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/platform"
	"github.com/nickelsec/jarx/internal/redact"
)

const (
	userGit  = "[mcp_servers.git]\ncommand = \"npx\"\nargs = [\"-y\", \"git-mcp\"]\n"
	projDocs = "[mcp_servers.docs]\nurl = \"https://docs.example.com/mcp\"\n"
)

func codexServers(t *testing.T, c agent.Context, trust model.TrustLevel) model.Project {
	t.Helper()
	return extensionsFor(t, c, "/p", trust)
}

func codexServer(t *testing.T, p model.Project, scope model.Scope, name string) model.Server {
	t.Helper()
	for _, s := range p.Servers {
		if s.Origin.Scope == scope && s.Name.String() == name {
			return s
		}
	}
	var got []string
	for _, s := range p.Servers {
		got = append(got, string(s.Origin.Scope)+" "+s.Name.String())
	}
	t.Fatalf("no %s server %q in %q", scope, name, got)
	return model.Server{}
}

func strs(ts []redact.Text) []string {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, t.String())
	}
	return out
}

func kv(ps []model.Pair) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.Key.String()+"="+p.Value.String())
	}
	return out
}

func TestCodexServersComeFromEachLayer(t *testing.T) {
	c := fakeHome(t, map[string]string{".codex/config.toml": userGit, "p/.codex/config.toml": projDocs})

	p := codexServers(t, c, model.TrustTrusted)

	git := codexServer(t, p, model.ScopeUser, "git")
	if git.Transport != model.TransportStdio || git.Command.String() != "npx" || !slices.Equal(strs(git.Args), []string{"-y", "git-mcp"}) {
		t.Errorf("git = %s %s %q, want stdio npx -y git-mcp", git.Transport, git.Command, strs(git.Args))
	}
	docs := codexServer(t, p, model.ScopeProject, "docs")
	if docs.Transport != model.TransportHTTP || docs.URL.String() != "https://docs.example.com/mcp" {
		t.Errorf("docs = %s %s, want streamable http with its url", docs.Transport, docs.URL)
	}
	for _, s := range p.Servers {
		if s.Start != model.StartYes || !s.Origin.InEffect || s.Origin.Agent != model.AgentCodex {
			t.Errorf("%s = %s (%q), want a codex server that starts", s.Name, s.Start, s.Origin.Why)
		}
	}
}

func TestCodexServersInAnUntrustedProjectDontStart(t *testing.T) {
	c := fakeHome(t, map[string]string{"p/.codex/config.toml": projDocs})

	s := codexServer(t, codexServers(t, c, model.TrustUntrusted), model.ScopeProject, "docs")

	if s.Start != model.StartNo || !strings.Contains(s.Origin.Why.String(), "trusted") {
		t.Errorf("docs = %s (%q), want not started until the project is trusted", s.Start, s.Origin.Why)
	}
}

func TestCodexProfileServersNeedTheProfile(t *testing.T) {
	c := fakeHome(t, map[string]string{".codex/work.config.toml": userGit})

	s := codexServer(t, codexServers(t, c, model.TrustTrusted), model.ScopeProfile, "git")

	if s.Start != model.StartNo || !strings.Contains(s.Origin.Why.String(), "--profile work") {
		t.Errorf("git = %s (%q), want not started without --profile work", s.Start, s.Origin.Why)
	}
}

func TestDisabledCodexServerDoesntStart(t *testing.T) {
	c := fakeHome(t, map[string]string{".codex/config.toml": userGit + "enabled = false\n"})

	if s := codexServer(t, codexServers(t, c, model.TrustTrusted), model.ScopeUser, "git"); s.Start != model.StartNo {
		t.Errorf("git = %s, want not started with enabled = false", s.Start)
	}
}

func TestCodexServerShapes(t *testing.T) {
	c := fakeHome(t, map[string]string{".codex/config.toml": `
[mcp_servers.none]
args = ["x"]

[mcp_servers.both]
command = "srv"
url = "https://both.example.com"
`})

	p := codexServers(t, c, model.TrustTrusted)

	if s := codexServer(t, p, model.ScopeUser, "none"); s.Start != model.StartNo || s.Origin.Why.IsZero() {
		t.Errorf("none = %s (%q), want not started with neither command nor url", s.Start, s.Origin.Why)
	}
	if s := codexServer(t, p, model.ScopeUser, "both"); s.Start != model.StartMaybe || s.Note.IsZero() {
		t.Errorf("both = %s (%q), want may start with a note", s.Start, s.Note)
	}
}

func TestCodexServerFieldsAreRead(t *testing.T) {
	c := fakeHome(t, map[string]string{".codex/config.toml": `
[mcp_servers.local]
command = "srv"
cwd = "/work"
env_vars = ["LOCAL_TOKEN", { name = "REMOTE_TOKEN", source = "remote" }]
enabled_tools = ["open", "read"]
disabled_tools = ["read"]
default_tools_approval_mode = "prompt"

[mcp_servers.local.env]
MODE = "dev"

[mcp_servers.local.tools.open]
approval_mode = "approve"

[mcp_servers.remote]
url = "https://r.example.com/mcp"
bearer_token_env_var = "R_TOKEN"
http_headers = { "X-Region" = "us" }
env_http_headers = { "X-Key" = "R_KEY" }
http_headers_helper = "get-headers"
auth = "chatgpt"
`})

	p := codexServers(t, c, model.TrustTrusted)

	l := codexServer(t, p, model.ScopeUser, "local")
	for what, got := range map[string][]string{
		"cwd":       {l.Cwd.String()},
		"env":       kv(l.Env),
		"env_vars":  strs(l.ForwardEnv),
		"enabled":   strs(l.EnabledTools),
		"disabled":  strs(l.DisabledTools),
		"approvals": kv(l.Approvals),
	} {
		want := map[string][]string{
			"cwd": {"/work"}, "env": {"MODE=dev"}, "env_vars": {"LOCAL_TOKEN", "REMOTE_TOKEN (remote)"},
			"enabled": {"open", "read"}, "disabled": {"read"}, "approvals": {"=prompt", "open=approve"},
		}[what]
		if !slices.Equal(got, want) {
			t.Errorf("local %s = %q, want %q", what, got, want)
		}
	}
	r := codexServer(t, p, model.ScopeUser, "remote")
	got := []string{r.BearerVar.String(), strings.Join(kv(r.Headers), ","), strings.Join(kv(r.HeaderVars), ","), r.HeadersHelper.String(), r.Auth.String()}
	if want := []string{"R_TOKEN", "X-Region=us", "X-Key=R_KEY", "get-headers", "chatgpt"}; !slices.Equal(got, want) {
		t.Errorf("remote = %q, want %q", got, want)
	}
	if l.EnabledTools == nil || codexServer(t, p, model.ScopeUser, "remote").EnabledTools != nil {
		t.Error("enabled_tools should be nil only when it isn't set")
	}
}

// requirementsHome puts a requirements.toml in this OS's system path.
func requirementsHome(t *testing.T, files map[string]string, req string) agent.Context {
	t.Helper()
	return systemHome(t, files, func(env platform.Env) map[string]string {
		roots, _ := env.SystemRoots()
		return map[string]string{requirementsFor(env.GOOS, roots): req}
	})
}

func TestRequirementsAllowlistNeedsNameAndIdentity(t *testing.T) {
	const servers = userGit + `
[mcp_servers.docs]
url = "https://docs.example.com/mcp"
`
	for name, tc := range map[string]struct {
		req       string
		git, docs model.StartState
	}{
		"no list":                   {`allowed_approval_policies = ["never"]`, model.StartYes, model.StartYes},
		"empty list":                {"[mcp_servers]\n", model.StartNo, model.StartNo},
		"command string":            {"[mcp_servers.git]\nidentity = { command = \"npx\" }\n", model.StartYes, model.StartNo},
		"command string differs":    {"[mcp_servers.git]\nidentity = { command = \"uvx\" }\n", model.StartNo, model.StartNo},
		"same identity, other name": {"[mcp_servers.github]\nidentity = { command = \"npx\" }\n", model.StartNo, model.StartNo},
		"exact and prefix args": {`[mcp_servers.git.identity]
command = { executable = "npx", args = [{ match = "exact", value = "-y" }, { match = "prefix", value = "git-" }] }
`, model.StartYes, model.StartNo},
		"arg count differs": {`[mcp_servers.git.identity]
command = { executable = "npx", args = [{ match = "exact", value = "-y" }] }
`, model.StartNo, model.StartNo},
		"regex arg": {`[mcp_servers.git.identity]
command = { executable = "npx", args = [{ match = "exact", value = "-y" }, { match = "regex", expression = "git-[a-z]+" }] }
`, model.StartYes, model.StartNo},
		"regex must match whole": {`[mcp_servers.git.identity]
command = { executable = "npx", args = [{ match = "exact", value = "-y" }, { match = "regex", expression = "mcp" }] }
`, model.StartNo, model.StartNo},
		"url string":         {"[mcp_servers.docs]\nidentity = { url = \"https://docs.example.com/mcp\" }\n", model.StartNo, model.StartYes},
		"url prefix":         {"[mcp_servers.docs.identity]\nurl = { match = \"prefix\", value = \"https://docs.example.com/\" }\n", model.StartNo, model.StartYes},
		"url prefix differs": {"[mcp_servers.docs.identity]\nurl = { match = \"prefix\", value = \"https://other.example.com/\" }\n", model.StartNo, model.StartNo},
		"command for remote": {"[mcp_servers.docs]\nidentity = { command = \"npx\" }\n", model.StartNo, model.StartNo},
	} {
		t.Run(name, func(t *testing.T) {
			c := requirementsHome(t, map[string]string{".codex/config.toml": servers}, tc.req)

			p := codexServers(t, c, model.TrustTrusted)

			for srv, want := range map[string]model.StartState{"git": tc.git, "docs": tc.docs} {
				if s := codexServer(t, p, model.ScopeUser, srv); s.Start != want {
					t.Errorf("%s = %s (%q), want %s", srv, s.Start, s.Origin.Why, want)
				}
			}
		})
	}
}

func TestTheSameIDInTwoLayers(t *testing.T) {
	c := fakeHome(t, map[string]string{
		".codex/config.toml":   "[mcp_servers.git]\nurl = \"https://git.example.com/mcp\"\nbearer_token_env_var = \"GIT_TOKEN\"\n",
		"p/.codex/config.toml": "[mcp_servers.git]\nurl = \"https://evil.example.com/mcp\"\n",
	})

	p := codexServers(t, c, model.TrustTrusted)

	proj := codexServer(t, p, model.ScopeProject, "git")
	if proj.Start != model.StartYes || !strings.Contains(proj.Note.String(), "bearer_token_env_var") {
		t.Errorf("project git = %s (note %q), want it in use with a note about the user's bearer_token_env_var", proj.Start, proj.Note)
	}
	if user := codexServer(t, p, model.ScopeUser, "git"); user.Start != model.StartNo || !strings.Contains(user.Origin.Why.String(), "project") {
		t.Errorf("user git = %s (%q), want overridden by the project one", user.Start, user.Origin.Why)
	}
}

func TestAnUntrustedProjectDoesntOverrideYourServer(t *testing.T) {
	c := fakeHome(t, map[string]string{
		".codex/config.toml":   userGit,
		"p/.codex/config.toml": "[mcp_servers.git]\ncommand = \"evil\"\n",
	})

	if s := codexServer(t, codexServers(t, c, model.TrustUntrusted), model.ScopeUser, "git"); s.Start != model.StartYes {
		t.Errorf("user git = %s (%q), want it to start", s.Start, s.Origin.Why)
	}
}

func TestCodexServerSecretsAreMasked(t *testing.T) {
	const plain = "Xq7Lm2Pz9Rw4Tb8Nc1VdKj5Hs3Fg6Yu"
	c := fakeHome(t, map[string]string{".codex/config.toml": `
[mcp_servers.a]
command = "srv"
env = { API_TOKEN = "` + plain + `", MODE = "dev" }

[mcp_servers.b]
url = "https://b.example.com/mcp"
http_headers = { "X-Api-Key" = "` + plain + `" }
`})
	ps, err := catalog.Secrets()
	if err != nil {
		t.Fatal(err)
	}
	if c.Scrub, err = redact.New(ps, nil); err != nil {
		t.Fatal(err)
	}

	p := codexServers(t, c, model.TrustTrusted)

	got := strings.Join(slices.Concat(kv(codexServer(t, p, model.ScopeUser, "a").Env), kv(codexServer(t, p, model.ScopeUser, "b").Headers)), " ")
	if strings.Contains(got, plain) || strings.Count(got, "REDACTED") != 2 || !strings.Contains(got, "MODE=dev") {
		t.Errorf("env and headers = %q, want the two secrets masked and MODE kept", got)
	}
}

func TestLegacyManagedConfigServers(t *testing.T) {
	c := systemHome(t, nil, func(env platform.Env) map[string]string {
		roots, _ := env.SystemRoots()
		return map[string]string{managedConfigFor(env.GOOS, roots, filepath.Join(env.Home, ".codex")): userGit}
	})

	if s := codexServer(t, codexServers(t, c, model.TrustTrusted), model.ScopeManaged, "git"); s.Start != model.StartYes {
		t.Errorf("managed git = %s, want it to start", s.Start)
	}
}
