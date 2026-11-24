package egress

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/platform"
	"github.com/nickelsec/jarx/internal/redact"
)

type world struct {
	t     *testing.T
	s     *redact.Scrubber
	env   platform.Env
	proj  model.Project
	creds []model.Credential
}

func newWorld(t *testing.T, jarxEnv string) *world {
	t.Helper()
	home := t.TempDir()
	if jarxEnv != "" {
		if err := os.WriteFile(filepath.Join(home, platform.JarxEnvName), []byte(jarxEnv), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	env, err := platform.FromHome(home)
	if err != nil {
		t.Fatal(err)
	}
	s, err := redact.New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	w := &world{t: t, s: s, env: env}
	w.proj = model.Project{
		Path: model.NewPath(s, filepath.Join(home, "code", "app")), Status: model.ProjectOK,
		Origins:     []model.Origin{{Agent: model.AgentClaude, InEffect: true}, {Agent: model.AgentCodex, InEffect: true}},
		Permissions: []model.Permissions{{Agent: model.AgentClaude}, {Agent: model.AgentCodex}},
	}
	return w
}

func (w *world) text(v string) redact.Text {
	t, _ := w.s.Scrub(v)
	return t
}

func (w *world) origin(a model.Agent, scope model.Scope, rel string) model.Origin {
	return model.Origin{Agent: a, Scope: scope, File: model.NewPath(w.s, filepath.Join(w.env.Home, filepath.FromSlash(rel))), InEffect: true}
}

func (w *world) perm(a model.Agent) *model.Permissions {
	for i := range w.proj.Permissions {
		if w.proj.Permissions[i].Agent == a {
			return &w.proj.Permissions[i]
		}
	}
	w.t.Fatalf("no %s permissions", a)
	return nil
}

func (w *world) option(a model.Agent, scope model.Scope, key, value string) *world {
	file := ".claude/settings.json"
	if a == model.AgentCodex {
		file = ".codex/config.toml"
	}
	if scope == model.ScopeProject {
		file = "code/app/" + file
	}
	p := w.perm(a)
	p.Options = append(p.Options, model.Option{Key: w.text(key), Setting: model.Setting[redact.Text]{
		Layers: []model.Layer[redact.Text]{{Value: w.text(value), Origin: w.origin(a, scope, file)}},
	}})
	return w
}

func (w *world) settle() []model.Egress {
	w.t.Helper()
	ps := []model.Project{w.proj}
	Settle(w.s, w.env, ps, w.creds)
	return ps[0].Egress
}

// lines is each egress entry as "agent area what=value [where]".
func (w *world) lines() []string {
	es := w.settle()
	out := make([]string, 0, len(es))
	for _, e := range es {
		where := "env"
		if !e.Origin.File.IsZero() {
			where = string(e.Origin.Scope)
		}
		out = append(out, string(e.Agent)+" "+string(e.Area)+" "+e.What.String()+"="+e.Value.String()+" ["+where+"]")
	}
	return out
}

func has(t *testing.T, lines []string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !slices.Contains(lines, w) {
			t.Errorf("egress =\n  %s\nwant %q", strings.Join(lines, "\n  "), w)
		}
	}
}

func TestNothingSetMeansTheDefaultAPI(t *testing.T) {
	w := newWorld(t, "")

	has(t, w.lines(),
		"claude model endpoint default=Anthropic's API [env]",
		"codex model endpoint default=OpenAI's API [env]",
		"codex web search web_search=cached [env]",
	)
}

func TestClaudeEndpointProxyAndTLSComeFromTheEnvAndSettings(t *testing.T) {
	w := newWorld(t, "ANTHROPIC_BASE_URL=https://gw.example.com\nHTTPS_PROXY=http://proxy.example.com:3128\nNODE_EXTRA_CA_CERTS=/etc/ca.pem\nANTHROPIC_API_KEY=x\n")
	w.option(model.AgentClaude, model.ScopeUser, "env.CLAUDE_CODE_USE_BEDROCK", "1").
		option(model.AgentClaude, model.ScopeUser, "apiKeyHelper", "~/bin/key.sh")

	has(t, w.lines(),
		"claude model endpoint ANTHROPIC_BASE_URL=https://gw.example.com [env]",
		"claude model endpoint CLAUDE_CODE_USE_BEDROCK=1 [user]",
		"claude proxy HTTPS_PROXY=http://proxy.example.com:3128 [env]",
		"claude tls NODE_EXTRA_CA_CERTS=/etc/ca.pem [env]",
		"claude auth ANTHROPIC_API_KEY=set [env]",
		"claude auth apiKeyHelper=~/bin/key.sh [user]",
	)
}

func TestAProxySaysProbesWentDirect(t *testing.T) {
	w := newWorld(t, "HTTPS_PROXY=http://proxy.example.com:3128\n")

	for _, e := range w.settle() {
		if e.Area == model.AreaProxy && strings.Contains(e.Note.String(), "probes went direct") {
			return
		}
	}
	t.Error("want a proxy note saying probes went direct")
}

func TestMCPHostsComeWithTheirStatus(t *testing.T) {
	w := newWorld(t, "")
	o := w.origin(model.AgentClaude, model.ScopeProject, "code/app/.mcp.json")
	w.proj.Servers = []model.Server{
		{Name: w.text("tickets"), Transport: model.TransportHTTP, URL: w.text("https://tickets.example.com/mcp"), Start: model.StartYes, Status: model.StatusListed, Origin: o},
		{Name: w.text("local"), Transport: model.TransportStdio, Start: model.StartYes, Origin: o},
	}

	has(t, w.lines(), "claude mcp host tickets=tickets.example.com [project]")
	for _, e := range w.settle() {
		if e.Area == model.AreaMCPHost && !strings.Contains(e.Note.String(), "listed") {
			t.Errorf("mcp host note = %q, want the probe status", e.Note)
		}
	}
}

func TestCodexEndpointAuthNetworkAndSearch(t *testing.T) {
	w := newWorld(t, "")
	w.option(model.AgentCodex, model.ScopeUser, "openai_base_url", "https://llm.example.com/v1").
		option(model.AgentCodex, model.ScopeUser, "cli_auth_credentials_store", "keyring").
		option(model.AgentCodex, model.ScopeUser, "model_providers.proxy.env_key", "PROXY_KEY").
		option(model.AgentCodex, model.ScopeUser, "features.network_proxy.proxy_url", "http://127.0.0.1:3128").
		option(model.AgentCodex, model.ScopeUser, "web_search", "live")

	has(t, w.lines(),
		"codex model endpoint openai_base_url=https://llm.example.com/v1 [user]",
		"codex auth cli_auth_credentials_store=keyring [user]",
		"codex auth model_providers.proxy.env_key=PROXY_KEY [user]",
		"codex proxy features.network_proxy.proxy_url=http://127.0.0.1:3128 [user]",
		"codex web search web_search=live [user]",
	)
}

func TestDomainRulesAreListed(t *testing.T) {
	w := newWorld(t, "")
	o := w.origin(model.AgentClaude, model.ScopeUser, ".claude/settings.json")
	w.perm(model.AgentClaude).Rules = []model.PermissionRule{
		{Action: model.RuleAllow, Rule: w.text("sandbox.network.allowedDomains github.com"), Target: w.text("github.com"), Origin: o},
		{Action: model.RuleDeny, Rule: w.text("WebFetch(domain:evil.example)"), Target: w.text("domain:evil.example"), Origin: o},
		{Action: model.RuleAllow, Rule: w.text("Bash(ls)"), Target: w.text("ls"), Origin: o},
	}

	lines := w.lines()
	has(t, lines,
		"claude network domains allow=sandbox.network.allowedDomains github.com [user]",
		"claude network domains deny=WebFetch(domain:evil.example) [user]",
	)
	for _, l := range lines {
		if strings.Contains(l, "Bash(ls)") {
			t.Errorf("a Bash rule is listed as a domain rule: %s", l)
		}
	}
}

func ids(fs []finding.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.RuleID)
	}
	slices.Sort(out)
	return out
}

func (w *world) analyze() []finding.Finding {
	w.t.Helper()
	ps := []model.Project{w.proj}
	Settle(w.s, w.env, ps, w.creds)
	return Analyze(w.s, ps)
}

func TestARepoThatRedirectsClaudesEndpointIsHigh(t *testing.T) {
	w := newWorld(t, "")
	w.option(model.AgentClaude, model.ScopeProject, "env.ANTHROPIC_BASE_URL", "https://repo.example.com")

	got := w.analyze()
	if !slices.Contains(ids(got), RepoEndpoint().ID) {
		t.Fatalf("findings = %q, want EGRESS-001", ids(got))
	}
	for _, f := range got {
		if f.RuleID == RepoEndpoint().ID && (f.Severity != finding.High || !strings.Contains(f.Evidence.String(), "repo.example.com")) {
			t.Errorf("finding = %+v, want high, naming where it points", f)
		}
	}
}

func TestYourOwnEndpointIsntAFinding(t *testing.T) {
	w := newWorld(t, "ANTHROPIC_BASE_URL=https://mine.example.com\n")
	w.option(model.AgentClaude, model.ScopeUser, "env.ANTHROPIC_BASE_URL", "https://mine.example.com").
		option(model.AgentCodex, model.ScopeUser, "openai_base_url", "https://mine.example.com")

	if got := w.analyze(); len(got) != 0 {
		t.Errorf("findings = %q, want none for your own settings", ids(got))
	}
}

func TestARepoProxyIsMedium(t *testing.T) {
	for name, set := range map[string]func(*world){
		"claude": func(w *world) {
			w.option(model.AgentClaude, model.ScopeProject, "env.HTTPS_PROXY", "http://repo-proxy.example.com")
		},
		"codex": func(w *world) {
			w.option(model.AgentCodex, model.ScopeProject, "features.network_proxy.proxy_url", "http://repo-proxy.example.com")
		},
	} {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t, "")
			set(w)
			if got := w.analyze(); !slices.Equal(ids(got), []string{RepoProxy().ID}) {
				t.Errorf("findings = %q, want EGRESS-002", ids(got))
			}
		})
	}
}

func TestACodexRepoEndpointIsIgnoredSoOnlyInfo(t *testing.T) {
	w := newWorld(t, "")
	o := w.origin(model.AgentCodex, model.ScopeProject, "code/app/.codex/config.toml")
	o.InEffect, o.Why = false, w.text("Codex ignores openai_base_url in a project's .codex/config.toml, and warns at startup")
	p := w.perm(model.AgentCodex)
	p.Options = append(p.Options, model.Option{Key: w.text("openai_base_url"), Setting: model.Setting[redact.Text]{
		Layers: []model.Layer[redact.Text]{{Value: w.text("https://repo.example.com"), Origin: o}},
	}})

	got := w.analyze()
	if !slices.Equal(ids(got), []string{IgnoredRepoEndpoint().ID}) {
		t.Fatalf("findings = %q, want only EGRESS-003", ids(got))
	}
	if got[0].Severity != finding.Info {
		t.Errorf("severity = %s, want info: Codex ignores it", got[0].Severity)
	}
	has(t, w.lines(), "codex model endpoint default=OpenAI's API [env]")
}

func TestRulesRegister(t *testing.T) {
	if _, err := finding.NewRegistry(Rules()...); err != nil {
		t.Fatal(err)
	}
}

func TestAProxyPasswordFromTheEnvIsMasked(t *testing.T) {
	w := newWorld(t, "HTTPS_PROXY=http://me:hunter2-demo-pass@proxy.example.com:3128\n")

	for _, l := range w.lines() {
		if strings.Contains(l, "hunter2") {
			t.Errorf("egress line %q holds the proxy's password", l)
		}
	}
}

func TestARepoNoProxyIsntARepoProxy(t *testing.T) {
	w := newWorld(t, "")
	w.option(model.AgentClaude, model.ScopeProject, "env.NO_PROXY", "internal.example.com")

	if got := w.analyze(); len(got) != 0 {
		t.Errorf("findings = %q, want none: NO_PROXY only lists hosts that skip the proxy", ids(got))
	}
}

func TestACodexEndpointIsNeverTheHighRule(t *testing.T) {
	// The adapter marks these not in effect, since Codex ignores them in
	// project config. Even if one got through, it isn't EGRESS-001, which
	// is about Claude's env block.
	w := newWorld(t, "")
	w.option(model.AgentCodex, model.ScopeProject, "openai_base_url", "https://repo.example.com")

	if got := w.analyze(); slices.Contains(ids(got), RepoEndpoint().ID) {
		t.Errorf("findings = %q, want no EGRESS-001 for Codex", ids(got))
	}
}

func TestASetEndpointReplacesTheDefault(t *testing.T) {
	w := newWorld(t, "ANTHROPIC_BASE_URL=https://gw.example.com\n")

	for _, l := range w.lines() {
		if strings.HasPrefix(l, "claude model endpoint default=") {
			t.Errorf("egress still lists Claude's default endpoint next to ANTHROPIC_BASE_URL: %s", l)
		}
	}
}
