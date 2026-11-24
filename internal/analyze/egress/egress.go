// Package egress works out where each agent talks to from each project:
// its model endpoint, auth source, proxies, TLS, remote MCP hosts, network
// domain rules and (for Codex) web search, each with where it was set. It
// reads only the model and the env vars the catalog names as non-secret;
// for a credential var it only notes that it's set.
//
// Sources: the Claude Code env vars and settings references, and the Codex
// config reference and advanced config ("Project config files": Codex
// ignores the endpoint and provider keys in a project's config).
package egress

import (
	"net/url"
	"strings"

	"github.com/nickelsec/jarx/internal/catalog"
	"github.com/nickelsec/jarx/internal/credmeta"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/platform"
	"github.com/nickelsec/jarx/internal/redact"
)

// proxyNote is what a proxy entry says about jarx's own probes, which
// never use a proxy (design.md, "Probes never use a proxy").
const proxyNote = "proxy set, probes went direct"

// Settle sets Egress on every ok project an agent knows. machine is the
// scan's own credentials, for the agents' login files.
func Settle(s *redact.Scrubber, env platform.Env, projects []model.Project, machine []model.Credential) {
	for i := range projects {
		p := &projects[i]
		p.Egress = nil
		if p.Status != model.ProjectOK {
			continue
		}
		b := &builder{s: s, env: env, p: *p, machine: machine}
		if knows(*p, model.AgentClaude) {
			b.claude()
		}
		if knows(*p, model.AgentCodex) {
			b.codex()
		}
		p.Egress = b.out
	}
}

func knows(p model.Project, a model.Agent) bool {
	for _, o := range p.Origins {
		if o.Agent == a {
			return true
		}
	}
	return false
}

func permissionsOf(p model.Project, a model.Agent) model.Permissions {
	for _, perm := range p.Permissions {
		if perm.Agent == a {
			return perm
		}
	}
	return model.Permissions{Agent: a}
}

type builder struct {
	s       *redact.Scrubber
	env     platform.Env
	p       model.Project
	machine []model.Credential
	out     []model.Egress
}

func (b *builder) text(v string) redact.Text {
	t, _ := b.s.Scrub(v)
	return t
}

func (b *builder) add(e model.Egress) { b.out = append(b.out, e) }

// effective is an option's layer in effect.
func effective(perm model.Permissions, key string) (model.Layer[redact.Text], bool) {
	for _, o := range perm.Options {
		if o.Key.String() == key {
			return o.Setting.Effective()
		}
	}
	return model.Layer[redact.Text]{}, false
}

// fromOption adds an option in effect, and says whether it did.
func (b *builder) fromOption(a model.Agent, area model.EgressArea, perm model.Permissions, key, what string) bool {
	l, ok := effective(perm, key)
	if !ok {
		return false
	}
	if what == "" {
		what = key
	}
	e := model.Egress{Agent: a, Area: area, What: b.text(what), Value: l.Value, Origin: l.Origin}
	if area == model.AreaProxy {
		e.Note = b.text(proxyNote)
	}
	b.add(e)
	return true
}

// fromEnv adds a non-secret env var the agent sees, its password masked
// when it's a URL with one.
func (b *builder) fromEnv(a model.Agent, area model.EgressArea, name string) {
	v, ok := b.env.Lookup(name)
	if !ok || v == "" {
		return
	}
	e := model.Egress{Agent: a, Area: area, What: b.text(name), Value: b.maskURL(v), Origin: model.Origin{Agent: a, InEffect: true}}
	if area == model.AreaProxy {
		e.Note = b.text(proxyNote)
	}
	b.add(e)
}

// maskURL masks a password in a URL, like a proxy's user:pass@host, without
// relying on the secret patterns.
func (b *builder) maskURL(v string) redact.Text {
	if u, err := url.Parse(v); err == nil && u.User != nil {
		if pw, ok := u.User.Password(); ok && pw != "" {
			masked, _ := b.s.Secret("url_password", pw)
			v = strings.Replace(v, ":"+pw+"@", ":"+masked.String()+"@", 1)
		}
	}
	return b.text(v)
}

// claude is where Claude talks to: env vars first, then the same names in
// a settings env block, then its own settings.
func (b *builder) claude() {
	a := model.AgentClaude
	perm := permissionsOf(b.p, a)
	model0 := len(b.out)
	for _, v := range catalog.ClaudeEgressVars() {
		if v.Area == model.AreaModel {
			b.fromEnv(a, v.Area, v.Name)
			b.fromOption(a, v.Area, perm, "env."+v.Name, v.Name)
		}
	}
	if len(b.out) == model0 {
		b.add(model.Egress{Agent: a, Area: model.AreaModel, What: b.text("default"), Value: b.text("Anthropic's API"), Origin: model.Origin{Agent: a, InEffect: true}})
	}
	b.claudeAuth(perm)
	for _, area := range []model.EgressArea{model.AreaProxy, model.AreaTLS} {
		for _, v := range catalog.ClaudeEgressVars() {
			if v.Area == area {
				b.fromEnv(a, area, v.Name)
				b.fromOption(a, area, perm, "env."+v.Name, v.Name)
			}
		}
	}
	b.fromOption(a, model.AreaProxy, perm, "sandbox.network.httpProxyPort", "")
	b.fromOption(a, model.AreaProxy, perm, "sandbox.network.socksProxyPort", "")
	b.mcpHosts(a)
	b.claudeDomains(perm)
}

// claudeAuth is where Claude's credential comes from: which credential
// vars are set (never their values), its helper commands and login method,
// and the login file.
func (b *builder) claudeAuth(perm model.Permissions) {
	a := model.AgentClaude
	for _, name := range catalog.ClaudeAuthVars() {
		if v, ok := b.env.Lookup(name); ok && v != "" {
			b.add(model.Egress{Agent: a, Area: model.AreaAuth, What: b.text(name), Value: b.text("set"), Origin: model.Origin{Agent: a, InEffect: true}})
		}
		for _, l := range perm.Env {
			if l.Value.String() == name && l.Origin.InEffect {
				b.add(model.Egress{Agent: a, Area: model.AreaAuth, What: l.Value, Value: b.text("set"), Origin: l.Origin})
			}
		}
	}
	for _, key := range []string{"apiKeyHelper", "forceLoginMethod", "awsAuthRefresh", "gcpAuthRefresh"} {
		b.fromOption(a, model.AreaAuth, perm, key, "")
	}
	b.loginFile(a, credmeta.KindClaudeLogin)
}

func (b *builder) loginFile(a model.Agent, kind string) {
	for _, cr := range b.machine {
		if string(cr.Kind) == kind {
			b.add(model.Egress{Agent: a, Area: model.AreaAuth, What: b.text("login file"), Value: cr.Path.Text(), Origin: model.Origin{Agent: a, InEffect: true}})
		}
	}
}

// mcpHosts are the remote MCP servers the agent would start, by host, with
// what probe found.
func (b *builder) mcpHosts(a model.Agent) {
	for _, srv := range b.p.Servers {
		if srv.Origin.Agent != a || srv.Start == model.StartNo || srv.URL.IsZero() {
			continue
		}
		host := srv.URL.String()
		if u, err := url.Parse(host); err == nil && u.Host != "" {
			host = u.Host
		}
		note := "status: " + string(srv.Status)
		if srv.Status == "" {
			note = "not probed"
		}
		b.add(model.Egress{Agent: a, Area: model.AreaMCPHost, What: srv.Name, Value: b.text(host), Origin: srv.Origin, Note: b.text(note)})
	}
}

// claudeDomains are the sandbox's domain lists and WebFetch domain rules.
func (b *builder) claudeDomains(perm model.Permissions) {
	for _, r := range perm.Rules {
		rule := r.Rule.String()
		domain := strings.HasPrefix(rule, "sandbox.network.") || strings.HasPrefix(rule, "WebFetch(domain:")
		if r.Origin.InEffect && domain {
			b.add(model.Egress{Agent: model.AgentClaude, Area: model.AreaDomains, What: b.text(string(r.Action)), Value: r.Rule, Origin: r.Origin})
		}
	}
}

// codexModelKeys set where Codex sends model requests.
//
//nolint:gochecknoglobals // fixed list, read only
var codexModelKeys = []string{"model_provider", "openai_base_url", "chatgpt_base_url"}

// codex is where Codex talks to.
func (b *builder) codex() {
	a := model.AgentCodex
	perm := permissionsOf(b.p, a)
	model0 := len(b.out)
	for _, key := range codexModelKeys {
		b.fromOption(a, model.AreaModel, perm, key, "")
	}
	b.providerKeys(perm, ".base_url", model.AreaModel)
	if len(b.out) == model0 {
		b.add(model.Egress{Agent: a, Area: model.AreaModel, What: b.text("default"), Value: b.text("OpenAI's API"), Origin: model.Origin{Agent: a, InEffect: true}})
	}
	b.fromOption(a, model.AreaAuth, perm, "cli_auth_credentials_store", "")
	b.fromOption(a, model.AreaAuth, perm, "forced_login_method", "")
	b.providerKeys(perm, ".env_key", model.AreaAuth)
	b.providerKeys(perm, ".auth.command", model.AreaAuth)
	b.loginFile(a, credmeta.KindCodexLogin)
	for _, key := range []string{"features.network_proxy.enabled", "features.network_proxy.proxy_url", "features.network_proxy.socks_url"} {
		b.fromOption(a, model.AreaProxy, perm, key, "")
	}
	b.mcpHosts(a)
	b.codexDomains(perm)
	if !b.fromOption(a, model.AreaWebSearch, perm, "web_search", "") {
		b.add(model.Egress{Agent: a, Area: model.AreaWebSearch, What: b.text("web_search"), Value: b.text("cached"), Origin: model.Origin{Agent: a, InEffect: true},
			Note: b.text("the docs' default")})
	}
	b.fromOption(a, model.AreaWebSearch, perm, "requirements.allowed_web_search_modes", "")
}

// providerKeys adds each model_providers.<id> key with the suffix.
func (b *builder) providerKeys(perm model.Permissions, suffix string, area model.EgressArea) {
	for _, o := range perm.Options {
		if k := o.Key.String(); strings.HasPrefix(k, "model_providers.") && strings.HasSuffix(k, suffix) {
			b.fromOption(model.AgentCodex, area, perm, k, "")
		}
	}
}

// codexDomains are the network proxy's domains, the active profile's
// network rules, and the switches that turn command networking on.
func (b *builder) codexDomains(perm model.Permissions) {
	a := model.AgentCodex
	profile := ""
	if l, ok := effective(perm, "default_permissions"); ok {
		profile = l.Value.String()
	}
	for _, r := range perm.Rules {
		rule := r.Rule.String()
		ours := strings.HasPrefix(rule, "features.network_proxy.domains ") ||
			profile != "" && strings.HasPrefix(rule, "permissions."+profile+".network.domains ")
		if r.Origin.InEffect && ours {
			b.add(model.Egress{Agent: a, Area: model.AreaDomains, What: b.text(string(r.Action)), Value: r.Rule, Origin: r.Origin})
		}
	}
	if profile != "" {
		b.fromOption(a, model.AreaDomains, perm, "permissions."+profile+".network.enabled", "")
	}
	b.fromOption(a, model.AreaDomains, perm, "sandbox_workspace_write.network_access", "")
}
