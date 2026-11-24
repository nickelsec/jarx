package egress

import (
	"slices"
	"strings"

	"github.com/nickelsec/jarx/internal/catalog"
	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/redact"
)

// RepoEndpoint is a repo's Claude settings that send model requests, and
// the credential with them, somewhere else.
func RepoEndpoint() finding.Rule {
	return finding.Rule{
		ID: "JARX-EGRESS-001", Severity: finding.High, Title: "A repo points the model endpoint elsewhere",
		Detail: "a repository's .claude/settings.json sets the model endpoint or provider in its env block, so Claude sends your prompts, code and API key where the repository chose",
		Fix:    "remove it from the repository's settings; set an endpoint you trust in your own user settings or env",
	}
}

// RepoProxy is a repo that routes the agent's traffic through a proxy.
func RepoProxy() finding.Rule {
	return finding.Rule{
		ID: "JARX-EGRESS-002", Severity: finding.Medium, Title: "A repo sets a proxy for the agent",
		Detail: "a repository's config sends the agent's traffic through a proxy it chose, which can read or change what goes through it",
		Fix:    "remove the proxy from the repository's config, or check who runs it",
	}
}

// IgnoredRepoEndpoint is a repo's Codex config that sets an endpoint or
// provider, which Codex ignores in project config.
func IgnoredRepoEndpoint() finding.Rule {
	return finding.Rule{
		ID: "JARX-EGRESS-003", Severity: finding.Info, Title: "A repo tries to set Codex's endpoint",
		Detail: "a repository's .codex/config.toml sets the model endpoint or provider; Codex ignores these keys in project config and warns at startup, so it doesn't take effect",
		Fix:    "ask why the repository sets it; nothing to change on your side",
	}
}

// Rules returns the analyzer's rules.
func Rules() []finding.Rule {
	return []finding.Rule{RepoEndpoint(), RepoProxy(), IgnoredRepoEndpoint()}
}

// Analyze flags the egress settings a repository sets.
func Analyze(s *redact.Scrubber, projects []model.Project) []finding.Finding {
	seen := map[string]bool{}
	var out []finding.Finding
	add := func(r finding.Rule, o model.Origin, ev string) {
		if k := r.ID + "\x00" + o.File.Raw() + "\x00" + ev; !seen[k] {
			seen[k] = true
			t, _ := s.Scrub(ev)
			out = append(out, r.New(o, t))
		}
	}
	for _, p := range projects {
		for _, e := range p.Egress {
			if r, ev, ok := repoSet(e); ok {
				add(r, e.Origin, ev)
			}
		}
		for _, f := range ignoredEndpoints(permissionsOf(p, model.AgentCodex)) {
			add(IgnoredRepoEndpoint(), f.origin, f.ev)
		}
	}
	return out
}

// repoSet is the rule a repository's egress setting raises, if any: a
// Claude model endpoint, or a proxy for either agent.
func repoSet(e model.Egress) (finding.Rule, string, bool) {
	if e.Origin.Scope != model.ScopeProject || e.Origin.File.IsZero() {
		return finding.Rule{}, "", false
	}
	what := e.What.String()
	switch {
	case e.Agent == model.AgentClaude && e.Area == model.AreaModel:
		return RepoEndpoint(), what + " = " + e.Value.String() + " in the repository's settings env", true
	case e.Area == model.AreaProxy && repoProxyKey(e.Agent, what):
		return RepoProxy(), what + " = " + e.Value.String(), true
	}
	return finding.Rule{}, "", false
}

// repoProxyKey says whether a proxy entry routes traffic, rather than
// naming hosts that skip the proxy.
func repoProxyKey(a model.Agent, what string) bool {
	if a == model.AgentCodex {
		return what == "features.network_proxy.proxy_url" || what == "features.network_proxy.socks_url"
	}
	area, ok := catalog.EgressVarArea(what)
	return ok && area == model.AreaProxy && what != "NO_PROXY"
}

type ignored struct {
	origin model.Origin
	ev     string
}

// ignoredEndpoints are the endpoint and provider layers Codex ignores in a
// project's config.
func ignoredEndpoints(perm model.Permissions) []ignored {
	var out []ignored
	for _, o := range perm.Options {
		key := o.Key.String()
		if !strings.HasPrefix(key, "model_providers.") && !slices.Contains(codexModelKeys, key) {
			continue
		}
		for _, l := range o.Setting.Layers {
			if l.Origin.Scope == model.ScopeProject && !l.Origin.InEffect && strings.Contains(l.Origin.Why.String(), "Codex ignores") {
				out = append(out, ignored{l.Origin, key + " = " + l.Value.String() + ", which Codex ignores in project config"})
			}
		}
	}
	return out
}
