package reach

import (
	"regexp"

	"github.com/nickelsec/jarx/internal/credmeta"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/redact"
)

// The credential view (PRD, "The credential view"): each credential's
// states for each agent in a project, worst first. sees is a secret
// already in text the agent loads; can read is any channel that isn't
// blocked; can use is an MCP server that would start and holds it; not
// reachable is none of those.

// view sets p.Exposure from p.Reach and what each agent loads and starts.
func view(s *redact.Scrubber, p *model.Project) {
	p.Exposure = nil
	for _, a := range []model.Agent{model.AgentClaude, model.AgentCodex} {
		if !knows(*p, a) {
			continue
		}
		p.Exposure = append(p.Exposure, seen(s, *p, a)...)
		p.Exposure = append(p.Exposure, reachable(s, *p, a)...)
		p.Exposure = append(p.Exposure, inline(s, *p, a)...)
	}
}

// key names a credential across its channels.
func key(kind model.CredentialKind, path model.Path, name redact.Text) string {
	return string(kind) + "\x00" + path.Raw() + "\x00" + name.String()
}

// reachable is the states of each credential with verdicts: can read
// from the channels, can use from the servers that hold it.
func reachable(s *redact.Scrubber, p model.Project, a model.Agent) []model.Exposure {
	var out []model.Exposure
	index := map[string]int{}
	for _, r := range p.Reach {
		if r.Agent != a {
			continue
		}
		k := key(r.Kind, r.Path, r.Name)
		i, ok := index[k]
		if !ok {
			index[k], i = len(out), len(out)
			out = append(out, model.Exposure{Agent: a, Kind: r.Kind, Path: r.Path, Name: r.Name})
		}
		if r.Verdict != model.ReachBlocked {
			out[i].States = addState(out[i].States, model.StateCanRead)
		}
	}
	for i := range out {
		e := &out[i]
		if e.Kind == credmeta.KindEnvVar {
			for _, srv := range holders(p, a, e.Name.String()) {
				e.States = addState(e.States, model.StateCanUse)
				e.Via = append(e.Via, text(s, "MCP server "+srv+" holds it"))
			}
		}
		if len(e.States) == 0 {
			e.States = []model.CredentialState{model.StateUnreachable}
		}
	}
	return out
}

// addState adds a state, keeping the list worst first.
func addState(ss []model.CredentialState, st model.CredentialState) []model.CredentialState {
	order := []model.CredentialState{model.StateSees, model.StateCanRead, model.StateCanUse, model.StateUnreachable}
	have := map[model.CredentialState]bool{st: true}
	for _, s := range ss {
		have[s] = true
	}
	out := make([]model.CredentialState, 0, len(have))
	for _, s := range order {
		if have[s] {
			out = append(out, s)
		}
	}
	return out
}

func text(s *redact.Scrubber, v string) redact.Text {
	t, _ := s.Scrub(v)
	return t
}

// starts says whether the agent would start a server.
func starts(srv model.Server, a model.Agent) bool {
	return srv.Origin.Agent == a && (srv.Start == model.StartYes || srv.Start == model.StartMaybe)
}

// varRef is a ${NAME} or ${NAME:-default} reference, Claude's form.
var varRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-[^}]*)?\}`)

// holders are the servers the agent would start that get the env var:
// Claude's ${VAR} in env, headers, args or the URL; Codex's env_vars,
// bearer_token_env_var and env_http_headers.
func holders(p model.Project, a model.Agent, name string) []string {
	var out []string
	for _, srv := range p.Servers {
		if starts(srv, a) && references(srv, name) {
			out = append(out, srv.Name.String())
		}
	}
	return out
}

func references(srv model.Server, name string) bool {
	if namedVar(srv, name) {
		return true
	}
	for _, t := range serverTexts(srv) {
		for _, m := range varRef.FindAllStringSubmatch(t.String(), -1) {
			if m[1] == name {
				return true
			}
		}
	}
	return false
}

// namedVar says whether a server's Codex fields name the env var.
func namedVar(srv model.Server, name string) bool {
	if srv.BearerVar.String() == name {
		return true
	}
	for _, v := range srv.ForwardEnv {
		if v.String() == name {
			return true
		}
	}
	for _, h := range srv.HeaderVars {
		if h.Value.String() == name {
			return true
		}
	}
	return false
}

// seen is a row for each secret in text the agent loads, by the file and
// the secret's kind and fingerprint.
func seen(s *redact.Scrubber, p model.Project, a model.Agent) []model.Exposure {
	var out []model.Exposure
	done := map[string]bool{}
	for _, in := range p.Instructions {
		if in.Origin.Agent != a || !in.Origin.InEffect || done[in.Path.Raw()] {
			continue
		}
		if via := secretsIn(s, in.Text); len(via) > 0 {
			done[in.Path.Raw()] = true
			out = append(out, model.Exposure{
				Agent: a, Kind: credmeta.KindSecretInText, Path: in.Path, States: []model.CredentialState{model.StateSees}, Via: via,
			})
		}
	}
	for _, ses := range p.Sessions {
		if ses.Agent == a && len(ses.Secrets) > 0 && !done[ses.File.Raw()] {
			done[ses.File.Raw()] = true
			out = append(out, model.Exposure{
				Agent: a, Kind: credmeta.KindSecretInHistory, Path: ses.File, States: []model.CredentialState{model.StateSees}, Via: ses.Secrets,
			})
		}
	}
	return out
}

// secretsIn names the real secrets masked in a text: kind and
// fingerprint. A likely placeholder doesn't count.
func secretsIn(s *redact.Scrubber, t redact.Text) []redact.Text {
	var out []redact.Text
	for _, f := range t.Secrets() {
		if f.LikelyPlaceholder {
			continue
		}
		what := f.Kind
		if f.Fingerprint != "" {
			what += ", fingerprint " + f.Fingerprint
		}
		out = append(out, text(s, what))
	}
	return out
}

// inline is a row for each server the agent would start whose own
// definition holds a secret: the server can use it.
func inline(s *redact.Scrubber, p model.Project, a model.Agent) []model.Exposure {
	var out []model.Exposure
	for _, srv := range p.Servers {
		if !starts(srv, a) {
			continue
		}
		var via []redact.Text
		for _, t := range serverTexts(srv) {
			via = append(via, secretsIn(s, t)...)
		}
		if len(via) == 0 {
			continue
		}
		out = append(out, model.Exposure{
			Agent: a, Kind: credmeta.KindInlineSecret, Path: srv.Origin.File, Name: text(s, "MCP server "+srv.Name.String()),
			States: []model.CredentialState{model.StateCanUse}, Via: via,
		})
	}
	return out
}

// serverTexts are the values in a server's definition that can hold a
// reference or a secret: the URL, args, env and header values.
func serverTexts(srv model.Server) []redact.Text {
	out := make([]redact.Text, 0, 1+len(srv.Args)+len(srv.Env)+len(srv.Headers))
	out = append(out, srv.URL)
	out = append(out, srv.Args...)
	for _, pr := range append(append([]model.Pair{}, srv.Env...), srv.Headers...) {
		out = append(out, pr.Value)
	}
	return out
}
