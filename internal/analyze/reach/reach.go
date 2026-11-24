// Package reach works out, for each project and each agent that knows it,
// whether each credential is reachable on each channel the agent has, and
// why: the PRD's reachability verdicts. It only reads the model. The
// verdicts follow the agents' docs (for Claude: permissions, sandboxing,
// permission-modes and the settings and env var references) and never guess
// in the agent's favor: where the docs leave room, the worse verdict wins.
package reach

import (
	"strings"

	"github.com/nickelsec/jarx/internal/catalog"
	"github.com/nickelsec/jarx/internal/credmeta"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/platform"
	"github.com/nickelsec/jarx/internal/redact"
)

// Settle sets Reach on every project an agent knows. machine is the scan's
// own credentials; a project's own are on it.
func Settle(s *redact.Scrubber, env platform.Env, projects []model.Project, machine []model.Credential) {
	for i := range projects {
		p := &projects[i]
		p.Reach = nil
		if p.Status != model.ProjectOK || !knows(*p, model.AgentClaude) {
			continue
		}
		perm := permissionsOf(*p, model.AgentClaude)
		c := newClaude(s, env, *p, perm)
		for _, cr := range credentialsFor(s, *p, perm, machine) {
			p.Reach = append(p.Reach, c.verdicts(cr)...)
		}
	}
}

// knows says whether a project is in the agent's own records.
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

// credentialsFor is every credential an agent could reach from a project:
// the machine's, the project's own, and the secret-looking names the
// agent's settings put in its env.
func credentialsFor(s *redact.Scrubber, p model.Project, perm model.Permissions, machine []model.Credential) []model.Credential {
	out := append(append([]model.Credential{}, machine...), p.Credentials...)
	seen := map[string]bool{}
	for _, cr := range out {
		if cr.Kind == credmeta.KindEnvVar {
			seen[cr.Name.String()] = true
		}
	}
	for _, l := range perm.Env {
		name := l.Value.String()
		if !l.Origin.InEffect || seen[name] || !catalog.SecretName(name) {
			continue
		}
		seen[name] = true
		via, _ := s.Scrub("settings env in " + l.Origin.File.Text().String())
		out = append(out, model.Credential{Kind: credmeta.KindEnvVar, Name: l.Value, Via: via, Read: model.ReadExistsOnly})
	}
	return out
}

// reachOf starts a verdict for a credential on a channel.
func reachOf(cr model.Credential, ch model.ReachChannel) model.Reach {
	return model.Reach{Agent: model.AgentClaude, Kind: cr.Kind, Path: cr.Path, Name: cr.Name, Channel: ch}
}

// processChannels are the channels that run code as you, outside any
// sandbox: local MCP servers that start, and hooks. They can read any file
// you can, and they get Claude's env unless the scrub is on.
func (c *claude) processChannels(cr model.Credential, isEnv bool) []model.Reach {
	var out []model.Reach
	if names := c.localServers(); len(names) > 0 && !isEnv {
		r := reachOf(cr, model.ChannelMCP)
		r.Via = c.text(strings.Join(names, ", "))
		r.Verdict = model.ReachByTheProcess
		r.Why = c.texts("MCP servers that run on this machine (" + strings.Join(names, ", ") + ") run as you, outside the sandbox")
		out = append(out, r)
	}
	if n := c.hooks(); n > 0 && (!isEnv || !c.scrubs(cr.Name.String())) {
		r := reachOf(cr, model.ChannelHooks)
		r.Via = c.text(plural(n, "hook", "hooks"))
		r.Verdict = model.ReachByTheProcess
		r.Why = c.texts("hooks run as you, outside the sandbox")
		out = append(out, r)
	}
	return out
}

func (c *claude) localServers() []string {
	var out []string
	for _, srv := range c.p.Servers {
		if srv.Origin.Agent != model.AgentClaude || srv.Transport != model.TransportStdio {
			continue
		}
		if srv.Start == model.StartYes || srv.Start == model.StartMaybe {
			out = append(out, srv.Name.String())
		}
	}
	return out
}

func (c *claude) hooks() int {
	n := 0
	for _, h := range c.p.Hooks {
		if h.Origin.Agent == model.AgentClaude && h.Origin.InEffect {
			n++
		}
	}
	return n
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return itoa(n) + " " + many
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}
