// Package reach works out, for each project and each agent that knows it,
// whether each credential is reachable on each channel the agent has, and
// why: the PRD's reachability verdicts. It only reads the model. The
// verdicts follow the agents' docs (for Claude: permissions, sandboxing,
// permission-modes and the settings and env var references) and never guess
// in the agent's favor: where the docs leave room, the worse verdict wins.
package reach

import (
	"strconv"
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
		if p.Status != model.ProjectOK {
			continue
		}
		if knows(*p, model.AgentClaude) {
			perm := permissionsOf(*p, model.AgentClaude)
			c := newClaude(s, env, *p, perm)
			for _, cr := range credentialsFor(s, *p, perm, machine) {
				p.Reach = append(p.Reach, c.verdicts(cr)...)
			}
		}
		if knows(*p, model.AgentCodex) {
			perm := permissionsOf(*p, model.AgentCodex)
			x := newCodex(s, env, *p, perm)
			for _, cr := range credentialsFor(s, *p, perm, machine) {
				p.Reach = append(p.Reach, x.verdicts(cr)...)
			}
		}
		view(s, p)
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
func reachOf(a model.Agent, cr model.Credential, ch model.ReachChannel) model.Reach {
	return model.Reach{Agent: a, Kind: cr.Kind, Path: cr.Path, Name: cr.Name, Channel: ch}
}

// process is what the channels that run code as you need: the project,
// the agent, and whether the agent strips a var from subprocesses.
type process struct {
	s      *redact.Scrubber
	p      model.Project
	agent  model.Agent
	strips func(name string) bool
}

func (pc process) text(v string) redact.Text {
	t, _ := pc.s.Scrub(v)
	return t
}

// channels are the channels that run code as you, outside any sandbox:
// local MCP servers that start, and hooks. They can read any file you can,
// and hooks get the agent's env unless it strips the var.
func (pc process) channels(cr model.Credential, isEnv bool) []model.Reach {
	var out []model.Reach
	if names := pc.localServers(); len(names) > 0 && !isEnv {
		r := reachOf(pc.agent, cr, model.ChannelMCP)
		r.Via = pc.text(strings.Join(names, ", "))
		r.Verdict = model.ReachByTheProcess
		r.Why = []redact.Text{pc.text("MCP servers that run on this machine (" + strings.Join(names, ", ") + ") run as you, outside the sandbox")}
		out = append(out, r)
	}
	if n := pc.hooks(); n > 0 && (!isEnv || !pc.strips(cr.Name.String())) {
		r := reachOf(pc.agent, cr, model.ChannelHooks)
		r.Via = pc.text(plural(n, "hook", "hooks"))
		r.Verdict = model.ReachByTheProcess
		r.Why = []redact.Text{pc.text("hooks run as you, outside the sandbox")}
		out = append(out, r)
	}
	return out
}

func (pc process) localServers() []string {
	var out []string
	for _, srv := range pc.p.Servers {
		if srv.Origin.Agent != pc.agent || srv.Transport != model.TransportStdio {
			continue
		}
		if srv.Start == model.StartYes || srv.Start == model.StartMaybe {
			out = append(out, srv.Name.String())
		}
	}
	return out
}

func (pc process) hooks() int {
	n := 0
	for _, h := range pc.p.Hooks {
		if h.Origin.Agent == pc.agent && h.Origin.InEffect {
			n++
		}
	}
	return n
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}
