package report

import (
	"net/url"
	"slices"
	"strings"

	"github.com/nickelsec/jarx/internal/model"
)

// talksTo is where each agent talks to from a project, in one line: its
// model endpoint, how many remote MCP hosts, whether a proxy is set, and
// Codex's web search.
func (p *Printer) talksTo(proj model.Project) node {
	var items []string
	for _, a := range []model.Agent{model.AgentClaude, model.AgentCodex} {
		parts := talkParts(proj, a)
		if len(parts) > 0 {
			parts[0] = string(a) + " " + parts[0]
			items = append(items, parts...)
		}
	}
	if len(items) == 0 {
		return nil
	}
	return p.wrapList("talks to: ", items)
}

// talk is what one agent's line says.
type talk struct {
	endpoints []string
	hosts     int
	proxy     bool
	search    string
}

func (t *talk) add(e model.Egress) {
	switch e.Area {
	case model.AreaModel:
		if ep := endpointLabel(e); !slices.Contains(t.endpoints, ep) {
			t.endpoints = append(t.endpoints, ep)
		}
	case model.AreaMCPHost:
		t.hosts++
	case model.AreaProxy:
		t.proxy = t.proxy || e.What.String() != "NO_PROXY" && e.Value.String() != "false"
	case model.AreaWebSearch:
		if e.What.String() == "web_search" {
			t.search = e.Value.String()
		}
	case model.AreaAuth, model.AreaTLS, model.AreaDomains:
	}
}

func talkParts(proj model.Project, a model.Agent) []string {
	var t talk
	for _, e := range proj.Egress {
		if e.Agent == a {
			t.add(e)
		}
	}
	parts := t.endpoints
	if t.hosts > 0 {
		parts = append(parts, plural(t.hosts, "MCP host", "MCP hosts"))
	}
	if t.proxy {
		parts = append(parts, "proxy set")
	}
	if t.search != "" {
		parts = append(parts, "web search "+t.search)
	}
	return parts
}

// endpointLabel names a model endpoint briefly: the default, a URL's host,
// or the setting.
func endpointLabel(e model.Egress) string {
	if e.What.String() == valueDefault {
		return "default API"
	}
	if u, err := url.Parse(e.Value.String()); err == nil && u.Host != "" {
		return u.Host
	}
	return e.What.String() + "=" + e.Value.String()
}

// egressList lists where each agent talks to from a project, in full:
// area, setting, value, where it was set, and any note.
func (p *Printer) egressList(proj model.Project) {
	var agent model.Agent
	for _, e := range proj.Egress {
		if e.Agent != agent {
			agent = e.Agent
			p.Out.Printf("    %s talks to\n", p.text(string(e.Agent)))
		}
		parts := []string{string(e.Area), e.What.String()}
		if !e.Value.IsZero() {
			parts = append(parts, e.Value.String())
		}
		switch {
		case !e.Origin.File.IsZero():
			parts = append(parts, e.Origin.File.Text().String())
		case e.What.String() != valueDefault && e.Note.String() != "the docs' default":
			parts = append(parts, "env")
		}
		if !e.Note.IsZero() {
			parts = append(parts, e.Note.String())
		}
		p.Out.Printf("      %s\n", p.text(strings.Join(parts, "  ")))
	}
}
