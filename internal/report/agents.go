package report

import (
	"strconv"
	"strings"

	"github.com/nickelsec/jarx/internal/model"
)

// trustLevels are the trust decisions the agents block counts, in order.
//
//nolint:gochecknoglobals // fixed list, read only
var trustLevels = []string{string(model.TrustTrusted), string(model.TrustUntrusted), "unknown"}

// trustTone colors a trust decision; the word itself always says it.
func trustTone(level string) tone {
	switch level {
	case string(model.TrustTrusted):
		return green
	case string(model.TrustUntrusted):
		return yellow
	}
	return dim
}

// trustOf is agent's trust decision for p, "unknown" when it has none.
func trustOf(p model.Project, agent model.Agent) string {
	for _, t := range p.Trust {
		if t.Origin.Agent == agent && t.Level != "" {
			return string(t.Level)
		}
	}
	return "unknown"
}

// knows reports whether agent's own records name p.
func knows(p model.Project, agent model.Agent) bool {
	for _, o := range p.Origins {
		if o.Agent == agent {
			return true
		}
	}
	return false
}

// agentColumns are the widths the agents block lines its rows up on.
type agentColumns struct{ name, dir int }

func (p *Printer) agents(v ScanView) {
	p.emit(line{{text: "agents on this machine", tone: bold}})
	var cols agentColumns
	for _, a := range v.Agents {
		cols.name = max(cols.name, cells(a.Name))
		if a.Found {
			cols.dir = max(cols.dir, cells(escape(p.short(a.ConfigDir, model.Path{}, v.Home))))
		}
	}
	nodes := make([]node, 0, len(v.Agents))
	for _, a := range v.Agents {
		nodes = append(nodes, p.agentRow(v, a, cols))
	}
	p.tree(p.alignAgents(nodes, cols))
}

// agentRow is one agent: its name, its config dir and the projects it
// knows, with their trust.
func (p *Printer) agentRow(v ScanView, a AgentInfo, cols agentColumns) node {
	name := seg{text: own(a.Name + strings.Repeat(" ", cols.name-cells(a.Name)+1))}
	if !a.Found {
		return node{line{name, {text: "not found", tone: dim}}}
	}
	counts := map[string]int{}
	n := 0
	for _, proj := range v.Projects {
		if knows(proj, a.Agent) {
			counts[trustOf(proj, a.Agent)]++
			n++
		}
	}
	var parts []string
	for _, level := range trustLevels {
		if counts[level] > 0 {
			parts = append(parts, strconv.Itoa(counts[level])+" "+level)
		}
	}
	d := escape(p.short(a.ConfigDir, model.Path{}, v.Home))
	row := line{name, {text: d + strings.Repeat(" ", cols.dir-cells(d)+minGap)}, {text: own(plural(n, "project", "projects"))}}
	if len(parts) > 0 {
		row = append(row, seg{text: own(" (" + strings.Join(parts, p.sep()) + ")"), tone: dim})
	}
	return node{row}
}

// alignAgents moves every row's project counts down a line when one row
// doesn't fit, so the rows stay lined up.
func (p *Printer) alignAgents(nodes []node, cols agentColumns) []node {
	fits := true
	for _, n := range nodes {
		fits = fits && branchCells+n[0].cells() <= p.Style.width()
	}
	if fits {
		return nodes
	}
	for i := range nodes {
		if len(nodes[i][0]) > minGap {
			first := nodes[i][0][:2]
			rest := append(line{{text: strings.Repeat(" ", cols.name+1)}}, nodes[i][0][2:]...)
			nodes[i] = node{first, rest}
		}
	}
	return nodes
}
