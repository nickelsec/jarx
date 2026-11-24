package report

import (
	"slices"
	"strconv"

	"github.com/nickelsec/jarx/internal/model"
)

// notedModes are the modes a sessions line names, per agent: the ones
// where something other than you approves (PRD, "Modes that count").
//
//nolint:gochecknoglobals // fixed table, read only
var notedModes = map[model.Agent][]string{
	model.AgentClaude: {"bypassPermissions", "auto"},
	model.AgentCodex:  {"approval_policy=never", "approvals_reviewer=auto_review"},
}

// countSessions is how many of the agent's sessions there are, how many
// are undated, and how many ran in each noted mode.
func countSessions(sessions []model.Session, a model.Agent) (int, int, map[string]int) {
	n, undated := 0, 0
	counts := map[string]int{}
	for _, s := range sessions {
		if s.Agent != a {
			continue
		}
		n++
		if s.LastUnix == 0 {
			undated++
		}
		for _, m := range s.Modes {
			if slices.Contains(notedModes[a], m.String()) {
				counts[m.String()]++
			}
		}
	}
	return n, undated, counts
}

// sessionsLine is a project's sessions, per agent: how many, how many ran
// in each hands-off mode, and how many are undated.
func (p *Printer) sessionsLine(proj model.Project) node {
	var items []string
	for _, a := range []model.Agent{model.AgentClaude, model.AgentCodex} {
		n, undated, counts := countSessions(proj.Sessions, a)
		if n == 0 {
			continue
		}
		items = append(items, string(a)+" "+strconv.Itoa(n))
		in := "in"
		if a == model.AgentCodex {
			in = "with"
		}
		for _, m := range notedModes[a] {
			if counts[m] > 0 {
				items = append(items, strconv.Itoa(counts[m])+" "+in+" "+m)
			}
		}
		if undated > 0 {
			items = append(items, strconv.Itoa(undated)+" undated")
		}
	}
	if len(items) == 0 {
		return nil
	}
	return p.wrapList("sessions: ", items)
}
