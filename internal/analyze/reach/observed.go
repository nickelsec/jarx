package reach

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/redact"
)

// window is how far back observed modes count (PRD, "Observed modes change
// the verdict").
const window = 30 * 24 * time.Hour

// handsOff are the modes where something other than you approves, per
// agent (PRD, "Modes that count"). They count on every read channel.
// Claude's acceptEdits only auto-approves edits, so it never counts for
// reading a credential. Codex's granular policy auto-rejects, so it
// doesn't count either.
//
//nolint:gochecknoglobals // fixed table, read only
var handsOff = map[model.Agent][]string{
	model.AgentClaude: {"auto", "bypassPermissions"},
	model.AgentCodex:  {"approval_policy=never", "approvals_reviewer=auto_review"},
}

// Observe adds what history says to each project's verdicts: when more
// than half of an agent's sessions there in the 30 days before now ran
// hands-off, every needs approval verdict of that agent also shows as
// effectively readable. Undated sessions count, and the reason says how
// many there were. The configured verdict stays.
func Observe(s *redact.Scrubber, projects []model.Project, now time.Time) {
	for i := range projects {
		p := &projects[i]
		for a := range handsOff {
			why, ok := tally(p.Sessions, a, now)
			if !ok {
				continue
			}
			t, _ := s.Scrub(why)
			for j := range p.Reach {
				if r := &p.Reach[j]; r.Agent == a && r.Verdict == model.ReachApproval {
					r.Observed, r.ObservedWhy = model.ReachEffective, t
				}
			}
		}
	}
}

// handsOffIn are the hands-off modes a session ran in.
func handsOffIn(s model.Session, a model.Agent) []string {
	var out []string
	for _, m := range s.Modes {
		if slices.Contains(handsOff[a], m.String()) {
			out = append(out, m.String())
		}
	}
	return out
}

// tally counts agent a's sessions in the window and says whether more
// than half ran hands-off, with the reason.
func tally(sessions []model.Session, a model.Agent, now time.Time) (string, bool) {
	total, undated, hands := 0, 0, 0
	var seen []string
	for _, s := range sessions {
		if s.Agent != a || s.LastUnix != 0 && now.Sub(s.LastTime()) > window {
			continue
		}
		total++
		if s.LastUnix == 0 {
			undated++
		}
		if modes := handsOffIn(s, a); len(modes) > 0 {
			hands++
			seen = union(seen, modes)
		}
	}
	if total == 0 || hands*2 <= total {
		return "", false
	}
	return reason(a, hands, total, undated, seen), true
}

// reason says how many sessions ran hands-off, like "3 of 4 sessions in
// bypassPermissions, 1 undated".
func reason(a model.Agent, hands, total, undated int, modes []string) string {
	slices.Sort(modes)
	in := "in"
	if a == model.AgentCodex {
		in = "with"
	}
	why := fmt.Sprintf("%d of %d sessions %s %s", hands, total, in, strings.Join(modes, " or "))
	if undated > 0 {
		why += fmt.Sprintf(", %d undated", undated)
	}
	return why
}

// union adds each of add that list doesn't have.
func union(list, add []string) []string {
	for _, m := range add {
		if !slices.Contains(list, m) {
			list = append(list, m)
		}
	}
	return list
}
