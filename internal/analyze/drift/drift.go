// Package drift compares what MCP servers offer now with the last snapshot.
// A tool whose definition changed is flagged, since a server can change a
// tool after you approved it. The poison rules already run on every tool's
// current text each scan, so a changed tool is checked again, not just
// noted. A tool new on a server seen before is noted too. A server seen for
// the first time isn't drift; the snapshot diff shows it as new.
package drift

import (
	"slices"
	"strings"

	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/redact"
	"github.com/nickelsec/jarx/internal/snapshot"
)

// ToolChanged is a tool whose definition changed since the last scan.
func ToolChanged() finding.Rule {
	return finding.Rule{
		ID: "JARX-DRIFT-001", Severity: finding.Medium, Title: "An MCP tool changed since the last scan",
		Detail: "a tool's description, schema or annotations changed since the last scan, so the agent now reads something different about it under the same config. The text checks ran on the new version.",
		Fix:    "read the tool's new description and schema before the agent uses it again",
	}
}

// ToolAdded is a tool new on a server that was listed before.
func ToolAdded() finding.Rule {
	return finding.Rule{
		ID: "JARX-DRIFT-002", Severity: finding.Info, Title: "An MCP server added a tool",
		Detail: "a server that was listed in the last scan offers a tool it didn't offer then",
		Fix:    "check the new tool before the agent uses it",
	}
}

// Rules returns the analyzer's rules.
func Rules() []finding.Rule { return []finding.Rule{ToolChanged(), ToolAdded()} }

// Analyze compares the listed servers' offers in projects with prev. With no
// earlier snapshot there's nothing to compare.
func Analyze(s *redact.Scrubber, prev snapshot.Snapshot, projects []model.Project) []finding.Finding {
	if prev.Taken.IsZero() {
		return nil
	}
	e := earlier{s: s, when: prev.Taken.UTC().Format("2006-01-02 15:04 UTC"), hashes: map[string]string{}, keys: map[string][]string{}}
	for _, it := range prev.Items {
		if it.Kind == snapshot.KindOffer {
			e.hashes[it.Project.String()+"\x00"+it.Key.String()] = it.Hash
			e.keys[it.Project.String()] = append(e.keys[it.Project.String()], it.Key.String())
		}
	}
	seen := map[string]bool{}
	var out []finding.Finding
	for _, p := range projects {
		dir := p.Path.Text().String()
		for _, srv := range p.Servers {
			if srv.Status != model.StatusListed {
				continue
			}
			for _, h := range e.compare(dir, srv) {
				if key := h.rule.ID + "\x00" + srv.Origin.File.Raw() + "\x00" + h.ev; !seen[key] {
					seen[key] = true
					t, _ := s.Scrub(h.ev)
					out = append(out, h.rule.New(srv.Origin, t))
				}
			}
		}
	}
	return out
}

// earlier is what the last snapshot held about offers.
type earlier struct {
	s      *redact.Scrubber
	when   string
	hashes map[string]string   // project and offer key to hash
	keys   map[string][]string // project to its offer keys
}

type hit struct {
	rule finding.Rule
	ev   string
}

// compare is what changed on one server in the project dir.
func (e earlier) compare(dir string, srv model.Server) []hit {
	// A server is known when an earlier offer's key starts with its own key;
	// matching on the whole key keeps spaces in a path or a name from
	// mattering.
	prefix := snapshot.ServerKey(e.s, srv).String() + " "
	known := slices.ContainsFunc(e.keys[dir], func(k string) bool { return strings.HasPrefix(k, prefix) })
	var out []hit
	for _, o := range srv.Offers {
		was, ok := e.hashes[dir+"\x00"+snapshot.OfferKey(e.s, srv, o).String()]
		what := string(o.Kind) + " " + o.Name.String() + " of " + srv.Name.String()
		switch {
		case ok && was != snapshot.OfferHash(o):
			out = append(out, hit{ToolChanged(), what + " is different from the scan on " + e.when})
		case !ok && known:
			out = append(out, hit{ToolAdded(), what + " is new since the scan on " + e.when})
		}
	}
	return out
}
