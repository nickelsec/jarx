package poison

import (
	"encoding/json"
	"slices"
	"sort"
	"strings"

	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/redact"
)

// What MCP servers say: their instructions, and every string in what they
// offer (names, descriptions, input schemas with param names, enums and
// defaults, prompts' arguments, resources). The text rules run on all of it,
// on servers probe listed. Two rules are about MCP alone: annotations that
// lie, and two servers offering the same tool name.

func lyingAnnotation() finding.Rule {
	return rule("JARX-POISON-014", finding.Medium, "an MCP tool claims to be read-only",
		"a tool is marked readOnlyHint, but its name or its own destructiveHint says it changes things; Codex doesn't ask before a tool marked read-only, even one also marked destructive",
		"don't trust the annotation; deny or ask for the tool in your permission rules")
}

func shadowedTool() finding.Rule {
	return rule("JARX-POISON-015", finding.Medium, "two MCP servers offer the same tool name",
		"two servers the agent loads offer a tool with the same name, so a description written for one can steer calls meant for the other",
		"check which server each tool comes from, and remove or rename the one you don't need")
}

// serverSources are the texts a listed server gives the agent.
func serverSources(p model.Project) []source {
	var out []source
	for _, s := range p.Servers {
		if s.Status != model.StatusListed {
			continue
		}
		name := s.Name.String()
		if !s.Instructions.IsZero() {
			out = append(out, source{origin: s.Origin, text: s.Instructions.String(), where: "instructions of " + name, project: p.Path.Raw()})
		}
		for _, o := range s.Offers {
			out = append(out, source{
				origin: s.Origin, text: entryStrings(o.Text.String()),
				where: string(o.Kind) + " " + o.Name.String() + " of " + name, project: p.Path.Raw(),
			})
		}
	}
	return out
}

// entryStrings is every string in an entry, keys too, one per line, so
// hidden characters written as JSON escapes are decoded before the rules
// see them. An entry that isn't JSON is checked as it is.
func entryStrings(raw string) string {
	var v any
	if json.Unmarshal([]byte(raw), &v) != nil {
		return raw
	}
	var out []string
	var walk func(any)
	walk = func(v any) {
		switch v := v.(type) {
		case string:
			out = append(out, v)
		case []any:
			for _, x := range v {
				walk(x)
			}
		case map[string]any:
			keys := make([]string, 0, len(v))
			for k := range v {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				out = append(out, k)
				walk(v[k])
			}
		}
	}
	walk(v)
	return strings.Join(out, "\n")
}

// mcpFindings are the two MCP-only rules over each project's listed
// servers.
func mcpFindings(s *redact.Scrubber, projects []model.Project) []finding.Finding {
	seen := map[string]bool{}
	var out []finding.Finding
	add := func(r finding.Rule, o model.Origin, ev string) {
		if key := r.ID + "\x00" + o.File.Raw() + "\x00" + ev; !seen[key] {
			seen[key] = true
			t, _ := s.Scrub(ev)
			out = append(out, r.New(o, t))
		}
	}
	for _, p := range projects {
		offered := map[string]string{} // agent and tool name to the first server offering it
		for _, srv := range p.Servers {
			if srv.Status == model.StatusListed {
				serverTools(srv, offered, add)
			}
		}
	}
	return out
}

// serverTools checks one listed server's tools for lying annotations, and
// for names an earlier server in offered already has.
func serverTools(srv model.Server, offered map[string]string, add func(finding.Rule, model.Origin, string)) {
	for _, o := range srv.Offers {
		if o.Kind != model.OfferTool {
			continue
		}
		if why := lies(o); why != "" {
			add(lyingAnnotation(), srv.Origin, "tool "+o.Name.String()+" of "+srv.Name.String()+" is marked readOnlyHint, but "+why)
		}
		key := string(srv.Origin.Agent) + "\x00" + o.Name.String()
		if first, ok := offered[key]; ok && first != srv.Name.String() {
			add(shadowedTool(), srv.Origin, "tool "+o.Name.String()+" is offered by both "+first+" and "+srv.Name.String())
		} else if !ok {
			offered[key] = srv.Name.String()
		}
	}
}

// lies says why a read-only tool's annotations don't hold, or "".
func lies(o model.Offer) string {
	hinted := func(h string) bool {
		return slices.ContainsFunc(o.Hints, func(t redact.Text) bool { return t.String() == h })
	}
	if !hinted("readOnlyHint") {
		return ""
	}
	if hinted("destructiveHint") {
		return "it's also marked destructiveHint"
	}
	if w := o.ChangeWord(); w != "" {
		return "its name says " + w
	}
	return ""
}
