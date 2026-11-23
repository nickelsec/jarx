package claude

import "github.com/nickelsec/jarx/internal/finding"

// RepoServerTakesName is a repository's .mcp.json server with the name of
// one of your user servers. Once approved it replaces yours, and permission
// rules, hooks and policy entries written for that name apply to the
// repository's server. A local server wins over the project's, so it can't
// be taken over this way.
func RepoServerTakesName() finding.Rule {
	return finding.Rule{
		ID: "JARX-CLAUDE-006", Severity: finding.High, Title: "A repo MCP server takes your server's name",
		Detail: "a repository's .mcp.json defines a server with the name of one of your user servers; once it's approved, Claude uses it instead of yours, and your mcp__<name>__ permission rules and hooks apply to it",
		Fix:    "reject it with disabledMcpjsonServers, or rename your own server",
	}
}

// SameNameOtherEndpoint is one server name in two scopes with different
// endpoints, which Claude warns about.
func SameNameOtherEndpoint() finding.Rule {
	return finding.Rule{
		ID: "JARX-CLAUDE-007", Severity: finding.Info, Title: "An MCP server name points two places",
		Detail: "the same server name is defined in two scopes with different URLs or commands; Claude uses the higher scope's, which may not be the one you sign in to",
		Fix:    "keep one definition and remove the others with claude mcp remove <name> --scope <scope>",
	}
}

// nameFindings flags the name clashes among a project's definitions. A pair
// that isn't tied to this project is reported once across projects.
func (e *extReader) nameFindings(defs []def) {
	for i, d := range defs {
		for _, h := range defs[i+1:] {
			if d.raw.name != h.raw.name || d.rank == rankPlugin || h.rank == rankPlugin {
				continue
			}
			if h.rank < d.rank {
				d, h = h, d
			}
			e.namePair(d, h)
		}
	}
}

// namePair checks one pair with the same name, hi winning over lo.
func (e *extReader) namePair(hi, lo def) {
	if hi.rank == rankProject && lo.rank == rankUser { // local beats project, so only a user server can be taken over
		e.findings = append(e.findings, RepoServerTakesName().New(hi.origin, e.text(
			"the repository's .mcp.json defines "+hi.raw.name+", the name of your "+rankScope(lo.rank)+" server; once approved it replaces yours")))
		return
	}
	if endpoint(hi.raw) == endpoint(lo.raw) {
		return
	}
	key := hi.origin.File.Raw() + "\x00" + lo.origin.File.Raw() + "\x00" + hi.raw.name
	if hi.rank == rankProject || lo.rank == rankProject || lo.rank == rankLocal {
		key += "\x00" + e.project.Path.Raw() // tied to this project
	}
	if e.seen[key] {
		return
	}
	e.seen[key] = true
	e.findings = append(e.findings, SameNameOtherEndpoint().New(lo.origin, e.text(
		hi.raw.name+" is defined in "+rankScope(hi.rank)+" and "+rankScope(lo.rank)+" with different endpoints; Claude uses the "+rankScope(hi.rank)+" one")))
}
