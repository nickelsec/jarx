// Package capability works out, for each tool a listed MCP server offers,
// whether the agent can call it and whether you're asked first, and flags
// the tools that change things and run without asking. That's the third
// layer of the PRD's capability view: what the server offers is on the
// model already, and what the server's own credential allows can't be known
// without calling it, which jarx never does.
//
// Claude, from code.claude.com/docs/en/permissions#mcp: rules name a whole
// server (mcp__<server>, mcp__<server>__*) or one tool
// (mcp__<server>__<tool>), with characters other than letters, digits, _ and
// - turned into _, and plugin servers as plugin_<plugin>_<server>. Deny
// beats ask beats allow, an allow with a specifier matches nothing, and a
// server name with __ in it or ending in _ is allowed only by the wildcard
// form, while a shorter deny or ask still covers it. With no rule the mode
// decides: bypassPermissions runs it, dontAsk denies it, auto leaves it to a
// classifier, and the rest ask.
//
// Codex, from developers.openai.com/codex/mcp and /agent-approvals-security:
// enabled_tools and then disabled_tools decide which tools the agent sees.
// approval_mode (per tool, else the server's default) prompt asks, writes
// asks unless the tool is marked read-only, and auto and approve aren't
// described, so they may run without asking. With no mode, a tool marked
// destructive always asks unless it's also marked read-only (the read
// annotation wins), and the rest follow approval_policy.
package capability

import (
	"regexp"
	"slices"
	"strings"

	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/redact"
)

// DestructiveRunsUnasked is a tool that changes things and runs without
// asking because an allow or approval mode says so.
func DestructiveRunsUnasked() finding.Rule {
	return finding.Rule{
		ID: "JARX-CAP-001", Severity: finding.High, Title: "A tool that changes things runs unasked",
		Detail: "an MCP tool marked destructive, or named for a change (delete, write, send and the like), is pre-approved by an allow rule or approval mode, so the agent can call it without asking you",
		Fix:    "remove it from the allow, or set it to ask; allow only the tools that read",
	}
}

// UndocumentedApproval is a Codex approval mode whose meaning the docs
// don't give.
func UndocumentedApproval() finding.Rule {
	return finding.Rule{
		ID: "JARX-CAP-002", Severity: finding.Medium, Title: "A Codex MCP approval mode may skip asking",
		Detail: "a Codex MCP server or tool sets approval_mode or default_tools_approval_mode to auto or approve; the docs don't say what these do, and they may let tools run without asking you",
		Fix:    "use prompt, or writes to ask only for tools that aren't marked read-only",
	}
}

// Rules returns the analyzer's rules.
func Rules() []finding.Rule { return []finding.Rule{DestructiveRunsUnasked(), UndocumentedApproval()} }

// Settle sets Access and AccessWhy on every tool of every listed server.
func Settle(s *redact.Scrubber, projects []model.Project) {
	for i := range projects {
		p := &projects[i]
		for j := range p.Servers {
			srv := &p.Servers[j]
			if srv.Status != model.StatusListed {
				continue
			}
			perm := permissionsOf(*p, srv.Origin.Agent)
			for k := range srv.Offers {
				o := &srv.Offers[k]
				if o.Kind != model.OfferTool {
					continue
				}
				var a model.ToolAccess
				var why string
				if srv.Origin.Agent == model.AgentCodex {
					a, why = codexAccess(*srv, *o, perm)
				} else {
					a, why, _ = claudeAccess(*srv, *o, perm)
				}
				o.Access = a
				o.AccessWhy, _ = s.Scrub(why)
			}
		}
	}
}

func permissionsOf(p model.Project, a model.Agent) model.Permissions {
	for _, perm := range p.Permissions {
		if perm.Agent == a {
			return perm
		}
	}
	return model.Permissions{Agent: a}
}

func hinted(o model.Offer, h string) bool {
	return slices.ContainsFunc(o.Hints, func(t redact.Text) bool { return t.String() == h })
}

var notNameChar = regexp.MustCompile(`[^A-Za-z0-9_-]`)

// serverPart is the server's name the way it shows in its tool names.
func serverPart(srv model.Server) string {
	name := srv.Name.String()
	if !srv.Plugin.IsZero() {
		plugin, _, _ := strings.Cut(srv.Plugin.String(), "@")
		name = "plugin_" + plugin + "_" + name
	}
	return notNameChar.ReplaceAllString(name, "_")
}

// claudeAccess settles one tool for Claude, and gives the allow rule that
// lets it run without asking, if one does.
func claudeAccess(srv model.Server, o model.Offer, perm model.Permissions) (model.ToolAccess, string, *model.PermissionRule) {
	server, tool := serverPart(srv), notNameChar.ReplaceAllString(o.Name.String(), "_")
	full := "mcp__" + server + "__" + tool
	cover := func(r *model.PermissionRule) bool { return covers(r, server, full) }
	deny := firstRule(perm, model.RuleDeny, cover)
	ask := firstRule(perm, model.RuleAsk, cover)
	allow := firstRule(perm, model.RuleAllow, func(r *model.PermissionRule) bool { return allows(r, server, full) })
	in := func(r *model.PermissionRule) string { return r.Rule.String() + " in " + r.Origin.File.Text().String() }
	switch {
	case deny != nil:
		return model.AccessDenied, "denied by " + in(deny), nil
	case ask != nil:
		return model.AccessAsks, "asks: " + in(ask), nil
	case allow != nil:
		return model.AccessNoAsk, "allowed by " + in(allow), allow
	}
	a, why := claudeMode(perm)
	return a, why, nil
}

// firstRule is the first in-effect rule with the action that applies.
func firstRule(perm model.Permissions, action model.RuleAction, applies func(*model.PermissionRule) bool) *model.PermissionRule {
	for i := range perm.Rules {
		if r := &perm.Rules[i]; r.Origin.InEffect && r.Action == action && applies(r) {
			return r
		}
	}
	return nil
}

// claudeMode is the access the default mode gives a tool no rule covers.
func claudeMode(perm model.Permissions) (model.ToolAccess, string) {
	// The start mode is the defaultMode in effect, else Claude's built-in
	// one, which the adapter worked out. Without one, the defaultMode.
	mode, why := perm.StartMode.String(), perm.StartWhy.String()
	if mode == "" {
		if l, ok := perm.DefaultMode.Effective(); ok {
			mode, why = l.Value.String(), "defaultMode is "+l.Value.String()
		}
	}
	switch mode {
	case "bypassPermissions":
		return model.AccessNoAsk, "the session starts in bypassPermissions: " + why
	case "dontAsk":
		return model.AccessDenied, "dontAsk mode denies tools no rule allows: " + why
	case modeAuto:
		return model.AccessMayNotAsk, "auto mode, where a classifier decides instead of asking you: " + why
	}
	return model.AccessAsks, "no rule allows it, so Claude asks"
}

// modeAuto is both a Claude default mode and a Codex approval mode.
const modeAuto = "auto"

// covers says whether a deny or ask rule applies to every call of the tool:
// the server's name or wildcard (a shorter name too, for a server with __
// in it), or the tool's own name, with no specifier.
func covers(r *model.PermissionRule, server, full string) bool {
	rule := r.Rule.String()
	if !r.Target.IsZero() {
		return false // only some calls
	}
	return rule == full || strings.HasPrefix(full, strings.TrimSuffix(rule, "*")) && strings.HasSuffix(rule, "__*") ||
		strings.HasPrefix(full, rule+"__") && strings.HasPrefix(rule, "mcp__") || rule == "mcp__"+server
}

// allows says whether an allow rule pre-approves the tool. The bare server
// name works only for a name with no __ and no trailing _.
func allows(r *model.PermissionRule, server, full string) bool {
	if !r.Target.IsZero() {
		return false // an allow with a specifier matches nothing
	}
	rule := r.Rule.String()
	clean := !strings.Contains(server, "__") && !strings.HasSuffix(server, "_")
	return rule == full || rule == "mcp__"+server+"__*" || (clean && rule == "mcp__"+server)
}

// approvalMode is the tool's own approval mode, else the server's default.
func approvalMode(srv model.Server, tool string) string {
	def := ""
	for _, a := range srv.Approvals {
		switch a.Key.String() {
		case tool:
			return a.Value.String()
		case "":
			def = a.Value.String()
		}
	}
	return def
}

func codexAccess(srv model.Server, o model.Offer, perm model.Permissions) (model.ToolAccess, string) {
	tool := o.Name.String()
	switch {
	case srv.EnabledTools != nil && !slices.Contains(texts(srv.EnabledTools), tool):
		return model.AccessHidden, "not in enabled_tools"
	case slices.Contains(texts(srv.DisabledTools), tool):
		return model.AccessHidden, "in disabled_tools"
	}
	if a, why, ok := codexMode(approvalMode(srv, tool), hinted(o, "readOnlyHint")); ok {
		return a, why
	}
	return codexDefault(o, perm)
}

func texts(ts []redact.Text) []string {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, t.String())
	}
	return out
}

// codexMode is the access an approval mode gives, when one is set.
func codexMode(mode string, readOnly bool) (model.ToolAccess, string, bool) {
	switch mode {
	case "prompt":
		return model.AccessAsks, "approval_mode prompt", true
	case "writes":
		if readOnly {
			return model.AccessMayNotAsk, "approval_mode writes, and the tool is marked read-only", true
		}
		return model.AccessAsks, "approval_mode writes, and the tool isn't marked read-only", true
	case modeAuto, modeApprove:
		return model.AccessMayNotAsk, "approval_mode " + mode + ", which the docs don't describe", true
	}
	return model.AccessUnsettled, "", false
}

// modeApprove is the other Codex approval mode the docs don't describe.
const modeApprove = "approve"

// codexDefault is the access with no approval mode: a tool marked
// destructive asks unless it's also marked read-only, and the rest follow
// approval_policy.
func codexDefault(o model.Offer, perm model.Permissions) (model.ToolAccess, string) {
	readOnly := hinted(o, "readOnlyHint")
	if hinted(o, "destructiveHint") && !readOnly {
		return model.AccessAsks, "marked destructive, so Codex always asks"
	}
	policy := option(perm, "approval_policy")
	if policy == "never" {
		return model.AccessNoAsk, "approval_policy never"
	}
	why := "Codex decides by approval_policy"
	if policy != "" {
		why += " " + policy
	}
	if readOnly {
		why += "; the tool is marked read-only, which Codex trusts"
	}
	return model.AccessMayNotAsk, why
}

func option(perm model.Permissions, key string) string {
	for _, o := range perm.Options {
		if o.Key.String() == key {
			if l, ok := o.Setting.Effective(); ok {
				return l.Value.String()
			}
		}
	}
	return ""
}

// changes says whether a tool changes things: marked destructive and not
// read-only, or named for a change.
func changes(o model.Offer) bool {
	if hinted(o, "destructiveHint") && !hinted(o, "readOnlyHint") {
		return true
	}
	return o.ChangeWord() != ""
}

// Analyze flags tools that change things and run without asking because a
// specific allow says so (a mode like bypassPermissions has its own rule),
// and Codex approval modes the docs don't describe.
func Analyze(s *redact.Scrubber, projects []model.Project) []finding.Finding {
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
		for _, srv := range p.Servers {
			if srv.Start == model.StartNo {
				continue
			}
			for _, what := range undocumentedModes(srv) {
				add(UndocumentedApproval(), srv.Origin, what)
			}
			if srv.Status == model.StatusListed {
				unasked(srv, permissionsOf(p, srv.Origin.Agent), add)
			}
		}
	}
	return out
}

// undocumentedModes describes each auto or approve approval mode a server
// sets.
func undocumentedModes(srv model.Server) []string {
	var out []string
	for _, a := range srv.Approvals {
		if m := a.Value.String(); m == modeAuto || m == modeApprove {
			what := "default_tools_approval_mode " + m + " for " + srv.Name.String()
			if !a.Key.IsZero() {
				what = "approval_mode " + m + " for tool " + a.Key.String() + " of " + srv.Name.String()
			}
			out = append(out, what)
		}
	}
	return out
}

// letThrough says whether a specific allow rule or approval mode lets the
// tool run without asking, and where that's set: the rule's file for
// Claude, the server's for Codex.
func letThrough(srv model.Server, o model.Offer, perm model.Permissions) (model.Origin, bool) {
	if srv.Origin.Agent == model.AgentCodex {
		return srv.Origin, o.Access == model.AccessMayNotAsk && strings.HasPrefix(o.AccessWhy.String(), "approval_mode")
	}
	if _, _, rule := claudeAccess(srv, o, perm); rule != nil {
		return rule.Origin, true
	}
	return model.Origin{}, false
}

// unasked flags the tools that change things and run without asking
// because of a specific allow or approval mode. The finding goes on the
// allow rule's file for Claude and on the server's for Codex.
func unasked(srv model.Server, perm model.Permissions, add func(finding.Rule, model.Origin, string)) {
	// One allow rule or approval mode is one fix, so the tools it lets
	// through are one finding.
	type group struct {
		origin model.Origin
		why    string
		tools  []string
	}
	var groups []*group
	for _, o := range srv.Offers {
		if o.Kind != model.OfferTool || !changes(o) {
			continue
		}
		origin, ok := letThrough(srv, o, perm)
		if !ok {
			continue
		}
		i := slices.IndexFunc(groups, func(g *group) bool { return g.why == o.AccessWhy.String() && g.origin.File.Raw() == origin.File.Raw() })
		if i < 0 {
			groups = append(groups, &group{origin: origin, why: o.AccessWhy.String()})
			i = len(groups) - 1
		}
		groups[i].tools = append(groups[i].tools, o.Name.String())
	}
	for _, g := range groups {
		what := "tool "
		if len(g.tools) > 1 {
			what = "tools "
		}
		add(DestructiveRunsUnasked(), g.origin, what+strings.Join(g.tools, ", ")+" of "+srv.Name.String()+" "+g.why)
	}
}
