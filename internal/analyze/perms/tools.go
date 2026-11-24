package perms

import (
	"slices"

	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/model"
)

// A Claude rule naming a tool Claude doesn't have applies to nothing. The
// adapter marks those with the catalog; these rules raise them.

func misspelledTool() finding.Rule {
	return rule("JARX-PERMS-011", finding.High, "a deny or ask rule's tool is misspelled",
		"a deny or ask rule names a tool that doesn't exist but is close to one that does, so the protection it was meant to add isn't on",
		"fix the tool name, then check the rule applies")
}

func deadPathRule() finding.Rule {
	return rule("JARX-PERMS-013", finding.High, "a deny or ask path rule never matches",
		"a deny or ask rule gives Grep, Glob or Write a path, but Claude checks reads and edits against Read and Edit rules only, so this rule protects nothing",
		"write it as a Read rule for reads, or an Edit rule for writes")
}

// deadPathTools take a path in a rule that Claude accepts but never matches
// (permissions docs: Write(path), Glob(path) and Grep(path) rules don't
// match).
//
//nolint:gochecknoglobals // fixed list, read only
var deadPathTools = []string{"Grep", "Glob", toolWrite}

// toolWrite is Claude's Write tool, whose path rules never match.
const toolWrite = "Write"

// deadPath flags a deny or ask that names a path for one of those tools.
func (a *analysis) deadPath(r model.PermissionRule) {
	if r.Action != model.RuleDeny && r.Action != model.RuleAsk {
		return
	}
	tool, pattern := ruleTool(r.Rule.String())
	if !slices.Contains(deadPathTools, tool) || pattern == "" || pattern == "*" {
		return
	}
	want := "Read"
	if tool == toolWrite {
		want = "Edit"
	}
	a.add(deadPathRule(), r.Origin, string(r.Action)+" "+r.Rule.String()+" never matches; write "+want+"("+pattern+") instead")
}

func unknownTool() finding.Rule {
	return rule("JARX-PERMS-012", finding.Info, "a rule names a tool jarx doesn't know",
		"a permission rule names a tool that isn't in jarx's catalog of built-in tools: a typo, or a tool newer than the catalog",
		"check the name against the agent's tools reference")
}

// toolName flags a rule whose tool the adapter didn't find. A deny or ask
// close to a real tool is the dangerous case: the protection is off.
func (a *analysis) toolName(r model.PermissionRule) {
	if !r.ToolUnknown {
		return
	}
	near := r.NearTool.String()
	if near != "" && (r.Action == model.RuleDeny || r.Action == model.RuleAsk) {
		a.add(misspelledTool(), r.Origin, string(r.Action)+" "+r.Rule.String()+" names no tool; did you mean "+near+"?")
		return
	}
	ev := string(r.Action) + " " + r.Rule.String() + " names no tool jarx knows"
	if near != "" {
		ev += "; did you mean " + near + "?"
	}
	a.add(unknownTool(), r.Origin, ev)
}
