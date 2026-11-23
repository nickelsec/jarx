package perms

import (
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
