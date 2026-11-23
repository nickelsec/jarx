package perms

import (
	"slices"
	"strings"
	"testing"

	"github.com/nickelsec/jarx/internal/model"
)

// unknownRule is a rule the adapter marked as naming no tool it knows.
func (f fixture) unknownRule(action model.RuleAction, rule, near string) model.PermissionRule {
	r := f.claudeRule(action, rule)
	r.ToolUnknown, r.NearTool = true, f.text(near)
	return r
}

func TestAMisspelledDenyOrAskProtectsNothing(t *testing.T) {
	f := newFixture(t)
	for _, action := range []model.RuleAction{model.RuleDeny, model.RuleAsk} {
		got := f.analyze(f.project(f.claude(f.unknownRule(action, "Raed(./.env)", "Read"))))

		x, ok := findID(got, misspelledTool().ID)
		if !ok || x.Severity != misspelledTool().Severity || !strings.Contains(x.Evidence.String(), "Raed(./.env)") || !strings.Contains(x.Evidence.String(), "Read") {
			t.Errorf("%s: findings = %q, want the misspelled tool with its rule and the likely name", action, ids(got))
		}
	}
}

func TestOtherUnknownToolsAreNoted(t *testing.T) {
	f := newFixture(t)
	for name, r := range map[string]model.PermissionRule{
		"an allow typo":            f.unknownRule(model.RuleAllow, "Raed(./docs/**)", "Read"),
		"a deny with no near name": f.unknownRule(model.RuleDeny, "FancyNewTool", ""),
	} {
		got := f.analyze(f.project(f.claude(r)))

		if !slices.Contains(ids(got), unknownTool().ID) || slices.Contains(ids(got), misspelledTool().ID) {
			t.Errorf("%s: findings = %q, want only the unknown-tool note", name, ids(got))
		}
	}
}

func TestKnownToolsAndRulesNotInEffectAreQuiet(t *testing.T) {
	f := newFixture(t)
	off := f.unknownRule(model.RuleDeny, "Raed(./.env)", "Read")
	off.Origin.InEffect = false

	got := f.analyze(f.project(f.claude(f.claudeRule(model.RuleDeny, "Read(./.env)"), off)))

	if slices.Contains(ids(got), misspelledTool().ID) || slices.Contains(ids(got), unknownTool().ID) {
		t.Errorf("findings = %q, want none for a known tool or a file that isn't loaded", ids(got))
	}
}
