package versions

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/nickelsec/jarx/internal/catalog"
	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/redact"
)

func scrubber(t *testing.T) *redact.Scrubber {
	t.Helper()
	s, err := redact.New([]redact.Pattern{{Kind: "test_token", Re: regexp.MustCompile(`tok_[A-Za-z0-9]{16,}`)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func install(s *redact.Scrubber, a model.Agent, m model.InstallMethod, path, version string, onPath bool) model.Install {
	v, _ := s.Scrub(version)
	return model.Install{Agent: a, Method: m, Path: model.NewPath(s, path), BinDir: model.NewPath(s, path), Version: v, OnPath: onPath}
}

func ruleIDs(fs []finding.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.RuleID)
	}
	slices.Sort(out)
	return out
}

func TestAnInstallWithAHighAdvisoryIsHigh(t *testing.T) {
	s := scrubber(t)
	in := install(s, model.AgentClaude, model.InstallNative, "/home/me/.local/bin/claude", "2.1.120", true)

	got := Analyze(s, []model.Install{in})

	if len(got) != 1 || got[0].RuleID != VulnerableHigh().ID || got[0].Severity != finding.High {
		t.Fatalf("findings = %q, want one %s", ruleIDs(got), VulnerableHigh().ID)
	}
	ev := got[0].Evidence.String()
	for _, want := range []string{"2.1.120", "GHSA-5j29-h97v-84ch", "2.1.260"} {
		if !strings.Contains(ev, want) {
			t.Errorf("evidence = %q, want it to name %s (the version, the worst advisory and the version that fixes them all)", ev, want)
		}
	}
	if got[0].Origin.File.Raw() != in.Path.Raw() || got[0].Origin.Agent != model.AgentClaude {
		t.Errorf("origin = %s %s, want the install", got[0].Origin.Agent, got[0].Origin.File.Raw())
	}
}

func TestTheWorstAdvisorySetsTheRule(t *testing.T) {
	s := scrubber(t)
	// No real Claude version sits only in medium advisories (GHSA-5xjx, a
	// high, covers everything before 2.1.251), so this one fakes the data.
	lookup := func(_ model.Agent, v string) []catalog.Advisory {
		return map[string][]catalog.Advisory{
			"1.0.0": {{ID: "GHSA-crit", Severity: "critical", Fixed: "1.0.1"}, {ID: "GHSA-low", Severity: "low", Fixed: "1.0.1"}},
			"2.0.0": {{ID: "GHSA-med", Severity: "medium", Fixed: "2.0.1"}, {ID: "GHSA-low", Severity: "low", Fixed: "2.0.1"}},
			"3.0.0": {{ID: "GHSA-low", Severity: "low", Fixed: "3.0.1"}},
		}[v]
	}
	for _, tc := range []struct {
		version string
		want    []string
	}{
		{"1.0.0", []string{VulnerableHigh().ID}}, // critical counts as high
		{"2.0.0", []string{VulnerableMedium().ID}},
		{"3.0.0", []string{VulnerableLow().ID}},
		{"4.0.0", []string{}},
	} {
		got := analyze(s, []model.Install{install(s, model.AgentClaude, model.InstallNPM, "/npm", tc.version, true)}, lookup)
		if ids := ruleIDs(got); !slices.Equal(ids, tc.want) {
			t.Errorf("%s: findings = %q, want %q", tc.version, ids, tc.want)
		}
	}
}

func TestTheRealDataFlagsALowOnlyVersion(t *testing.T) {
	s := scrubber(t)
	// 2.1.255 is only in GHSA-gfvf-j8jh-jxxw, a low.
	got := Analyze(s, []model.Install{install(s, model.AgentClaude, model.InstallNPM, "/npm", "2.1.255", true)})

	if ids := ruleIDs(got); !slices.Equal(ids, []string{VulnerableLow().ID}) {
		t.Errorf("findings = %q, want %s", ids, VulnerableLow().ID)
	}
}

func TestAnUnknownVersionIsntCheckedAgainstAdvisories(t *testing.T) {
	s := scrubber(t)
	in := install(s, model.AgentClaude, model.InstallNative, "/bin/claude", "", false)

	if got := Analyze(s, []model.Install{in}); len(got) != 0 {
		t.Errorf("findings = %q, want none", ruleIDs(got))
	}
}

func TestAnOlderInstallWinningOnPathIsFlagged(t *testing.T) {
	s := scrubber(t)
	ins := []model.Install{
		install(s, model.AgentCodex, model.InstallNPM, "/npm/codex", "0.170.0", true),
		install(s, model.AgentCodex, model.InstallNPM, "/other/codex", "0.171.0", false),
		install(s, model.AgentClaude, model.InstallNPM, "/npm/claude", "2.1.400", false), // another agent
	}

	got := Analyze(s, ins)

	if ids := ruleIDs(got); !slices.Equal(ids, []string{OlderOnPath().ID}) {
		t.Fatalf("findings = %q, want %s", ids, OlderOnPath().ID)
	}
	if ev := got[0].Evidence.String(); !strings.Contains(ev, "0.170.0") || !strings.Contains(ev, "0.171.0") {
		t.Errorf("evidence = %q, want both versions", ev)
	}
}

func TestTheNewestWinningOnPathIsFine(t *testing.T) {
	s := scrubber(t)
	ins := []model.Install{
		install(s, model.AgentCodex, model.InstallNPM, "/npm/codex", "0.171.0", true),
		install(s, model.AgentCodex, model.InstallNPM, "/other/codex", "0.170.0", false),
	}

	if got := Analyze(s, ins); len(got) != 0 {
		t.Errorf("findings = %q, want none", ruleIDs(got))
	}
}

func TestAPathWinnerAtAnUnknownPlaceIsANote(t *testing.T) {
	s := scrubber(t)
	in := install(s, model.AgentCodex, model.InstallUnknown, "/opt/codex/bin/codex", "", true)

	got := Analyze(s, []model.Install{in})

	if ids := ruleIDs(got); !slices.Equal(ids, []string{UnknownOnPath().ID}) || got[0].Severity != finding.Info {
		t.Errorf("findings = %q, want one info %s", ids, UnknownOnPath().ID)
	}
}

func TestRulesAreAllRegistered(t *testing.T) {
	if _, err := finding.NewRegistry(Rules()...); err != nil {
		t.Fatal(err)
	}
	if got := len(Rules()); got != 5 {
		t.Errorf("%d rules, want 5", got)
	}
}

func TestOneAdvisoryIsFixedByItsOwnVersion(t *testing.T) {
	s := scrubber(t)
	got := Analyze(s, []model.Install{install(s, model.AgentCodex, model.InstallNPM, "/npm/codex", "0.38.0", true)})

	if len(got) != 1 {
		t.Fatalf("findings = %q, want one", ruleIDs(got))
	}
	if ev := got[0].Evidence.String(); !strings.HasSuffix(ev, "; 0.39.0 fixes it") {
		t.Errorf("evidence = %q, want it to end with the fix for the one advisory", ev)
	}
}
