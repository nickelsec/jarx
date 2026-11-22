package finding

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/nickelsec/jarx/internal/fsys"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/redact"
)

const canary = "tok_Xq7Lm2Pz9Rw4Tb8Nc1Vd" // made up for tests

func scrubber(t *testing.T) *redact.Scrubber {
	t.Helper()
	s, err := redact.New([]redact.Pattern{
		{Kind: "test_token", Re: regexp.MustCompile(`tok_[A-Za-z0-9]{16,}`)},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func rule(id string, sev Severity) Rule {
	return Rule{ID: id, Severity: sev, Title: "a title", Fix: "a fix"}
}

func TestSeverityNamesAndOrder(t *testing.T) {
	want := map[Severity]string{Info: "info", Medium: "medium", High: "high", Critical: "critical"}
	for sev, name := range want {
		if sev.String() != name {
			t.Errorf("%d.String() = %q, want %q", sev, sev.String(), name)
		}
	}
	if Info >= Medium || Medium >= High || High >= Critical {
		t.Error("severities are out of order")
	}
}

func TestRegistryAcceptsGoodRules(t *testing.T) {
	r, err := NewRegistry(rule("JARX-MCP-001", High), rule("JARX-HOOK-002", Medium))
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}

	got, ok := r.Lookup("JARX-HOOK-002")
	if !ok || got.Severity != Medium {
		t.Errorf("Lookup() = %+v, %v; want the hook rule", got, ok)
	}
	if _, ok := r.Lookup("JARX-NOPE-001"); ok {
		t.Error("Lookup() found a rule that wasn't registered")
	}
}

func TestRegistryRejectsBadRules(t *testing.T) {
	for name, rules := range map[string][]Rule{
		"lowercase id":  {rule("JARX-mcp-001", High)},
		"short number":  {rule("JARX-MCP-1", High)},
		"other prefix":  {rule("FOO-MCP-001", High)},
		"duplicate id":  {rule("JARX-MCP-001", High), rule("JARX-MCP-001", Info)},
		"no title":      {{ID: "JARX-MCP-001", Severity: High, Fix: "f"}},
		"no fix":        {{ID: "JARX-MCP-001", Severity: High, Title: "t"}},
		"zero severity": {rule("JARX-MCP-001", 0)},
		"wild severity": {rule("JARX-MCP-001", 99)},
	} {
		if _, err := NewRegistry(rules...); err == nil {
			t.Errorf("%s: NewRegistry() error = nil, want an error", name)
		}
	}
}

func TestRuleNewTakesSeverityFromTheRule(t *testing.T) {
	s := scrubber(t)
	o := model.Origin{Agent: model.AgentClaude, File: model.NewPath(s, "/p/.mcp.json"), Line: 4}
	ev, _ := s.Scrub("evidence")

	f := rule("JARX-MCP-001", Critical).New(o, ev)

	if f.RuleID != "JARX-MCP-001" || f.Severity != Critical || f.Origin.Line != 4 || f.Evidence.String() != "evidence" {
		t.Errorf("New() = %+v, want the rule's id and severity with the origin and evidence", f)
	}
}

func TestSortPutsWorstFirst(t *testing.T) {
	s := scrubber(t)
	at := func(file string, line int) model.Origin {
		return model.Origin{File: model.NewPath(s, file), Line: line}
	}
	fs := []Finding{
		rule("JARX-B-001", Info).New(at("/a", 1), redact.Text{}),
		rule("JARX-A-001", High).New(at("/b", 9), redact.Text{}),
		rule("JARX-A-001", High).New(at("/a", 2), redact.Text{}),
		rule("JARX-C-001", Critical).New(at("/z", 1), redact.Text{}),
		rule("JARX-A-001", High).New(at("/a", 1), redact.Text{}),
		rule("JARX-B-001", Medium).New(at("/a", 1), redact.Text{}),
	}

	Sort(fs)

	got := make([]string, 0, len(fs))
	for _, f := range fs {
		got = append(got, fmt.Sprintf("%s %s %s:%d", f.Severity, f.RuleID, f.Origin.File, f.Origin.Line))
	}
	want := []string{
		"critical JARX-C-001 /z:1",
		"high JARX-A-001 /a:1",
		"high JARX-A-001 /a:2",
		"high JARX-A-001 /b:9",
		"medium JARX-B-001 /a:1",
		"info JARX-B-001 /a:1",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("Sort() order:\n  %s\nwant\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
}

func TestFromSkipsMakesAMaskedInfoFindingPerSkip(t *testing.T) {
	s := scrubber(t)
	skips := []fsys.Skip{
		{Path: "/home/dev/" + canary + "/CLAUDE.md", Size: 12 << 20, Reason: "too large"},
		{Path: "/home/dev/big.md", Size: 11 << 20, Reason: "too large"},
	}

	got := FromSkips(s, skips)

	if len(got) != 2 {
		t.Fatalf("FromSkips() = %d findings, want 2", len(got))
	}
	f := got[0]
	if f.RuleID != SkippedTooLarge().ID || f.Severity != Info || f.Origin.Agent != model.AgentJarx {
		t.Errorf("finding = %+v, want an info %s from jarx", f, SkippedTooLarge().ID)
	}
	if !strings.Contains(f.Evidence.String(), "skipped, too large") || !strings.Contains(f.Evidence.String(), "12582912 bytes") {
		t.Errorf("evidence = %q, want the reason and size", f.Evidence)
	}
	if f.Origin.File.Raw() != skips[0].Path {
		t.Errorf("origin file raw = %q, want the skipped path", f.Origin.File.Raw())
	}
	if out := fmt.Sprintf("%+v %#v", f, f); strings.Contains(out, canary) {
		t.Errorf("finding prints the raw path: %s", out)
	}
}

func TestJarxsOwnRulesAreValid(t *testing.T) {
	if _, err := NewRegistry(Rules()...); err != nil {
		t.Errorf("NewRegistry(Rules()) error = %v", err)
	}
	if len(Rules()) == 0 || Rules()[0].ID != SkippedTooLarge().ID {
		t.Errorf("Rules() = %+v, want it to include %s", Rules(), SkippedTooLarge().ID)
	}
}
