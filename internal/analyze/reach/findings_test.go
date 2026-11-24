package reach

import (
	"slices"
	"strings"
	"testing"

	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/model"
)

func (w *world) analyze() []finding.Finding {
	w.t.Helper()
	ps := w.settle()
	return Analyze(w.s, w.env, ps)
}

func ruleIDs(fs []finding.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.RuleID)
	}
	slices.Sort(out)
	return out
}

func TestCredentialsReadableWithoutAskingAreOneFindingPerProject(t *testing.T) {
	w := newWorld(t, "linux", "")
	w.creds = append(w.creds, w.file("ssh", ".ssh/id_ed25519"))

	got := w.analyze()

	if !slices.Equal(ruleIDs(got), []string{ReadableSilently().ID}) {
		t.Fatalf("findings = %q, want one REACH-001", ruleIDs(got))
	}
	if ev := got[0].Evidence.String(); !strings.Contains(ev, "2 credentials") || !strings.Contains(ev, ".aws") || !strings.Contains(ev, "id_ed25519") {
		t.Errorf("evidence = %q, want both credentials counted and named", ev)
	}
}

func TestNoFindingWhenEveryCredentialAsksOrIsBlocked(t *testing.T) {
	w := newWorld(t, "linux", "")
	w.sandbox()
	w.rule(model.RuleDeny, "sandbox.filesystem.denyRead ~/.aws")
	w.option("sandbox.allowUnsandboxedCommands", "false")

	if got := w.analyze(); len(got) != 0 {
		t.Errorf("findings = %q, want none: file tools ask and the sandbox blocks the shell", ruleIDs(got))
	}
}

func TestABypassableDenyIsFlaggedOnItsRule(t *testing.T) {
	w := newWorld(t, "linux", "")
	w.rule(model.RuleDeny, "Read(~/.aws/**)")

	got := w.analyze()

	var f finding.Finding
	for _, x := range got {
		if x.RuleID == BypassableDeny().ID {
			f = x
		}
	}
	if f.RuleID == "" || !strings.Contains(f.Evidence.String(), "Read(~/.aws/**)") || !strings.Contains(f.Origin.File.Raw(), "settings.json") {
		t.Fatalf("findings = %q (%+v), want REACH-002 on the deny rule's file", ruleIDs(got), f)
	}
	if !slices.Contains(ruleIDs(got), ReadableSilently().ID) {
		t.Errorf("findings = %q, want REACH-001 too: Bash reads it without asking", ruleIDs(got))
	}
}

func TestRulesRegister(t *testing.T) {
	if _, err := finding.NewRegistry(Rules()...); err != nil {
		t.Fatal(err)
	}
}

func TestTheEvidenceSurvivesTheSecretMasker(t *testing.T) {
	ps, err := catalogScrubber()
	if err != nil {
		t.Fatal(err)
	}
	w := newWorld(t, "linux", "")
	w.s = ps
	w.creds = []model.Credential{w.file("aws", ".aws/credentials")}

	got := w.analyze()

	if len(got) != 1 || strings.Contains(got[0].Evidence.String(), "REDACTED") || !strings.Contains(got[0].Evidence.String(), "aws") {
		t.Errorf("findings = %+v, want the credential named, not masked", got)
	}
}
