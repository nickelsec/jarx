package reach

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nickelsec/jarx/internal/credmeta"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/redact"
)

// now is the window's end in these tests.
const nowUnix = 1795521600 // 2026-11-24 12:00 UTC

func testNow() time.Time { return time.Unix(nowUnix, 0).UTC() }

// session adds one of the agent's sessions to the project, daysAgo before
// now (negative for undated), that ran in modes.
func (w *world) session(a model.Agent, daysAgo int, modes ...string) *world {
	s := model.Session{Agent: a, ID: w.text("s"), CWD: w.proj.Path}
	if daysAgo >= 0 {
		s.LastUnix = testNow().AddDate(0, 0, -daysAgo).Unix()
	}
	for _, m := range modes {
		s.Modes = append(s.Modes, w.text(m))
	}
	w.proj.Sessions = append(w.proj.Sessions, s)
	return w
}

// observed is the file tools verdict on the AWS file after Observe.
func (w *world) observed() model.Reach {
	w.t.Helper()
	ps := w.settle()
	Observe(w.s, ps, testNow())
	for _, r := range ps[0].Reach {
		if r.Agent == model.AgentClaude && r.Channel == model.ChannelFileTools && r.Path.Raw() == w.home(awsCreds) {
			return r
		}
	}
	w.t.Fatal("no file tools verdict for the AWS file")
	return model.Reach{}
}

func TestMostSessionsInBypassMakeApprovalEffectivelyReadable(t *testing.T) {
	w := newWorld(t, "linux", "")
	w.session(model.AgentClaude, 1, "bypassPermissions").
		session(model.AgentClaude, 2, "default", "bypassPermissions").
		session(model.AgentClaude, -1, "auto").
		session(model.AgentClaude, 3, "default")

	r := w.observed()

	if r.Verdict != model.ReachApproval {
		t.Errorf("verdict = %s, want the configured needs approval kept", r.Verdict)
	}
	if r.Observed != model.ReachEffective || r.ObservedWhy.String() != "3 of 4 sessions in auto or bypassPermissions, 1 undated" {
		t.Errorf("observed = %s (%q), want effectively readable, 3 of 4 sessions in auto or bypassPermissions, 1 undated", r.Observed, r.ObservedWhy)
	}
}

func TestHalfIsntMoreThanHalf(t *testing.T) {
	w := newWorld(t, "linux", "")
	w.session(model.AgentClaude, 1, "bypassPermissions").session(model.AgentClaude, 2, "default")

	if r := w.observed(); r.Observed != "" {
		t.Errorf("observed = %s (%q), want nothing: 1 of 2 isn't more than half", r.Observed, r.ObservedWhy)
	}
}

func TestOldSessionsDontCount(t *testing.T) {
	w := newWorld(t, "linux", "")
	w.session(model.AgentClaude, 40, "bypassPermissions").
		session(model.AgentClaude, 31, "bypassPermissions").
		session(model.AgentClaude, 1, "default")

	if r := w.observed(); r.Observed != "" {
		t.Errorf("observed = %s (%q), want nothing: only the last 30 days count", r.Observed, r.ObservedWhy)
	}
}

func TestAcceptEditsNeverCountsForReading(t *testing.T) {
	w := newWorld(t, "linux", "")
	w.session(model.AgentClaude, 1, "acceptEdits").session(model.AgentClaude, 2, "acceptEdits")

	if r := w.observed(); r.Observed != "" {
		t.Errorf("observed = %s, want nothing: acceptEdits only approves edits", r.Observed)
	}
}

func TestOnlyApprovalVerdictsChange(t *testing.T) {
	w := newWorld(t, "linux", "")
	w.rule(model.RuleDeny, "Read(~/.aws/**)")
	w.session(model.AgentClaude, 1, "bypassPermissions")

	if r := w.observed(); r.Verdict != model.ReachBlocked || r.Observed != "" {
		t.Errorf("verdict = %s, observed %s; want a block to stay a block", r.Verdict, r.Observed)
	}
}

func TestAnotherAgentsSessionsDontCount(t *testing.T) {
	w := newWorld(t, "linux", "")
	w.session(model.AgentCodex, 1, "approval_policy=never").session(model.AgentCodex, 2, "approval_policy=never")

	if r := w.observed(); r.Observed != "" {
		t.Errorf("observed = %s, want nothing: those were Codex's sessions", r.Observed)
	}
}

func TestCodexNeverAndAutoReviewCount(t *testing.T) {
	for name, tc := range map[string]struct {
		modes []string
		want  model.ReachVerdict
		why   string
	}{
		"never":       {[]string{"approval_policy=never"}, model.ReachEffective, "2 of 2 sessions with approval_policy=never"},
		"auto review": {[]string{"approval_policy=on-request", "approvals_reviewer=auto_review"}, model.ReachEffective, "2 of 2 sessions with approvals_reviewer=auto_review"},
		"granular":    {[]string{"approval_policy=granular"}, "", ""},
		"on request":  {[]string{"approval_policy=on-request", "approvals_reviewer=user"}, "", ""},
	} {
		t.Run(name, func(t *testing.T) {
			w := codexWorld(t, "")
			// A profile that doesn't grant ~/.aws: Codex has to ask.
			w.codexOption("default_permissions", "tight").profileRule(":minimal", model.RuleRead)
			w.session(model.AgentCodex, 1, tc.modes...).session(model.AgentCodex, 2, tc.modes...)
			ps := w.settle()
			Observe(w.s, ps, testNow())
			var got []string
			for _, r := range ps[0].Reach {
				if r.Agent == model.AgentCodex && r.Verdict == model.ReachApproval {
					got = append(got, string(r.Observed)+"|"+r.ObservedWhy.String())
				}
			}
			if len(got) == 0 {
				t.Fatal("no Codex verdict needs approval here")
			}
			if want := string(tc.want) + "|" + tc.why; !slices.Contains(got, want) || slices.ContainsFunc(got, func(g string) bool { return g != want }) {
				t.Errorf("observed = %q, want all %q", got, want)
			}
		})
	}
}

func TestASecretInASessionIsOneTheAgentSees(t *testing.T) {
	w := newWorld(t, "linux", "")
	w.session(model.AgentClaude, 1)
	transcript := w.home(".claude/projects/p/s1.jsonl")
	w.proj.Sessions[0].File = model.NewPath(w.s, transcript)
	w.proj.Sessions[0].Secrets = []redact.Text{w.text("github_pat, fingerprint 0123456789ab")}

	var seen []model.Exposure
	for _, e := range w.settle()[0].Exposure {
		if slices.Contains(e.States, model.StateSees) {
			seen = append(seen, e)
		}
	}
	if len(seen) != 1 || seen[0].Kind != credmeta.KindSecretInHistory || seen[0].Path.Raw() != transcript ||
		!strings.Contains(seen[0].Via[0].String(), "github_pat") {
		t.Errorf("sees = %+v, want the transcript's github_pat", seen)
	}
}

func TestOnlyTheAgentsOwnSessionsAreCounted(t *testing.T) {
	// Codex's sessions in the same dir don't dilute Claude's: this is 1 of
	// 1 Claude session, not 1 of 3.
	w := newWorld(t, "linux", "")
	w.session(model.AgentClaude, 1, "bypassPermissions").
		session(model.AgentCodex, 1, "approval_policy=on-request").
		session(model.AgentCodex, 2, "approval_policy=on-request")

	if r := w.observed(); r.Observed != model.ReachEffective || r.ObservedWhy.String() != "1 of 1 sessions in bypassPermissions" {
		t.Errorf("observed = %s (%q), want effectively readable, 1 of 1 sessions in bypassPermissions", r.Observed, r.ObservedWhy)
	}
}

func TestAnotherAgentsSessionSecretIsntSeenByThisOne(t *testing.T) {
	w := newWorld(t, "linux", "")
	w.session(model.AgentCodex, 1)
	w.proj.Sessions[0].File = model.NewPath(w.s, w.home(".codex/sessions/r.jsonl"))
	w.proj.Sessions[0].Secrets = []redact.Text{w.text("github_pat, fingerprint 0123456789ab")}

	for _, e := range w.settle()[0].Exposure {
		if e.Agent == model.AgentClaude && e.Kind == credmeta.KindSecretInHistory {
			t.Errorf("claude sees %s, want nothing: it was Codex's session", e.Path.Raw())
		}
	}
}
