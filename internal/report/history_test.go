package report

import (
	"strings"
	"testing"
	"time"

	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/redact"
)

func TestTheScannedBlockCountsSessions(t *testing.T) {
	f := newScanFixture(t)
	v := f.view()
	v.HistoryFiles = 3
	v.Sessions = []model.Session{
		{Agent: model.AgentClaude, ID: f.text("a"), LastUnix: time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC).Unix()},
		{Agent: model.AgentClaude, ID: f.text("b")},
	}

	out := render(Style{Width: 120}, v)

	if want := "2 sessions - 3 history files"; !strings.Contains(out, want) {
		t.Errorf("output =\n%s\nwant %q", out, want)
	}
	if want := "1 undated - observed, not documented"; !strings.Contains(out, want) {
		t.Errorf("output =\n%s\nwant the note %q", out, want)
	}
}

func TestNoHistoryMeansNoSessionsRow(t *testing.T) {
	f := newScanFixture(t)

	if out := render(Style{Width: 120}, f.view()); strings.Contains(out, "session") {
		t.Errorf("output =\n%s\nwant no sessions row without history", out)
	}
}

func TestAnObservedVerdictSitsNextToTheConfiguredOne(t *testing.T) {
	f := newScanFixture(t)
	v := f.view()
	v.All = true
	v.Projects[0].Reach = []model.Reach{{
		Agent: model.AgentClaude, Kind: "aws", Path: f.path(".aws/credentials"), Channel: model.ChannelFileTools,
		Verdict: model.ReachApproval, Why: []redact.Text{f.text("it's outside the working dirs, where Read asks")},
		Observed: model.ReachEffective, ObservedWhy: f.text("3 of 4 sessions in bypassPermissions"),
	}}

	out := render(Style{Width: 200}, v)

	want := "        file tools  needs approval (effectively readable: 3 of 4 sessions in bypassPermissions): it's outside the working dirs, where Read asks\n"
	if !strings.Contains(out, want) {
		t.Errorf("output =\n%s\nwant %q", out, want)
	}
}

func TestEachProjectSaysWhatItsSessionsRanIn(t *testing.T) {
	f := newScanFixture(t)
	v := f.view()
	recent := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC).Unix()
	v.Projects[0].Sessions = []model.Session{
		{Agent: model.AgentClaude, LastUnix: recent, Modes: []redact.Text{f.text("default"), f.text("bypassPermissions")}},
		{Agent: model.AgentClaude, LastUnix: recent, Modes: []redact.Text{f.text("default")}},
		{Agent: model.AgentClaude, Modes: []redact.Text{f.text("auto")}},
		{Agent: model.AgentCodex, LastUnix: recent, Modes: []redact.Text{f.text("approval_policy=never"), f.text("sandbox=danger-full-access")}},
	}

	out := render(Style{Width: 160}, v)

	// The same list style as the other project lines (talks to, credentials).
	want := `\- sessions: claude 3 - 1 in bypassPermissions - 1 in auto - 1 undated - codex 1 - 1 with approval_policy=never` + "\n"
	if !strings.Contains(out, want) {
		t.Errorf("output =\n%s\nwant %q", out, want)
	}
}
