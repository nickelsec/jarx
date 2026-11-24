package report

import (
	"strings"
	"testing"
	"time"

	"github.com/nickelsec/jarx/internal/model"
)

func TestTheScannedBlockCountsSessions(t *testing.T) {
	f := newScanFixture(t)
	v := f.view()
	v.HistoryFiles = 3
	v.Sessions = []model.Session{
		{Agent: model.AgentClaude, ID: f.text("a"), Last: time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)},
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
