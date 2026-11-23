package report

import (
	"errors"
	"testing"
	"time"

	"github.com/nickelsec/jarx/internal/redact"
	"github.com/nickelsec/jarx/internal/snapshot"
)

func TestChangesWithNothingToCompare(t *testing.T) {
	for name, tc := range map[string]struct {
		note string
		want string
	}{
		"first scan":   {"", "changes: no earlier snapshot\n"},
		"bad snapshot": {"couldn't read the last snapshot", "changes: couldn't read the last snapshot\n"},
	} {
		p, _, out, _ := setup(t)

		p.Changes(time.Time{}, tc.note, nil, nil)

		if out.String() != tc.want {
			t.Errorf("%s: stdout = %q, want %q", name, out.String(), tc.want)
		}
	}
}

func TestNoChanges(t *testing.T) {
	p, _, out, _ := setup(t)

	p.Changes(time.Date(2026, 11, 23, 10, 4, 5, 0, time.UTC), "", nil, nil)

	if want := "changes since 2026-11-23 10:04:05 UTC: none\n"; out.String() != want {
		t.Errorf("stdout = %q, want %q", out.String(), want)
	}
}

func TestChangesAreGroupedByProject(t *testing.T) {
	p, s, out, _ := setup(t)
	text := func(raw string) redact.Text { v, _ := s.Scrub(raw); return v }
	app := text("/projects/app")

	p.Changes(time.Date(2026, 11, 23, 10, 4, 5, 0, time.UTC), "", []snapshot.Change{
		{Change: snapshot.Added, Item: snapshot.Item{Kind: snapshot.KindFinding, Key: text("JARX-PERMS-004 x")}},
		{Change: snapshot.Changed, Item: snapshot.Item{Project: app, Kind: snapshot.KindInstruction, Key: text("claude CLAUDE.md")}, What: text("content changed")},
		{Change: snapshot.Removed, Item: snapshot.Item{Project: app, Kind: snapshot.KindRule, Key: text("claude allow " + canary)}},
	}, nil)

	want := "changes since 2026-11-23 10:04:05 UTC (3)\n" +
		"  + finding  JARX-PERMS-004 x\n" +
		"  in /projects/app\n" +
		"    ~ instruction  claude CLAUDE.md: content changed\n" +
		"    - rule  claude allow REDACTED:test_token\n"
	if out.String() != want {
		t.Errorf("stdout =\n%s\nwant\n%s", out.String(), want)
	}
}

func TestAFailedSaveIsSaid(t *testing.T) {
	p, _, out, _ := setup(t)

	p.Changes(time.Time{}, "", nil, errors.New("disk full"))

	if want := "changes: no earlier snapshot\n  couldn't save this scan's snapshot: disk full\n"; out.String() != want {
		t.Errorf("stdout = %q, want %q", out.String(), want)
	}
}
