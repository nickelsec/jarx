package snapshot

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestNoRunsYet(t *testing.T) {
	log, note := Runs(newFixture(t).dir())

	if log.Total != 0 || len(log.Runs) != 0 || note != "" {
		t.Errorf("Runs() = %+v, %q; want an empty log and no note", log, note)
	}
}

func TestARunIsLoggedWithItsCounts(t *testing.T) {
	d := newFixture(t).dir()
	first := Run{Taken: time.Date(2026, 11, 25, 7, 14, 0, 0, time.UTC), Findings: 40, First: true}
	second := Run{Taken: time.Date(2026, 11, 25, 9, 0, 0, 0, time.UTC), Findings: 42, NewFindings: 3, Added: 5, Removed: 1, Changed: 2}

	for _, r := range []Run{first, second} {
		if err := AppendRun(d, r); err != nil {
			t.Fatal(err)
		}
	}
	log, note := Runs(d)

	if note != "" || log.Total != 2 || len(log.Runs) != 2 {
		t.Fatalf("Runs() = %+v, %q; want two runs", log, note)
	}
	if !log.Runs[0].Taken.Equal(second.Taken) || log.Runs[0] != (Run{Taken: log.Runs[0].Taken, Findings: 42, NewFindings: 3, Added: 5, Removed: 1, Changed: 2}) {
		t.Errorf("newest run = %+v, want %+v first", log.Runs[0], second)
	}
	if !log.Runs[1].First {
		t.Error("the first run isn't marked first")
	}
}

func TestTheLogKeepsTheNewestRunsButCountsThemAll(t *testing.T) {
	d := newFixture(t).dir()
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := range KeepRuns + 5 {
		if err := AppendRun(d, Run{Taken: start.Add(time.Duration(i) * time.Hour), Findings: i}); err != nil {
			t.Fatal(err)
		}
	}

	log, _ := Runs(d)

	if log.Total != KeepRuns+5 || len(log.Runs) != KeepRuns {
		t.Errorf("Total %d, kept %d; want %d and %d", log.Total, len(log.Runs), KeepRuns+5, KeepRuns)
	}
	if log.Runs[0].Findings != KeepRuns+4 {
		t.Errorf("newest kept run has %d findings, want %d", log.Runs[0].Findings, KeepRuns+4)
	}
}

func TestABadOrNewerRunLogIsANoteNotAnError(t *testing.T) {
	for name, tc := range map[string]struct{ body, note string }{
		"broken": {"{not json", "couldn't read"},
		"newer":  {fmt.Sprintf(`{"version": %d, "total": 3, "runs": []}`, Version+1), "newer jarx"},
	} {
		d := newFixture(t).dir()
		if err := d.WriteFile(RunsFile, []byte(tc.body)); err != nil {
			t.Fatal(err)
		}

		log, note := Runs(d)

		if log.Total != 0 || len(log.Runs) != 0 || !strings.Contains(note, tc.note) {
			t.Errorf("%s: Runs() = %+v, %q; want an empty log and a note about %q", name, log, note, tc.note)
		}
		if err := AppendRun(d, Run{Taken: time.Now()}); err != nil {
			t.Errorf("%s: a bad log stops the next run being logged: %v", name, err)
		}
	}
}
