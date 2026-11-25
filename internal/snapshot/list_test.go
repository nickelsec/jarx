package snapshot

import (
	"errors"
	"testing"
	"time"
)

func saveAt(t *testing.T, f fixture, taken time.Time) {
	t.Helper()
	if err := Save(f.dir(), Snapshot{Taken: taken}); err != nil {
		t.Fatal(err)
	}
}

func TestSavedSnapshotsAreListedNewestFirst(t *testing.T) {
	f := newFixture(t)
	start := time.Date(2026, 11, 25, 7, 0, 0, 0, time.UTC)
	for i := range 3 {
		saveAt(t, f, start.Add(time.Duration(i)*time.Hour))
	}

	got, err := List(f.dir())

	if err != nil || len(got) != 3 {
		t.Fatalf("List() = %+v, %v; want 3 snapshots", got, err)
	}
	for i, want := range []time.Time{start.Add(2 * time.Hour), start.Add(time.Hour), start} {
		if !got[i].Taken.Equal(want) || got[i].ID == "" {
			t.Errorf("snapshot %d = %+v, want one taken at %v", i, got[i], want)
		}
	}
}

func TestASnapshotLoadsByItsID(t *testing.T) {
	f := newFixture(t)
	taken := time.Date(2026, 11, 25, 7, 0, 0, 0, time.UTC)
	saveAt(t, f, taken)
	saveAt(t, f, taken.Add(time.Hour))
	list, _ := List(f.dir())

	got, err := Load(f.dir(), f.s, list[1].ID)

	if err != nil || !got.Taken.Equal(taken) {
		t.Errorf("Load(%q) = %v, %v; want the one taken at %v", list[1].ID, got.Taken, err, taken)
	}
}

func TestOnlyAListedSnapshotLoads(t *testing.T) {
	f := newFixture(t)
	saveAt(t, f, time.Date(2026, 11, 25, 7, 0, 0, 0, time.UTC))

	for _, id := range []string{"", "nope", "../config", "..\\config", "snapshots/x"} {
		if _, err := Load(f.dir(), f.s, id); !errors.Is(err, ErrNoSnapshot) {
			t.Errorf("Load(%q) err = %v, want ErrNoSnapshot", id, err)
		}
	}
}
