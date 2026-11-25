package cli

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/nickelsec/jarx/internal/llm"
	"github.com/nickelsec/jarx/internal/snapshot"
	"github.com/nickelsec/jarx/internal/ui"
)

// testApp starts the dashboard's app on a copy of the demo home, the way
// jarx ui does, without the server.
func testApp(t *testing.T, home string) *uiApp {
	t.Helper()
	p := testPrinter()
	ss, ok := openScan(p, scanFlags{home: home}, streams{})
	if !ok {
		t.Fatal("openScan failed")
	}
	t.Cleanup(func() { _ = ss.files.Close() })
	a, err := newUIApp(p, ss, streams{})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestRescanScansAgainAndSwapsTheResultIn(t *testing.T) {
	a := testApp(t, demoCopy(t))
	before := a.Data()

	if err := a.Rescan(); err != nil {
		t.Fatal(err)
	}
	state := waitForScan(t, a)

	after := a.Data()
	if state.Done != 1 || state.Failed {
		t.Errorf("scan state %+v, want one done and not failed", state)
	}
	if before.History.Total != 1 || after.History.Total != 2 || !after.Scanned.After(before.Scanned) {
		t.Errorf("scans logged %d then %d, scanned %v then %v; want a second scan swapped in", before.History.Total, after.History.Total, before.Scanned, after.Scanned)
	}
}

// waitForScan waits for a rescan in the background to finish.
func waitForScan(t *testing.T, a *uiApp) ui.ScanState {
	t.Helper()
	deadline := time.Now().Add(time.Minute)
	for time.Now().Before(deadline) {
		if s := a.ScanState(); !s.Running {
			return s
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the rescan didn't finish")
	return ui.ScanState{}
}

func TestARescanRunsInTheBackground(t *testing.T) {
	a := testApp(t, demoCopy(t))
	a.scanning.Lock() // hold the scan at the start, like a slow one

	if err := a.Rescan(); err != nil {
		t.Fatal(err)
	}

	if !a.ScanState().Running {
		t.Error("Rescan() waited for the scan instead of starting it")
	}
	a.scanning.Unlock()
	waitForScan(t, a)
}

func TestFoldersListsSubfoldersInTheFakeHome(t *testing.T) {
	home := demoCopy(t)
	a := testApp(t, home)
	file := filepath.Join(home, "notes.txt")
	if err := os.WriteFile(file, []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}

	root, err := a.Folders("~")
	if err != nil || root.Parent != "" || !subsAre(root, []string{"projects"}, []string{".claude", "notes.txt"}) {
		t.Errorf("Folders(~) = %+v, %v; want projects, no dot-folders or files, and no way up out of the fake home", root, err)
	}
	projects, err := a.Folders("~/projects")
	if err != nil || projects.Parent == "" || !subsAre(projects, []string{"app", "tools"}, nil) {
		t.Errorf("Folders(~/projects) = %+v, %v; want app and tools, and a way up", projects, err)
	}
}

func TestFoldersRefuseWhatItCantList(t *testing.T) {
	home := demoCopy(t)
	a := testApp(t, home)
	file := filepath.Join(home, "notes.txt")
	if err := os.WriteFile(file, []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}

	for dir, want := range map[string]error{t.TempDir(): ui.ErrRepoOutside, file: ui.ErrRepoNotDir, "~/nope": ui.ErrRepoMissing, "rel": ui.ErrRepoRelative} {
		if _, err := a.Folders(dir); !errors.Is(err, want) {
			t.Errorf("Folders(%q) = %v, want %v", dir, err, want)
		}
	}
}

// subsAre says whether f lists every name in in, and none in out.
func subsAre(f ui.Folder, in, out []string) bool {
	for _, n := range in {
		if !hasSub(f, n) {
			return false
		}
	}
	for _, n := range out {
		if hasSub(f, n) {
			return false
		}
	}
	return true
}

func hasSub(f ui.Folder, name string) bool {
	for _, s := range f.Subs {
		if s.Name == name {
			return true
		}
	}
	return false
}

func TestAComparisonIsWorkedOutOnce(t *testing.T) {
	home := demoCopy(t)
	run("scan", "--home", home)
	a := testApp(t, home)
	id := a.Data().Snapshots[0].ID

	_, first, err := a.ChangesSince(id)
	if err != nil {
		t.Fatal(err)
	}
	_, again, _ := a.ChangesSince(id)

	if len(a.since) != 1 || len(first) != len(again) {
		t.Errorf("cached %d comparisons, %d then %d changes; want one, the same both times", len(a.since), len(first), len(again))
	}
}

func TestARescanReportsItsSteps(t *testing.T) {
	a := testApp(t, demoCopy(t))
	a.scanning.Lock() // hold the scan, so the steps can be checked
	if err := a.Rescan(); err != nil {
		t.Fatal(err)
	}

	a.quiet.Watch("walking projects", 2, 5)

	st := a.ScanState()
	a.scanning.Unlock()
	if !slices.Equal(st.Steps, scanSteps) || st.Step != "walking projects" || st.StepDone != 2 || st.StepTotal != 5 {
		t.Errorf("scan state %+v, want the scan's steps and where it is", st)
	}
	if done := waitForScan(t, a); done.Step != "" || len(done.Steps) != 0 {
		t.Errorf("after the scan, state %+v, want no steps left", done)
	}
}

func TestOneRescanAtATime(t *testing.T) {
	a := testApp(t, demoCopy(t))
	a.scanning.Lock() // hold the first scan
	if err := a.Rescan(); err != nil {
		t.Fatal(err)
	}

	err := a.Rescan()

	a.scanning.Unlock()
	waitForScan(t, a)
	if !errors.Is(err, ui.ErrBusy) {
		t.Errorf("Rescan() while one runs = %v, want ErrBusy", err)
	}
}

func TestARepoIsSavedFromTheDashboard(t *testing.T) {
	home := demoCopy(t)
	a := testApp(t, home)
	work := filepath.Join(home, "work", "api")
	if err := os.MkdirAll(work, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := a.AddRepo("~/work/api"); err != nil {
		t.Fatalf("AddRepo(~/work/api) = %v", err)
	}

	if got := savedRepos(t, home); len(got) != 1 || !samePath(got[0], work, a.ss.env.GOOS) || len(a.Data().Repos) != 1 {
		t.Fatalf("saved %q and shows %d, want %s saved and shown", got, len(a.Data().Repos), work)
	}
	if err := a.AddRepo(work); !errors.Is(err, ui.ErrRepoSaved) {
		t.Errorf("adding it again = %v, want ErrRepoSaved", err)
	}
}

func TestARepoIsDroppedFromTheDashboard(t *testing.T) {
	home := demoCopy(t)
	a := testApp(t, home)
	if err := os.MkdirAll(filepath.Join(home, "work"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := a.AddRepo("~/work"); err != nil {
		t.Fatal(err)
	}

	if err := a.RemoveRepo(0); err != nil || len(savedRepos(t, home)) != 0 || len(a.Data().Repos) != 0 {
		t.Errorf("RemoveRepo(0) = %v, left %q saved", err, savedRepos(t, home))
	}
	if err := a.RemoveRepo(3); !errors.Is(err, ui.ErrRepoNotSaved) {
		t.Errorf("RemoveRepo(3) = %v, want ErrRepoNotSaved", err)
	}
}

func TestARepoThatWontDoIsRefused(t *testing.T) {
	home := demoCopy(t)
	a := testApp(t, home)
	file := filepath.Join(home, "notes.txt")
	if err := os.WriteFile(file, []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()

	for path, want := range map[string]error{
		"work/api":   ui.ErrRepoRelative,
		"":           ui.ErrRepoRelative,
		"~/nope":     ui.ErrRepoMissing,
		file:         ui.ErrRepoNotDir,
		outside:      ui.ErrRepoOutside,
		"~/../../..": ui.ErrRepoOutside,
	} {
		if err := a.AddRepo(path); !errors.Is(err, want) {
			t.Errorf("AddRepo(%q) = %v, want %v", path, err, want)
		}
	}
	if got := savedRepos(t, home); len(got) != 0 {
		t.Errorf("refused repos got saved: %q", got)
	}
}

func TestChangesCompareWithAnOlderSnapshot(t *testing.T) {
	home := demoCopy(t)
	run("scan", "--home", home)
	a := testApp(t, home)

	d := a.Data()
	if len(d.Snapshots) != 1 {
		t.Fatalf("%d older snapshots to pick, want the one scan before", len(d.Snapshots))
	}
	since, _, err := a.ChangesSince(d.Snapshots[0].ID)
	if err != nil || !since.Equal(d.Snapshots[0].Taken) {
		t.Errorf("ChangesSince = %v, %v; want the older scan's time", since, err)
	}
	if _, _, err := a.ChangesSince("nope"); !errors.Is(err, snapshot.ErrNoSnapshot) {
		t.Errorf("ChangesSince(nope) = %v, want ErrNoSnapshot", err)
	}
}

func TestTheDashboardShowsCachedLLMFindingsWithoutSending(t *testing.T) {
	f := &reviewer{}
	demo := llmDemo(t, f.serve(t))
	if got := withKey().ask("y\n", "scan", "--llm", "--home", demo); got.code != 0 {
		t.Fatalf("scan --llm = %d, %q", got.code, got.stderr)
	}
	sent := f.count()

	a := testApp(t, demo)

	if f.count() != sent {
		t.Errorf("the dashboard sent %d requests, want none", f.count()-sent)
	}
	n := 0
	for _, fd := range a.Data().Scan.Findings {
		if fd.RuleID == llm.RuleHigh().ID {
			n++
		}
	}
	if n == 0 {
		t.Error("the dashboard doesn't show the findings the last review cached")
	}
}
