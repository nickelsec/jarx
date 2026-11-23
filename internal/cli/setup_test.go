package cli

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// savedRepos reads the repos straight out of the fake home's config file.
func savedRepos(t *testing.T, home string) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(home, ".jarx-state", "config.json")) //nolint:gosec // G304: test temp path
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Repos []string `json:"repos"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg.Repos
}

func workDir(t *testing.T, home string) string {
	t.Helper()
	dir := filepath.Join(home, "work")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestSetupWithNothingSaved(t *testing.T) {
	home := fakeHome(t, "")

	got := run("setup", "--home", home)

	if got.code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr %q)", got.code, got.stderr)
	}
	for _, want := range []string{
		"state dir    " + filepath.Join(home, ".jarx-state") + "  (not created yet)",
		"repos (0)\n",
		"llm          not set up\n",
	} {
		if !strings.Contains(got.stdout, want) {
			t.Errorf("stdout = %q, want it to contain %q", got.stdout, want)
		}
	}
	if _, err := os.Stat(filepath.Join(home, ".jarx-state")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("setup with nothing to save created the state dir (err %v)", err)
	}
}

func TestSetupRepoAddSavesItAndScanFindsIt(t *testing.T) {
	home := fakeHome(t, "")
	dir := workDir(t, home)

	got := run("setup", "--home", home, "repo", "add", dir)

	if got.code != 0 || got.stdout != "added "+dir+"\n" {
		t.Fatalf("repo add = %d, %q (stderr %q); want added", got.code, got.stdout, got.stderr)
	}
	if repos := savedRepos(t, home); !slices.Equal(repos, []string{dir}) {
		t.Errorf("saved repos = %q, want just %s", repos, dir)
	}
	if got := run("setup", "--home", home); !strings.Contains(got.stdout, "repos (1)\n  "+dir+"  (exists)\n") {
		t.Errorf("setup = %q, want the repo listed", got.stdout)
	}
	// The full inventory lists it, from ~ when it's in the home dir.
	shown := dir
	if rel, err := filepath.Rel(home, dir); err == nil && filepath.IsLocal(rel) {
		shown = "~" + string(filepath.Separator) + rel
	}
	t.Setenv("COLUMNS", "400") // a long temp path, read in full
	if got := run("scan", "--all", "--home", home); !strings.Contains(got.stdout, "  "+shown+"  jarx  0 files (walk)\n") {
		t.Errorf("scan = %q, want the saved repo listed as from jarx", got.stdout)
	}
}

func TestSetupRepoAddMakesARelativePathAbsolute(t *testing.T) {
	home := fakeHome(t, "")
	dir := workDir(t, home)
	t.Chdir(home)

	got := run("setup", "--home", home, "repo", "add", "work")

	if got.code != 0 || !slices.Equal(savedRepos(t, home), []string{dir}) {
		t.Errorf("repo add work = %d (stderr %q), saved %q; want %s", got.code, got.stderr, savedRepos(t, home), dir)
	}
}

func TestSetupRepoAddTwiceIsANoOp(t *testing.T) {
	home := fakeHome(t, "")
	dir := workDir(t, home)
	run("setup", "--home", home, "repo", "add", dir)
	again := dir + string(filepath.Separator)
	if runtime.GOOS == "windows" {
		again = strings.ToUpper(dir) // Windows paths ignore case
	}

	got := run("setup", "--home", home, "repo", "add", again)

	if got.code != 0 || !strings.Contains(got.stdout, "already saved") {
		t.Errorf("second add = %d, %q; want already saved", got.code, got.stdout)
	}
	if repos := savedRepos(t, home); len(repos) != 1 {
		t.Errorf("saved repos = %q, want one", repos)
	}
}

func TestSetupRepoAddRefusesWhatItCantUse(t *testing.T) {
	home := fakeHome(t, "")
	file := filepath.Join(home, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{
		filepath.Join(home, "nope"): "doesn't exist",
		file:                        "isn't a directory",
		t.TempDir():                 "outside the fake home",
	} {
		got := run("setup", "--home", home, "repo", "add", path)

		if got.code != 1 || !strings.Contains(got.stderr, want) {
			t.Errorf("repo add %s = %d, %q; want exit 1 with %q", path, got.code, got.stderr, want)
		}
	}
	if _, err := os.Stat(filepath.Join(home, ".jarx-state")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a refused add created the state dir (err %v)", err)
	}
}

func TestSetupRepoRm(t *testing.T) {
	home := fakeHome(t, "")
	dir := workDir(t, home)
	run("setup", "--home", home, "repo", "add", dir)

	got := run("setup", "--home", home, "repo", "rm", dir)

	if got.code != 0 || got.stdout != "removed "+dir+"\n" {
		t.Errorf("repo rm = %d, %q (stderr %q); want removed", got.code, got.stdout, got.stderr)
	}
	if repos := savedRepos(t, home); len(repos) != 0 {
		t.Errorf("saved repos = %q, want none", repos)
	}
	if got := run("setup", "--home", home, "repo", "rm", dir); got.code != 1 || !strings.Contains(got.stderr, "isn't saved") {
		t.Errorf("rm of an unsaved path = %d, %q; want exit 1, isn't saved", got.code, got.stderr)
	}
}

func TestSetupUsageErrors(t *testing.T) {
	home := fakeHome(t, "")
	for name, args := range map[string][]string{
		"no verb":       {"repo"},
		"unknown verb":  {"repo", "move", "x"},
		"no path":       {"repo", "add"},
		"two paths":     {"repo", "add", "a", "b"},
		"unknown topic": {"bogus"},
	} {
		got := run(append([]string{"setup", "--home", home}, args...)...)

		if got.code != 2 || !strings.Contains(got.stderr, "usage: jarx setup") {
			t.Errorf("%s: exit %d, stderr %q; want 2 with setup usage", name, got.code, got.stderr)
		}
	}
	if got := run("setup", "-h"); got.code != 0 || !strings.Contains(got.stdout, "usage: jarx setup") {
		t.Errorf("setup -h = %d, %q; want 0 with usage", got.code, got.stdout)
	}
}

func TestBrokenConfigStopsSetupAndScan(t *testing.T) {
	home := fakeHome(t, "")
	state := filepath.Join(home, ".jarx-state")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	const secret = "hunter2-plain-secret-no-pattern"
	if err := os.WriteFile(filepath.Join(state, "config.json"), []byte(`{"repos": ["`+secret), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, cmd := range []string{"setup", "scan"} {
		got := run(cmd, "--home", home)

		if got.code != 1 || !strings.Contains(got.stderr, "isn't valid JSON") {
			t.Errorf("%s = %d, %q; want exit 1 naming the bad config", cmd, got.code, got.stderr)
		}
		if strings.Contains(got.stdout+got.stderr, secret) {
			t.Errorf("%s leaks the config's content", cmd)
		}
	}
}
