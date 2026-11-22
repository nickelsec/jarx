package discover

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/nickelsec/jarx/internal/agent"
	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/fsys"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/platform"
)

// realContext is the real machine's env, used only to find git on PATH.
// Every repo these tests touch is a throwaway one in t.TempDir().
func realContext(t *testing.T) agent.Context {
	t.Helper()
	env, err := platform.Real()
	if err != nil {
		t.Fatal(err)
	}
	f, err := fsys.New(env)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return agent.Context{Env: env, Files: f, Scrub: fakeContext(t).Scrub}
}

// git runs a setup command with the same scrubbed env the walk uses, so the
// developer's own git config never affects a test. git is required: these
// tests fail rather than skip without it.
func git(t *testing.T, c agent.Context, dir string, args ...string) {
	t.Helper()
	bin, ok := findGit(c)
	if !ok {
		t.Fatal("git not found on PATH; these tests need it")
	}
	cmd := exec.CommandContext(t.Context(), bin, args...) //nolint:gosec // G204: test setup on throwaway repos
	cmd.Dir = dir
	cmd.Env = gitEnv(c, dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	// 0700 because the hook fixture has to be executable.
	if err := os.WriteFile(path, []byte(content), 0o700); err != nil { //nolint:gosec // G306: see above
		t.Fatal(err)
	}
}

func newRepo(t *testing.T, c agent.Context) string {
	t.Helper()
	repo := filepath.Join(t.TempDir(), "repo")
	if err := os.Mkdir(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	git(t, c, repo, "init", "-q", ".")
	return repo
}

func sorted(files []string) []string {
	out := slices.Clone(files)
	slices.Sort(out)
	return out
}

func TestGitWalkListsTrackedAndUntrackedButNotIgnored(t *testing.T) {
	c := realContext(t)
	repo := newRepo(t, c)
	write(t, filepath.Join(repo, "a.go"), "a")
	write(t, filepath.Join(repo, "b.go"), "b")
	write(t, filepath.Join(repo, ".gitignore"), "*.log\n")
	write(t, filepath.Join(repo, "c.log"), "ignored")
	write(t, filepath.Join(repo, "node_modules", "pkg", "index.js"), "skip me")
	write(t, filepath.Join(repo, "node_modules", "pkg", "CLAUDE.md"), "keep me")
	git(t, c, repo, "add", "a.go")

	w := walkRepo(t.Context(), c, repo, maxFiles)

	if w.method != model.WalkGit {
		t.Fatalf("method = %q, want git", w.method)
	}
	want := []string{".gitignore", "a.go", "b.go", "node_modules/pkg/CLAUDE.md"}
	if got := sorted(w.files); !slices.Equal(got, want) {
		t.Errorf("files = %q, want %q", got, want)
	}
}

// markerCmd is a shell command git would run, which writes a marker file.
func markerCmd(dir, name string) string {
	return "echo ran > '" + filepath.ToSlash(filepath.Join(dir, name)) + "'"
}

func TestGitWalkNeverRunsCommandsFromTheReposConfig(t *testing.T) {
	c := realContext(t)
	repo := newRepo(t, c)
	marks := t.TempDir()
	hooks := t.TempDir()
	write(t, filepath.Join(hooks, "post-index-change"), "#!/bin/sh\n"+markerCmd(marks, "hook")+"\n")
	write(t, filepath.Join(repo, "a.go"), "a")
	write(t, filepath.Join(repo, ".gitattributes"), "* filter=evil diff=evil\n")
	git(t, c, repo, "add", "a.go")
	// Every key a hostile repo could use to run something. A plain ls-files
	// runs core.fsmonitor for real; the rest are defense in depth.
	for _, kv := range [][2]string{
		{"core.fsmonitor", markerCmd(marks, "fsmonitor") + " #"},
		{"core.pager", markerCmd(marks, "pager") + "; cat"},
		{"pager.ls-files", markerCmd(marks, "pager-ls-files") + "; cat"},
		{"core.hooksPath", filepath.ToSlash(hooks)},
		{"core.untrackedCache", "true"},
		{"filter.evil.clean", markerCmd(marks, "filter-clean") + "; cat"},
		{"filter.evil.process", markerCmd(marks, "filter-process")},
		{"diff.evil.textconv", markerCmd(marks, "textconv") + "; cat"},
		{"diff.external", markerCmd(marks, "diff-external")},
	} {
		git(t, c, repo, "config", kv[0], kv[1])
	}

	w := walkRepo(t.Context(), c, repo, maxFiles)

	if w.method != model.WalkGit {
		t.Fatalf("method = %q, want git (the repo is valid)", w.method)
	}
	entries, err := os.ReadDir(marks)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		t.Errorf("git ran a command from the repo's config: marker %q was written", e.Name())
	}
}

func TestGitWalkIgnoresCoreWorktree(t *testing.T) {
	c := realContext(t)
	repo := newRepo(t, c)
	elsewhere := t.TempDir()
	write(t, filepath.Join(elsewhere, "elsewhere.txt"), "outside the repo")
	write(t, filepath.Join(repo, "a.go"), "a")
	git(t, c, repo, "config", "core.worktree", filepath.ToSlash(elsewhere))

	w := walkRepo(t.Context(), c, repo, maxFiles)

	if slices.Contains(w.files, "elsewhere.txt") {
		t.Errorf("files = %q: core.worktree made git list another dir", w.files)
	}
	if !slices.Contains(w.files, "a.go") {
		t.Errorf("files = %q, want the repo's own a.go", w.files)
	}
}

func TestImplicitBareRepoFallsBackToTheWalk(t *testing.T) {
	c := realContext(t)
	bare := filepath.Join(t.TempDir(), "bare")
	if err := os.Mkdir(bare, 0o700); err != nil {
		t.Fatal(err)
	}
	git(t, c, bare, "init", "-q", "--bare", ".")

	w := walkRepo(t.Context(), c, bare, maxFiles)

	if w.method != model.WalkFallback {
		t.Errorf("method = %q, want walk: git must not treat the dir itself as a git dir", w.method)
	}
}

func TestDirInsideAnotherRepoFallsBackToTheWalk(t *testing.T) {
	c := realContext(t)
	repo := newRepo(t, c)
	write(t, filepath.Join(repo, "top.go"), "parent's file")
	sub := filepath.Join(repo, "sub")
	write(t, filepath.Join(sub, "own.go"), "sub's file")
	git(t, c, repo, "add", ".")

	w := walkRepo(t.Context(), c, sub, maxFiles)

	if w.method != model.WalkFallback {
		t.Errorf("method = %q, want walk: git must not climb into the parent repo", w.method)
	}
	if !slices.Equal(sorted(w.files), []string{"own.go"}) {
		t.Errorf("files = %q, want just sub's own file", w.files)
	}
}

func TestNoGitOnPathFallsBackToTheWalk(t *testing.T) {
	c := fakeContext(t) // fake home with no PATH
	write(t, filepath.Join(c.Env.Home, "repo", "a.go"), "a")

	w := walkRepo(t.Context(), c, filepath.Join(c.Env.Home, "repo"), maxFiles)

	if w.method != model.WalkFallback || !slices.Equal(w.files, []string{"a.go"}) {
		t.Errorf("walk = %+v, want the fallback walk with a.go", w)
	}
}

func TestFakeHomeNeverRunsGit(t *testing.T) {
	home := t.TempDir()
	// A git binary inside the fake home, on the fake PATH. fsys can see it,
	// so only the "never under --home" rule keeps it from running.
	bin := filepath.Join(home, "bin")
	write(t, filepath.Join(bin, "git"), "#!/bin/sh\n")
	write(t, filepath.Join(bin, "git.exe"), "fake")
	write(t, filepath.Join(home, ".jarx-env"), "PATH="+bin+"\n")
	env, err := platform.FromHome(home)
	if err != nil {
		t.Fatal(err)
	}
	f, err := fsys.New(env)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	c := agent.Context{Env: env, Files: f, Scrub: fakeContext(t).Scrub}

	if bin, ok := findGit(c); ok {
		t.Errorf("findGit() = %q under --home, want no git", bin)
	}
}

func TestWalkStopsAtTheLimitAndSaysSo(t *testing.T) {
	c := fakeContext(t)
	repo := filepath.Join(c.Env.Home, "repo")
	for _, n := range []string{"a", "b", "c", "d", "e"} {
		write(t, filepath.Join(repo, n+".txt"), n)
	}

	w := walkRepo(t.Context(), c, repo, 3)

	if len(w.files) != 3 || !w.truncated {
		t.Errorf("walk = %d files, truncated %v; want 3 and truncated", len(w.files), w.truncated)
	}
}

func TestParseLsFilesRejectsPathsOutsideTheRepo(t *testing.T) {
	for name, out := range map[string]string{
		"parent":   "a.go\x00../escape.txt\x00",
		"absolute": "a.go\x00/etc/passwd\x00",
		"windows":  "a.go\x00C:/Windows/win.ini\x00",
		"empty":    "a.go\x00\x00b.go\x00",
	} {
		if _, err := parseLsFiles([]byte(out)); err == nil {
			t.Errorf("%s: parseLsFiles() error = nil, want an error", name)
		}
	}
	got, err := parseLsFiles([]byte("a.go\x00dir/b.go\x00"))
	if err != nil || !slices.Equal(got, []string{"a.go", "dir/b.go"}) {
		t.Errorf("parseLsFiles() = %q, %v; want both files", got, err)
	}
}

func TestGitEnvIsBuiltFromScratch(t *testing.T) {
	c := realContext(t)
	repo := t.TempDir()

	env := gitEnv(c, repo)

	allowed := []string{
		"PATH", "GIT_OPTIONAL_LOCKS", "GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_GLOBAL",
		"GIT_TERMINAL_PROMPT", "GIT_CEILING_DIRECTORIES", "LC_ALL", "SystemRoot",
	}
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		if !slices.Contains(allowed, name) {
			t.Errorf("git env has %s, want only the scrubbed set", name)
		}
	}
	for _, want := range []string{"GIT_OPTIONAL_LOCKS=0", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + os.DevNull,
		"GIT_TERMINAL_PROMPT=0", "GIT_CEILING_DIRECTORIES=" + filepath.Dir(repo)} {
		if !slices.Contains(env, want) {
			t.Errorf("git env = %q, want %s", env, want)
		}
	}
}

func TestGitArgsHardenEveryKnownKey(t *testing.T) {
	args := strings.Join(gitArgs("/r"), " ")

	for _, want := range []string{
		"--no-pager", "--work-tree=/r",
		"core.fsmonitor=false", "core.useBuiltinFSMonitor=false", "core.untrackedCache=false",
		"core.hooksPath=" + os.DevNull, "core.excludesFile=" + os.DevNull, "safe.bareRepository=explicit",
		"ls-files -z --cached --others --exclude-standard",
	} {
		if !strings.Contains(args, want) {
			t.Errorf("git args = %q, want %q", args, want)
		}
	}
}

func TestRunWalksOKProjectsOnly(t *testing.T) {
	c := fakeContext(t)
	app := mkdir(t, filepath.Join(c.Env.Home, "app"))
	write(t, filepath.Join(app, "README.md"), "x")

	r := Run(c, []agent.Adapter{fakeAdapter{name: model.AgentClaude, paths: []string{app, filepath.Join(c.Env.Home, "gone")}}}, nil)

	got := byPath(r.Projects)
	if p := got[app]; p.Walk != model.WalkFallback || len(p.Files) != 1 || p.Files[0].Raw() != "README.md" {
		t.Errorf("app = walk %q, files %v; want the fallback walk with README.md", p.Walk, p.Files)
	}
	if p := got[filepath.Join(c.Env.Home, "gone")]; p.Walk != "" || len(p.Files) != 0 {
		t.Errorf("stale project was walked: %+v", p)
	}
}

func TestWalkProjectMakesAFindingWhenCutOff(t *testing.T) {
	c := fakeContext(t)
	repo := filepath.Join(c.Env.Home, "repo")
	for _, n := range []string{"a", "b", "c"} {
		write(t, filepath.Join(repo, n+".txt"), n)
	}
	p := model.Project{Path: model.NewPath(c.Scrub, repo), Status: model.ProjectOK}

	fs := walkProject(c, &p, 2)

	if len(p.Files) != 2 || len(fs) != 1 || fs[0].RuleID != finding.WalkTruncated().ID {
		t.Errorf("files = %d, findings = %+v; want 2 files and one %s", len(p.Files), fs, finding.WalkTruncated().ID)
	}
}
