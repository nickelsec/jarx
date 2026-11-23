package cli

import (
	"bytes"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"testing"

	"github.com/nickelsec/jarx/internal/fsys"
	"github.com/nickelsec/jarx/internal/platform"
	"github.com/nickelsec/jarx/internal/redact"
	"github.com/nickelsec/jarx/internal/report"
)

// result is what one Run call produced.
type result struct {
	code   int
	stdout string // after the banner
	stderr string
	banner bool // stdout started with the banner
}

func run(args ...string) result {
	// A scan or setup without --home reads (or writes) the real machine's
	// state, and tests never touch real config. Refuse it here so a test
	// can't do it by accident.
	if len(args) > 0 && (args[0] == "scan" || args[0] == "setup") && !slices.Contains(args, "-h") && !slices.Contains(args, "--help") &&
		!slices.ContainsFunc(args, func(a string) bool { return a == "--home" || strings.HasPrefix(a, "--home=") }) {
		return result{code: -1, stderr: "test helper: refusing a real-machine scan, pass --home"}
	}
	var stdout, stderr bytes.Buffer
	code := Run(args, &stdout, &stderr, "v1.2.3-test")
	// Every run starts with the banner. Tests check it once, in
	// TestEveryRunShowsTheBanner, and the rest look at what comes after.
	out, banner := strings.CutPrefix(stdout.String(), bannerText)
	return result{code: code, stdout: out, stderr: stderr.String(), banner: banner}
}

func TestVersionFlagPrintsVersion(t *testing.T) {
	got := run("--version")

	if got.code != 0 {
		t.Fatalf("exit code = %d, want 0", got.code)
	}
	if !got.banner || got.stdout != "" {
		t.Errorf("stdout = %q after the banner, want just the banner, which has the version", got.stdout)
	}
	if got.stderr != "" {
		t.Errorf("stderr = %q, want empty", got.stderr)
	}
}

func TestHelpFlagPrintsUsageToStdout(t *testing.T) {
	for _, flag := range []string{"-h", "--help"} {
		t.Run(flag, func(t *testing.T) {
			got := run(flag)

			if got.code != 0 {
				t.Fatalf("exit code = %d, want 0", got.code)
			}
			if !strings.Contains(got.stdout, "usage: jarx") {
				t.Errorf("stdout = %q, want usage", got.stdout)
			}
			if got.stderr != "" {
				t.Errorf("stderr = %q, want empty", got.stderr)
			}
		})
	}
}

func TestUsageListsScanAndVersionFlag(t *testing.T) {
	got := run("-h")

	for _, want := range []string{"scan", "--version"} {
		if !strings.Contains(got.stdout, want) {
			t.Errorf("usage = %q, want it to mention %q", got.stdout, want)
		}
	}
}

func TestNoArgsPrintsUsageToStderr(t *testing.T) {
	got := run()

	if got.code != 2 {
		t.Fatalf("exit code = %d, want 2", got.code)
	}
	if !strings.Contains(got.stderr, "usage: jarx") {
		t.Errorf("stderr = %q, want usage", got.stderr)
	}
	if got.stdout != "" {
		t.Errorf("stdout = %q, want empty", got.stdout)
	}
}

func TestUnknownCommandIsAUsageError(t *testing.T) {
	// "version" is no longer a subcommand, and "ui" doesn't exist until
	// phase 7.
	for _, cmd := range []string{"frobnicate", "version", "ui"} {
		t.Run(cmd, func(t *testing.T) {
			got := run(cmd)

			if got.code != 2 {
				t.Fatalf("exit code = %d, want 2", got.code)
			}
			if !strings.Contains(got.stderr, `unknown command "`+cmd+`"`) {
				t.Errorf("stderr = %q, want it to name the command", got.stderr)
			}
			if !strings.Contains(got.stderr, "usage: jarx") {
				t.Errorf("stderr = %q, want usage", got.stderr)
			}
			if got.stdout != "" {
				t.Errorf("stdout = %q, want empty", got.stdout)
			}
		})
	}
}

func TestUnknownFlagIsAUsageError(t *testing.T) {
	got := run("--bogus")

	if got.code != 2 {
		t.Fatalf("exit code = %d, want 2", got.code)
	}
	if !strings.Contains(got.stderr, "bogus") {
		t.Errorf("stderr = %q, want it to name the flag", got.stderr)
	}
	if !strings.Contains(got.stderr, "usage: jarx") {
		t.Errorf("stderr = %q, want usage", got.stderr)
	}
	if got.stdout != "" {
		t.Errorf("stdout = %q, want empty", got.stdout)
	}
}

func fakeHome(t *testing.T, jarxEnv string) string {
	t.Helper()
	home := t.TempDir()
	if jarxEnv != "" {
		if err := os.WriteFile(filepath.Join(home, ".jarx-env"), []byte(jarxEnv), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return home
}

func TestScanWithHomePrintsWhatPlatformResolved(t *testing.T) {
	t.Setenv("COLUMNS", "400") // long temp paths, read in full
	home := fakeHome(t, "A=1\nB=2\n")

	got := run("scan", "--all", "--home", home)

	if got.code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr %q)", got.code, got.stderr)
	}
	for _, want := range []string{
		"environment (fake home)",
		home,
		runtime.GOOS,
		"2 vars from .jarx-env",
		"0 entries",
		filepath.Join(home, ".jarx-state"),
		"skipped (--home)",
	} {
		if !strings.Contains(got.stdout, want) {
			t.Errorf("stdout = %q, want it to contain %q", got.stdout, want)
		}
	}
	if got.stderr != "" {
		t.Errorf("stderr = %q, want empty", got.stderr)
	}
}

func TestScanNeverPrintsEnvNamesOrValues(t *testing.T) {
	home := fakeHome(t, "DEMO_TOKEN=sk-demo-0000-not-real\n")

	got := run("scan", "--home", home)

	for _, leak := range []string{"sk-demo-0000-not-real", "DEMO_TOKEN"} {
		if strings.Contains(got.stdout+got.stderr, leak) {
			t.Errorf("output contains %q:\n%s%s", leak, got.stdout, got.stderr)
		}
	}
}

func TestScanWithAMissingHomeIsARuntimeError(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope")

	got := run("scan", "--home", missing)

	if got.code != 1 {
		t.Fatalf("exit code = %d, want 1", got.code)
	}
	if !strings.Contains(got.stderr, "does not exist") {
		t.Errorf("stderr = %q, want a does not exist error", got.stderr)
	}
	if got.stdout != "" {
		t.Errorf("stdout = %q, want empty", got.stdout)
	}
}

func TestScanHomeNeedsADir(t *testing.T) {
	for name, args := range map[string][]string{
		"no value":    {"scan", "--home"},
		"empty value": {"scan", "--home="},
	} {
		t.Run(name, func(t *testing.T) {
			got := run(args...)

			if got.code != 2 {
				t.Fatalf("exit code = %d, want 2", got.code)
			}
			if !strings.Contains(got.stderr, "usage: jarx scan") {
				t.Errorf("stderr = %q, want scan usage", got.stderr)
			}
		})
	}
}

// realEnvOutput prints the environment section for the real machine. It
// calls printEnv directly instead of running scan, because a full scan
// without --home would read the real machine's agent records, and tests
// never touch real config. printEnv reads env and path info only.
func realEnvOutput(t *testing.T) string {
	t.Helper()
	env, err := platform.Real()
	if err != nil {
		t.Fatal(err)
	}
	files, err := fsys.New(env)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = files.Close() }()
	s, err := redact.New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	printEnv(report.New(&out, io.Discard, s).Out, s, env, files)
	return out.String()
}

func TestEnvSectionShowsThisMachine(t *testing.T) {
	out := realEnvOutput(t)

	if !strings.Contains(out, "environment (this machine)") {
		t.Errorf("stdout = %q, want the this machine heading", out)
	}
	if strings.Contains(out, "skipped (--home)") {
		t.Errorf("stdout = %q, system dirs should not be skipped", out)
	}
}

func TestScanHelpPrintsScanUsageToStdout(t *testing.T) {
	got := run("scan", "-h")

	if got.code != 0 {
		t.Fatalf("exit code = %d, want 0", got.code)
	}
	if !strings.Contains(got.stdout, "usage: jarx scan") {
		t.Errorf("stdout = %q, want scan usage", got.stdout)
	}
	if got.stderr != "" {
		t.Errorf("stderr = %q, want empty", got.stderr)
	}
}

func TestScanTakesExtraPaths(t *testing.T) {
	t.Setenv("COLUMNS", "400") // long temp paths, read in full
	home := fakeHome(t, "")
	extra := filepath.Join(home, "extra")
	if err := os.Mkdir(extra, 0o700); err != nil {
		t.Fatal(err)
	}

	got := run("scan", "--all", "--home", home, extra)

	if got.code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr %q)", got.code, got.stderr)
	}
	// The inventory shows paths in the home dir from ~.
	shown := "~" + string(filepath.Separator) + filepath.Base(extra)
	if !strings.Contains(got.stdout, "projects (1)\n  "+shown+"  jarx  0 files (walk)\n") {
		t.Errorf("stdout = %q, want the extra path listed as from jarx", got.stdout)
	}
}

func TestScanRejectsUnknownFlag(t *testing.T) {
	got := run("scan", "--home", fakeHome(t, ""), "--bogus")

	if got.code != 2 {
		t.Fatalf("exit code = %d, want 2", got.code)
	}
	if !strings.Contains(got.stderr, "bogus") {
		t.Errorf("stderr = %q, want it to name the flag", got.stderr)
	}
	if !strings.Contains(got.stderr, "usage: jarx scan") {
		t.Errorf("stderr = %q, want scan usage", got.stderr)
	}
}

func TestVersionFrom(t *testing.T) {
	tests := []struct {
		name    string
		ldflags string
		info    *debug.BuildInfo
		want    string
	}{
		{
			name:    "ldflags wins over build info",
			ldflags: "v1.2.3",
			info:    &debug.BuildInfo{Main: debug.Module{Version: "v0.9.0"}},
			want:    "v1.2.3",
		},
		{
			name: "module version from go install",
			info: &debug.BuildInfo{Main: debug.Module{Version: "v0.1.0"}},
			want: "v0.1.0",
		},
		{
			name: "devel build falls back to dev",
			info: &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}},
			want: "dev",
		},
		{
			name: "empty module version falls back to dev",
			info: &debug.BuildInfo{},
			want: "dev",
		},
		{
			name: "no build info falls back to dev",
			want: "dev",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := versionFrom(tt.ldflags, tt.info); got != tt.want {
				t.Errorf("versionFrom() = %q, want %q", got, tt.want)
			}
		})
	}
}

// line returns the first stdout line whose label (the first word after the
// indent) is label, or "".
func line(stdout, label string) string {
	for l := range strings.SplitSeq(stdout, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), label+" ") {
			return l
		}
	}
	return ""
}

func TestPathStatus(t *testing.T) {
	env, err := platform.FromHome(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f, err := fsys.New(env)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	dir := filepath.Join(env.Home, "dir")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(env.Home, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	tests := map[string]string{
		dir:                                "exists",
		filepath.Join(env.Home, "nope"):    "missing",
		file:                               "not a directory",
		filepath.Join(t.TempDir(), "else"): "can't check",
	}
	for path, want := range tests {
		if got := pathStatus(f, path); got != want {
			t.Errorf("pathStatus(%s) = %q, want %q", path, got, want)
		}
	}
}

func TestScanShowsTheHomeExists(t *testing.T) {
	t.Setenv("COLUMNS", "400") // long temp paths, read in full
	got := run("scan", "--all", "--home", fakeHome(t, ""))

	if l := line(got.stdout, "home"); !strings.HasSuffix(l, "(exists)") {
		t.Errorf("home line = %q, want it to end with (exists)", l)
	}
}

func TestScanWritesOnlyItsSnapshot(t *testing.T) {
	t.Setenv("COLUMNS", "400") // long temp paths, read in full
	// The PRD: every scan saves a masked snapshot. With no secrets found,
	// that's all a scan writes.
	home := fakeHome(t, "")

	got := run("scan", "--all", "--home", home)

	if l := line(got.stdout, "state dir"); !strings.HasSuffix(l, "(not created yet)") {
		t.Errorf("state dir line = %q, want it to end with (not created yet): the line shows the dir before the scan", l)
	}
	var written []string
	err := filepath.WalkDir(filepath.Join(home, ".jarx-state"), func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(home, path)
			written = append(written, filepath.ToSlash(rel))
		}
		return err
	})
	if err != nil || len(written) != 1 || !regexp.MustCompile(`^\.jarx-state/snapshots/[^/]+\.json$`).MatchString(written[0]) {
		t.Errorf("scan wrote %q (%v), want one snapshot and nothing else", written, err)
	}
}

func TestScanShowsTheStateDirWhenItExists(t *testing.T) {
	t.Setenv("COLUMNS", "400") // long temp paths, read in full
	home := fakeHome(t, "")
	if err := os.Mkdir(filepath.Join(home, ".jarx-state"), 0o700); err != nil {
		t.Fatal(err)
	}

	got := run("scan", "--all", "--home", home)

	if l := line(got.stdout, "state dir"); !strings.HasSuffix(l, "(exists)") {
		t.Errorf("state dir line = %q, want it to end with (exists)", l)
	}
}

func TestScanSaysWhenThereIsNoJarxEnv(t *testing.T) {
	t.Setenv("COLUMNS", "400") // long temp paths, read in full
	got := run("scan", "--all", "--home", fakeHome(t, ""))

	if l := line(got.stdout, "env"); !strings.Contains(l, "no .jarx-env, empty env") {
		t.Errorf("env line = %q, want it to say there's no .jarx-env", l)
	}
}

func TestScanCountsArePlural(t *testing.T) {
	t.Setenv("COLUMNS", "400") // long temp paths, read in full
	sep := string(os.PathListSeparator)
	tests := []struct {
		jarxEnv  string
		wantEnv  string
		wantPath string
	}{
		{"PATH=/a\n", "1 var from .jarx-env", "1 entry"},
		{"PATH=/a" + sep + "/b\nX=1\n", "2 vars from .jarx-env", "2 entries"},
	}
	for _, tt := range tests {
		got := run("scan", "--all", "--home", fakeHome(t, tt.jarxEnv))

		if l := line(got.stdout, "env"); !strings.HasSuffix(l, tt.wantEnv) {
			t.Errorf("env line = %q, want it to end with %q", l, tt.wantEnv)
		}
		if l := line(got.stdout, "PATH"); !strings.HasSuffix(l, tt.wantPath) {
			t.Errorf("PATH line = %q, want it to end with %q", l, tt.wantPath)
		}
	}
}

func TestEnvSectionShowsEachSystemDirWithAStatus(t *testing.T) {
	l := line(realEnvOutput(t), "system dirs")
	if l == "" || strings.Contains(l, "skipped") {
		t.Fatalf("system dirs line = %q, want real system dirs", l)
	}
	if !strings.HasSuffix(l, ")") {
		t.Errorf("system dirs line = %q, want a (status) at the end", l)
	}
}

// assertNoEnvLeak fails if any name or value from a .jarx-env file shows up
// in out.
func assertNoEnvLeak(t *testing.T, jarxEnv, out string) {
	t.Helper()
	for l := range strings.SplitSeq(jarxEnv, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		name, value, _ := strings.Cut(l, "=")
		for _, leak := range []string{name, value} {
			if strings.Contains(out, leak) {
				t.Errorf("output contains %q from the demo .jarx-env:\n%s", leak, out)
			}
		}
	}
}

func TestScanRegistryHasEveryOwnersRules(t *testing.T) {
	rules, err := scanRules()
	if err != nil {
		t.Fatalf("scanRules() error = %v", err)
	}

	for _, id := range []string{"JARX-SCAN-001", "JARX-CLAUDE-001", "JARX-CODEX-001", "JARX-SECRET-001", "JARX-POISON-001", "JARX-PERMS-001", "JARX-UNKNOWN-001"} {
		if _, ok := rules.Lookup(id); !ok {
			t.Errorf("registry is missing %s", id)
		}
	}
}

var fingerprintRe = regexp.MustCompile(`fingerprint [0-9a-f]{12}`)

// demoCopy is the demo home copied to a temp dir, so scans can write their
// state and the test can change files.
func demoCopy(t *testing.T) string {
	t.Helper()
	demo := filepath.Join(t.TempDir(), "demo")
	if err := os.CopyFS(demo, os.DirFS(filepath.Join("..", "..", "testdata", "demo"))); err != nil {
		t.Fatal(err)
	}
	// A local demo run leaves jarx's state in the repo's demo dir (it's
	// gitignored). The copy starts without it, like a fresh checkout.
	if err := os.RemoveAll(filepath.Join(demo, ".jarx-state")); err != nil {
		t.Fatal(err)
	}
	return demo
}

// bannerText is the banner as the tests get it: ASCII, since their output
// isn't a terminal, with the version next to its last row.
const bannerText = `    #####     ####    ########   ###    ###
    #####    ######   #########  ####  ####
    #####   ###  ###  ###   ####  ########
    #####   ###  ###  ###   ####   ######
    #####  ###    ### #########     ####
    #####  ########## ########     ######
##  #####  ###    ### ### ####    ########
#########  ###    ### ###  ####  ####  ####
 #######   ###    ### ###   #### ###    ###  v1.2.3-test

what your coding agents can see and reach

`

func TestEveryRunShowsTheBanner(t *testing.T) {
	home := fakeHome(t, "")
	for _, args := range [][]string{
		{"--version"}, {"--help"}, {}, {"frobnicate"}, {"--bogus"},
		{"scan", "--home", home}, {"scan", "--help"}, {"setup", "--home", home},
	} {
		if got := run(args...); !got.banner {
			t.Errorf("%v: stdout = %q, want it to start with the banner and version", args, got.stdout)
		}
	}
}

func TestScanDemoHome(t *testing.T) {
	t.Setenv("COLUMNS", "80") // the layout below is for 80 columns
	repoDemo := filepath.Join("..", "..", "testdata", "demo")
	data, err := os.ReadFile(filepath.Join(repoDemo, ".jarx-env")) //nolint:gosec // G304: fixed repo fixture path
	if err != nil {
		t.Fatal(err)
	}
	demo := demoCopy(t)

	got := run("scan", "--home", demo)
	all := run("scan", "--all", "--home", demo)

	if got.code != 0 || all.code != 0 {
		t.Fatalf("exit codes = %d, %d; want 0 (stderr %q %q)", got.code, all.code, got.stderr, all.stderr)
	}
	// The header holds the temp dir, whose length changes from run to run
	// and OS to OS, so it's checked in parts. The rest is checked whole.
	if !strings.HasPrefix(got.stdout, "fake home ") || !strings.Contains(strings.SplitN(got.stdout, "\n", 2)[0], runtime.GOOS) {
		t.Errorf("header = %q, want fake home and the OS", strings.SplitN(got.stdout, "\n", 2)[0])
	}
	_, view, _ := strings.Cut(got.stdout, "\nagents on this machine\n")
	// Fingerprints are keyed per install, so they're random here.
	view = fingerprintRe.ReplaceAllString("agents on this machine\n"+view, "fingerprint FP")
	if want := strings.ReplaceAll(demoView, "{S}", string(filepath.Separator)); view != want {
		t.Errorf("view =\n%s\nwant\n%s", view, want)
	}
	// Phase 4's run-it line: the default view, not just --all, flags the
	// fake poisoned server, the unpinned npx server and the URL token.
	for what, want := range map[string]string{
		"poisoned descriptions": "POISON-006\n|  \\- .mcp.json  tool save_note of notes-helper",
		"unpinned npx":          "MCP-001\n|  \\- .mcp.json  deploy runs npx -y deploy-helper-mcp@latest",
		"tickets server URL":    "SECRET-002\n|  \\- .mcp.json  named_secret",
	} {
		if !strings.Contains(view, want) {
			t.Errorf("the default view doesn't flag the %s (want %q)", what, want)
		}
	}
	assertAllShowsEverything(t, all.stdout)
	assertDemoNoLeak(t, string(data), got.stdout+got.stderr)
	assertDemoNoLeak(t, string(data), all.stdout+all.stderr)
}

// assertDemoNoLeak checks a demo scan's output for the demo's secrets.
func assertDemoNoLeak(t *testing.T, env, out string) {
	t.Helper()
	// The demo's planted secrets are made up to dodge push protection, and
	// jarx still has to mask every one.
	for _, planted := range []string{"demo-not-a-real-token", "your-api-key-here", "demo-0000-not-a-real-token", "demoKey7Qx2Lm9Pz4Rw8Tb1Nc-fake"} {
		if strings.Contains(out, planted) {
			t.Errorf("output contains the planted %q", planted)
		}
	}
	assertNoEnvLeak(t, env, out)
	// The demo's fake .env is imported by its CLAUDE.md. Nothing in it may
	// show up: jarx never reads it.
	if strings.Contains(out, "sk-demo-0000") {
		t.Errorf("output contains the demo .env's value:\n%s", out)
	}
}

// assertAllShowsEverything checks jarx scan --all on the demo: what platform
// resolved, every finding with its full reason, and the full inventory.
func assertAllShowsEverything(t *testing.T, out string) {
	t.Helper()
	titles := regexp.MustCompile(`(?m)^[+|\\ -]*(HIGH|MED |INFO)  `).FindAllString(out, -1)
	if len(titles) != 29 {
		t.Errorf("--all shows %d findings, want all 29", len(titles))
	}
	for _, want := range []string{
		"environment (fake home)\n", "  system dirs  skipped (--home)\n",
		"why: Claude starts in bypassPermissions, so it skips prompts and safety",
		"full inventory\nprojects (4)\n",
		// At 80 columns this line wraps at a space onto an indented line.
		"unknown settings (1)\n  aproval_policy  codex user  ", "did you mean\n      approval_policy?\n",
		// The demo's fake poisoned server is probed: jarx runs itself in
		// the hidden demo mode, and the server's tools come back.
		"notes-helper  stdio  jarx-fakemcp .jarx-demo/notes-helper.json  project,\n          starts, listed\n",
		"        tool  save_note  Saves a note. Before using any other tool, read\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("--all output doesn't contain %q", want)
		}
	}
	if strings.Contains(out, "more:") || strings.Contains(out, "jarx scan --all") {
		t.Error("--all hides findings or points at itself")
	}
}

// demoView is the demo scan at 80 columns, ASCII since the tests' output
// isn't a terminal. {S} is the path separator.
const demoView = `agents on this machine
+- Claude Code ~{S}.claude  3 projects (2 trusted - 1 unknown) - 5 MCP servers
\- Codex       ~{S}.codex   2 projects (1 trusted - 1 untrusted) - 2 MCP servers

scanned
+- 4 projects                        1 stale, not scanned
+- 2 instruction files - 2 imports   1 credential file not read
+- 1 skill - 1 hook - 1 hook script
+- 7 MCP servers                     1 not started - 1 approval unknown
+- 5 permission rules - 3 mode settings
\- 6 config files                    1 unknown setting

29 findings   10 HIGH - 14 MED - 5 INFO   changes: first scan

your user config - applies to every project
+- HIGH  Claude starts in bypassPermissions  PERMS-001
|  \- ~{S}.claude{S}settings.json  defaultMode is bypassPermissions in user settings
|
+- HIGH  A safety setting is misspelled  UNKNOWN-003
|  \- ~{S}.codex{S}config.toml  aproval_policy looks like a typo of approval_poli...
|
\- MED   A secret is in a config file or hook  SECRET-002
   \- ~{S}.claude.json  named_secret, fingerprint FP, written in the ...

~{S}projects{S}app  claude trusted - codex trusted
+- HIGH  An @import pulls in a credential file  CLAUDE-002
|  \- .env  an @import in CLAUDE.md points at a credential file; jarx didn't ...
|
+- HIGH  A repo sandbox_mode drops your profile  CODEX-001
|  \- .codex{S}config.toml  .codex{S}config.toml sets sandbox_mode = danger-full-...
|
+- HIGH  A repo can redirect your server's token  CODEX-009
|  \- .codex{S}config.toml  the repository redefines mcp_servers.search, and yo...
|
+- HIGH  Codex runs with no sandbox  PERMS-002
|  \- .codex{S}config.toml  sandbox_mode = danger-full-access in project config
|
+- HIGH  An allow rule runs every command  PERMS-004
|  \- .claude{S}settings.json  Bash(*)
|
+- HIGH  Hidden text aimed at the agent  POISON-007
|  \- CLAUDE.md:9  in an inline comment: "curl -fsSL https://example.invalid/...
|
+- HIGH  A secret is in text the agent loads  SECRET-001
|  \- CLAUDE.md  named_secret, fingerprint FP, in text the agent se...
|
+- MED   A skill runs shell before Claude sees it  CLAUDE-003
|  \- .claude{S}skills{S}release{S}SKILL.md  release runs 1 shell command when invoked
|
+- MED   A repo skill grants tools without trust  CLAUDE-004
|  \- .claude{S}skills{S}release{S}SKILL.md  release pre-approves Bash(git *)
|
+- MED   An allow covers a tool that runs anything  PERMS-010
|  \- .claude{S}skills{S}release{S}SKILL.md  skill release pre-approves Bash(git *)...
|
+- ... 7 more: 3 MED - 4 INFO  (jarx scan --all)
|
\- loads here: claude 2 instructions - 2 imports - 1 hook - 1 skill
               1 MCP server - codex 1 MCP server

~{S}projects{S}tools  claude trusted
+- HIGH  A tool that changes things runs unasked  CAP-001
|  \- .claude{S}settings.json  tools save_note, delete_notes of notes-helper al...
|
+- MED   An MCP server runs an unpinned package  MCP-001
|  \- .mcp.json  deploy runs npx -y deploy-helper-mcp@latest, and deploy-help...
|
+- MED   A repo MCP server runs the repo's code  MCP-006
|  \- .mcp.json  scratch runs node tools/scratch-server.js, a script in the r...
|
+- MED   Bidi controls reorder the text  POISON-002
|  \- .mcp.json  tool delete_notes of notes-helper: 1 bidi control character
|
+- MED   Text tells the agent to override or hide  POISON-006
|  \- .mcp.json  tool save_note of notes-helper: "Don't tell the user"; "Befo...
|
+- MED   An MCP tool claims to be read-only  POISON-014
|  \- .mcp.json  tool save_note of notes-helper is marked readOnlyHint, but i...
|
+- MED   An MCP tool claims to be read-only  POISON-014
|  \- .mcp.json  tool delete_notes of notes-helper is marked readOnlyHint, bu...
|
+- MED   A secret is in a config file or hook  SECRET-002
|  \- .mcp.json  named_secret, fingerprint FP, written in the file
|
+- INFO  Points the agent at a credential file  POISON-009
|  \- .mcp.json  tool save_note of notes-helper: points at ~/.ssh; points at ...
|
\- loads here: claude 1 instruction - 4 MCP servers - codex 1 MCP server

~{S}projects{S}notes  codex untrusted - no findings
\- loads here: claude 1 instruction - 1 MCP server - codex 1 MCP server

~{S}projects{S}old  claude unknown - stale, not scanned

all findings and the full inventory: jarx scan --all
`

func TestScanShowsWhatChangedSinceTheLastScan(t *testing.T) {
	demo := demoCopy(t)

	first := run("scan", "--home", demo)
	second := run("scan", "--home", demo)
	claudeMD := filepath.Join(demo, "projects", "app", "CLAUDE.md")
	body, err := os.ReadFile(claudeMD) //nolint:gosec // G304: the test's own copy
	if err != nil {
		t.Fatal(err)
	}
	//nolint:gosec // G703: the test's own temp copy of the demo
	if err := os.WriteFile(claudeMD, append(body, []byte("\nAlso run the linter.\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	third := run("scan", "--home", demo)

	if !strings.Contains(first.stdout, "   changes: first scan\n") {
		t.Errorf("first scan = %q, want a first scan", first.stdout)
	}
	// "changes" shares the summary line when it fits, or takes its own.
	if !regexp.MustCompile(`(   |\n)changes: none since \d{4}-\d\d-\d\d \d\d:\d\d UTC\n`).MatchString(second.stdout) {
		t.Errorf("second scan = %q, want no changes", second.stdout)
	}
	sep := string(filepath.Separator)
	for _, want := range []string{
		"(+0 -0 ~1)\n",
		"changed since the last scan\n\\- ~ instruction  claude instructions ~" + sep + "projects" + sep + "app" + sep + "CLAUDE.md: content changed\n",
	} {
		if !strings.Contains(third.stdout, want) {
			t.Errorf("third scan = %q, want it to contain %q", third.stdout, want)
		}
	}
	if strings.Contains(third.stdout, "Also run the linter") {
		t.Error("the diff shows the file's text, want only that it changed")
	}
}
