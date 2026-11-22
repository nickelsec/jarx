package cli

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
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
	stdout string
	stderr string
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
	return result{code: code, stdout: stdout.String(), stderr: stderr.String()}
}

func TestVersionFlagPrintsVersion(t *testing.T) {
	got := run("--version")

	if got.code != 0 {
		t.Fatalf("exit code = %d, want 0", got.code)
	}
	if got.stdout != "jarx v1.2.3-test\n" {
		t.Errorf("stdout = %q, want %q", got.stdout, "jarx v1.2.3-test\n")
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
	home := fakeHome(t, "A=1\nB=2\n")

	got := run("scan", "--home", home)

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
	home := fakeHome(t, "")
	extra := filepath.Join(home, "extra")
	if err := os.Mkdir(extra, 0o700); err != nil {
		t.Fatal(err)
	}

	got := run("scan", "--home", home, extra)

	if got.code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr %q)", got.code, got.stderr)
	}
	if !strings.Contains(got.stdout, "projects (1)\n  "+extra+"  jarx  0 files (walk)\n") {
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
	got := run("scan", "--home", fakeHome(t, ""))

	if l := line(got.stdout, "home"); !strings.HasSuffix(l, "(exists)") {
		t.Errorf("home line = %q, want it to end with (exists)", l)
	}
}

func TestScanShowsTheStateDirNotCreatedAndLeavesItThat(t *testing.T) {
	home := fakeHome(t, "")

	got := run("scan", "--home", home)

	if l := line(got.stdout, "state dir"); !strings.HasSuffix(l, "(not created yet)") {
		t.Errorf("state dir line = %q, want it to end with (not created yet)", l)
	}
	if _, err := os.Stat(filepath.Join(home, ".jarx-state")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("scan created the state dir (stat err %v), want it to write nothing", err)
	}
}

func TestScanShowsTheStateDirWhenItExists(t *testing.T) {
	home := fakeHome(t, "")
	if err := os.Mkdir(filepath.Join(home, ".jarx-state"), 0o700); err != nil {
		t.Fatal(err)
	}

	got := run("scan", "--home", home)

	if l := line(got.stdout, "state dir"); !strings.HasSuffix(l, "(exists)") {
		t.Errorf("state dir line = %q, want it to end with (exists)", l)
	}
}

func TestScanSaysWhenThereIsNoJarxEnv(t *testing.T) {
	got := run("scan", "--home", fakeHome(t, ""))

	if l := line(got.stdout, "env"); !strings.Contains(l, "no .jarx-env, empty env") {
		t.Errorf("env line = %q, want it to say there's no .jarx-env", l)
	}
}

func TestScanCountsArePlural(t *testing.T) {
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
		got := run("scan", "--home", fakeHome(t, tt.jarxEnv))

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

func TestScanDemoHome(t *testing.T) {
	demo := filepath.Join("..", "..", "testdata", "demo")
	data, err := os.ReadFile(filepath.Join(demo, ".jarx-env")) //nolint:gosec // G304: fixed repo fixture path
	if err != nil {
		t.Fatal(err)
	}

	got := run("scan", "--home", demo)

	if got.code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr %q)", got.code, got.stderr)
	}
	abs, err := filepath.Abs(demo)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range demoWant(abs) {
		if !strings.Contains(got.stdout, want) {
			t.Errorf("stdout = %q, want it to contain %q", got.stdout, want)
		}
	}
	assertNoEnvLeak(t, string(data), got.stdout+got.stderr)
	// The demo's fake .env is imported by its CLAUDE.md. Nothing in it may
	// show up: jarx never reads it.
	if strings.Contains(got.stdout+got.stderr, "sk-demo-0000") {
		t.Errorf("output contains the demo .env's value:\n%s", got.stdout)
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

	for _, id := range []string{"JARX-SCAN-001", "JARX-CLAUDE-001", "JARX-CODEX-001"} {
		if _, ok := rules.Lookup(id); !ok {
			t.Errorf("registry is missing %s", id)
		}
	}
}

// demoWant is what the demo scan has to print, with paths under abs.
func demoWant(abs string) []string {
	proj := func(rel string) string { return filepath.Join(abs, "projects", rel) }
	userClaudeMD := filepath.Join(abs, ".claude", "CLAUDE.md")
	appCodex := proj(filepath.Join("app", ".codex", "config.toml"))
	codexOff := "  not in effect: sandbox_mode is set in " + appCodex
	userCodexProfile := "      default_permissions = locked  user\n" +
		"      deny   locked **/*.env  user\n" +
		"      deny   locked ~/.ssh  user\n"
	return []string{
		"environment (fake home)", "3 vars from .jarx-env", "skipped (--home)",
		// The demo's records use paths like /projects/app, read inside the
		// fake home.
		"projects (3)\n" +
			"  " + proj("app") + "  claude (trusted), codex (trusted)  8 files (walk)\n" +
			"    claude permissions\n" +
			"      mode   bypassPermissions  user\n" +
			"      allow  Bash(*)  project\n" +
			"      deny   Read(./.env)  project\n" +
			"    codex permissions\n" +
			"      sandbox_mode = danger-full-access  project\n" +
			"      default_permissions = locked  user" + codexOff + ", so Codex uses the legacy sandbox and ignores default_permissions\n" +
			"      deny   locked **/*.env  user" + codexOff + ", so Codex ignores permission profiles\n" +
			"      deny   locked ~/.ssh  user" + codexOff + ", so Codex ignores permission profiles\n" +
			"    claude instructions\n" +
			"      instructions  " + userClaudeMD + "  user, at launch\n" +
			"      instructions  CLAUDE.md  project, at launch\n" +
			"      import  docs/setup.md  project, at launch, via CLAUDE.md\n" +
			"      import  .env  project, at launch, via CLAUDE.md, credential file, not read\n" +
			"    claude hooks\n" +
			"      PostToolUse (Edit|Write)  command  ${CLAUDE_PROJECT_DIR}/.claude/hooks/format.sh  project, script .claude/hooks/format.sh\n" +
			"    claude skills\n" +
			"      skill  release  .claude/skills/release/SKILL.md  project, when invoked, pre-approves Bash(git *), runs 1 shell command\n" +
			"  " + proj("notes") + "  codex (untrusted)  1 file (walk)\n" +
			"    claude permissions\n" +
			"      mode   bypassPermissions  user\n" +
			"    codex permissions\n" + userCodexProfile +
			"    claude instructions\n" +
			"      instructions  " + userClaudeMD + "  user, at launch\n" +
			"  " + proj("old") + "  claude (unknown)  stale\n",
		"unknown settings (0)\n",
		"instructions not tied to a project (0)\n",
		"findings (4)\n" +
			"  high  JARX-CLAUDE-002  " + proj(filepath.Join("app", ".env")) +
			"  an instruction file pulls a credential file into Claude's context: an @import in " +
			proj(filepath.Join("app", "CLAUDE.md")) + " points at a credential file; jarx didn't read it\n" +
			"  high  JARX-CODEX-001  " + appCodex + "  a repository's sandbox_mode turns off your permission profile: " +
			appCodex + " sets sandbox_mode = danger-full-access, so Codex ignores default_permissions = locked from user settings\n" +
			"  medium  JARX-CLAUDE-003  " + proj(filepath.Join("app", ".claude", "skills", "release", "SKILL.md")) +
			"  a skill runs shell commands before Claude sees it: release runs 1 shell command when invoked\n" +
			"  medium  JARX-CLAUDE-004  " + proj(filepath.Join("app", ".claude", "skills", "release", "SKILL.md")) +
			"  a repository skill grants tools or adds hooks without the trust check: release pre-approves Bash(git *)\n",
	}
}
