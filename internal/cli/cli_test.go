package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
)

// result is what one Run call produced.
type result struct {
	code   int
	stdout string
	stderr string
}

func run(args ...string) result {
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

func TestScanWithoutHomeShowsThisMachine(t *testing.T) {
	// Prints counts and paths only. No config file is read.
	got := run("scan")

	if got.code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr %q)", got.code, got.stderr)
	}
	if !strings.Contains(got.stdout, "environment (this machine)") {
		t.Errorf("stdout = %q, want the this machine heading", got.stdout)
	}
	if strings.Contains(got.stdout, "skipped (--home)") {
		t.Errorf("stdout = %q, system dirs should not be skipped", got.stdout)
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

func TestScanRejectsArguments(t *testing.T) {
	got := run("scan", "extra")

	if got.code != 2 {
		t.Fatalf("exit code = %d, want 2", got.code)
	}
	if !strings.Contains(got.stderr, `unexpected argument "extra"`) {
		t.Errorf("stderr = %q, want it to name the argument", got.stderr)
	}
	if !strings.Contains(got.stderr, "usage: jarx scan") {
		t.Errorf("stderr = %q, want scan usage", got.stderr)
	}
}

func TestScanRejectsUnknownFlag(t *testing.T) {
	got := run("scan", "--bogus")

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
