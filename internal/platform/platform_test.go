package platform

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func TestLookupIgnoresCaseOnWindows(t *testing.T) {
	env := newEnv("windows", `C:\home`, `C:\state`, []string{`Path=C:\a;C:\b`}, true, false)

	got, ok := env.Lookup("PATH")

	if !ok || got != `C:\a;C:\b` {
		t.Errorf(`Lookup("PATH") = %q, %v; want the Path value`, got, ok)
	}
}

func TestLookupIsCaseSensitiveOffWindows(t *testing.T) {
	env := newEnv("linux", "/home/u", "/state", []string{"Path=/a"}, true, false)

	if _, ok := env.Lookup("PATH"); ok {
		t.Error(`Lookup("PATH") found "Path" on linux, want case-sensitive`)
	}
	if got, ok := env.Lookup("Path"); !ok || got != "/a" {
		t.Errorf(`Lookup("Path") = %q, %v; want "/a", true`, got, ok)
	}
}

func TestEmptyValueCountsAsSet(t *testing.T) {
	env := newEnv("linux", "/home/u", "/state", []string{"EMPTY="}, true, false)

	got, ok := env.Lookup("EMPTY")

	if !ok || got != "" {
		t.Errorf(`Lookup("EMPTY") = %q, %v; want "", true`, got, ok)
	}
}

func TestOddEnvironEntriesAreSkipped(t *testing.T) {
	// Windows has hidden entries like "=C:=C:\" for per-drive cwds.
	env := newEnv("windows", `C:\home`, `C:\state`, []string{`=C:=C:\`, "NOEQUALS", "A=1"}, true, false)

	if got := env.VarCount(); got != 1 {
		t.Errorf("VarCount() = %d, want 1", got)
	}
}

func TestPathSplitsWithTheGOOSSeparator(t *testing.T) {
	tests := []struct {
		goos string
		path string
		want []string
	}{
		{"windows", `PATH=C:\a;;C:\b`, []string{`C:\a`, `C:\b`}},
		{"linux", "PATH=/usr/bin::/bin", []string{"/usr/bin", "/bin"}},
		{"darwin", "PATH=/usr/bin:/opt/homebrew/bin", []string{"/usr/bin", "/opt/homebrew/bin"}},
	}
	for _, tt := range tests {
		t.Run(tt.goos, func(t *testing.T) {
			env := newEnv(tt.goos, "h", "s", []string{tt.path}, true, false)

			if !slices.Equal(env.Path, tt.want) {
				t.Errorf("Path = %q, want %q", env.Path, tt.want)
			}
		})
	}
}

func TestSystemRootsPerOS(t *testing.T) {
	tests := []struct {
		goos    string
		environ []string
		want    Roots
	}{
		{"linux", nil, Roots{Etc: "/etc"}},
		{"darwin", nil, Roots{Etc: "/etc", LibraryAppSupport: "/Library/Application Support"}},
		{
			"windows",
			[]string{`ProgramData=C:\ProgramData`, `ProgramFiles=C:\Program Files`},
			Roots{ProgramData: `C:\ProgramData`, ProgramFiles: `C:\Program Files`},
		},
		// Missing vars stay empty. jarx doesn't guess a drive letter.
		{"windows", nil, Roots{}},
	}
	for _, tt := range tests {
		t.Run(tt.goos, func(t *testing.T) {
			env := newEnv(tt.goos, "h", "s", tt.environ, true, false)

			got, ok := env.SystemRoots()

			if !ok {
				t.Fatal("SystemRoots() ok = false, want true")
			}
			if got != tt.want {
				t.Errorf("SystemRoots() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestSystemRootsOffWhenNotAllowed(t *testing.T) {
	env := newEnv("linux", "/home/u", "/state", nil, false, true)

	if _, ok := env.SystemRoots(); ok {
		t.Error("SystemRoots() ok = true, want false")
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestFromHomeReadsOnlyJarxEnv(t *testing.T) {
	home := t.TempDir()
	pathList := strings.Join([]string{"/fake/bin", "/fake/sbin"}, string(os.PathListSeparator))
	writeFile(t, filepath.Join(home, ".jarx-env"),
		"# demo env\n\nFOO=bar\r\nSPACED= keep me\nPATH="+pathList+"\n")

	env, err := FromHome(home)
	if err != nil {
		t.Fatalf("FromHome() error = %v", err)
	}

	if got, _ := env.Lookup("FOO"); got != "bar" {
		t.Errorf(`Lookup("FOO") = %q, want "bar" (CR stripped)`, got)
	}
	if got, _ := env.Lookup("SPACED"); got != " keep me" {
		t.Errorf(`Lookup("SPACED") = %q, want the value as written`, got)
	}
	if got := env.VarCount(); got != 3 {
		t.Errorf("VarCount() = %d, want 3", got)
	}
	if !slices.Equal(env.Path, []string{"/fake/bin", "/fake/sbin"}) {
		t.Errorf("Path = %q, want the PATH from .jarx-env", env.Path)
	}
	// Nothing from the real process env leaks in.
	if _, ok := env.Lookup("HOME"); ok {
		t.Error(`Lookup("HOME") found a value, want only .jarx-env vars`)
	}
	if _, ok := env.Lookup("USERPROFILE"); ok {
		t.Error(`Lookup("USERPROFILE") found a value, want only .jarx-env vars`)
	}
}

func TestFromHomeIsFakeWithNoSystemRoots(t *testing.T) {
	home := t.TempDir()

	env, err := FromHome(home)
	if err != nil {
		t.Fatalf("FromHome() error = %v", err)
	}

	if !env.Fake() {
		t.Error("Fake() = false, want true")
	}
	if _, ok := env.SystemRoots(); ok {
		t.Error("SystemRoots() ok = true, want false under --home")
	}
	if env.GOOS != runtime.GOOS {
		t.Errorf("GOOS = %q, want %q", env.GOOS, runtime.GOOS)
	}
}

func TestFromHomeKeepsStateInsideTheHome(t *testing.T) {
	home := t.TempDir()

	env, err := FromHome(home)
	if err != nil {
		t.Fatalf("FromHome() error = %v", err)
	}

	if want := filepath.Join(home, ".jarx-state"); env.StateDir != want {
		t.Errorf("StateDir = %q, want %q", env.StateDir, want)
	}
}

func TestFromHomeWithoutJarxEnvHasAnEmptyEnv(t *testing.T) {
	env, err := FromHome(t.TempDir())
	if err != nil {
		t.Fatalf("FromHome() error = %v", err)
	}

	if got := env.VarCount(); got != 0 {
		t.Errorf("VarCount() = %d, want 0", got)
	}
	if len(env.Path) != 0 {
		t.Errorf("Path = %q, want empty", env.Path)
	}
}

func TestFromHomeMakesTheHomeAbsolute(t *testing.T) {
	parent := t.TempDir()
	if err := os.Mkdir(filepath.Join(parent, "demo"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(parent)

	env, err := FromHome("demo")
	if err != nil {
		t.Fatalf("FromHome() error = %v", err)
	}

	if want := filepath.Join(parent, "demo"); env.Home != want {
		t.Errorf("Home = %q, want %q", env.Home, want)
	}
}

func TestFromHomeRejectsAMissingDir(t *testing.T) {
	_, err := FromHome(filepath.Join(t.TempDir(), "nope"))

	if err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("FromHome() error = %v, want a does not exist error", err)
	}
}

func TestFromHomeRejectsAFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	writeFile(t, file, "")

	_, err := FromHome(file)

	if err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("FromHome() error = %v, want a not a directory error", err)
	}
}

func TestFromHomeBadLineNamesTheLineNotTheValue(t *testing.T) {
	for name, bad := range map[string]string{
		"no equals": "sk-demo-SECRET-no-equals",
		"no key":    "=sk-demo-SECRET-no-key",
	} {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			writeFile(t, filepath.Join(home, ".jarx-env"), "OK=1\n"+bad+"\n")

			_, err := FromHome(home)

			if err == nil {
				t.Fatal("FromHome() error = nil, want a parse error")
			}
			if !strings.Contains(err.Error(), "line 2") {
				t.Errorf("error = %q, want it to name line 2", err)
			}
			if strings.Contains(err.Error(), "sk-demo-SECRET") {
				t.Errorf("error = %q, leaks the line content", err)
			}
		})
	}
}

func TestRealIsTheRealMachine(t *testing.T) {
	// Structural checks only. This reads the process env and home dir path,
	// never any config file.
	env, err := Real()
	if err != nil {
		t.Fatalf("Real() error = %v", err)
	}

	if env.Fake() {
		t.Error("Fake() = true, want false")
	}
	if env.GOOS != runtime.GOOS {
		t.Errorf("GOOS = %q, want %q", env.GOOS, runtime.GOOS)
	}
	if _, ok := env.SystemRoots(); !ok {
		t.Error("SystemRoots() ok = false, want true")
	}
	if filepath.Base(env.StateDir) != "jarx" || !filepath.IsAbs(env.StateDir) {
		t.Errorf("StateDir = %q, want an absolute <config dir>/jarx", env.StateDir)
	}
}
