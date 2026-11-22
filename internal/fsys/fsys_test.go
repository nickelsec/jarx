package fsys

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/nickelsec/jarx/internal/platform"
)

func write(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// fakeFS returns an FS confined to a new fake home.
func fakeFS(t *testing.T) (*FS, string) {
	t.Helper()
	home := t.TempDir()
	env, err := platform.FromHome(home)
	if err != nil {
		t.Fatal(err)
	}
	f, err := New(env)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f, env.Home
}

func TestFakeHomeReadsInsideTheHome(t *testing.T) {
	f, home := fakeFS(t)
	path := filepath.Join(home, ".claude", "settings.json")
	write(t, path, []byte(`{"a":1}`))

	got, err := f.ReadFile(path)

	if err != nil || string(got) != `{"a":1}` {
		t.Fatalf("ReadFile() = %q, %v; want the file", got, err)
	}
	if info, err := f.Stat(path); err != nil || info.Size() != 7 {
		t.Errorf("Stat() = %v, %v; want size 7", info, err)
	}
	entries, err := f.ReadDir(filepath.Join(home, ".claude"))
	if err != nil || len(entries) != 1 || entries[0].Name() != "settings.json" {
		t.Errorf("ReadDir() = %v, %v; want settings.json", entries, err)
	}
	r, err := f.Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() { _ = r.Close() }()
	if b, _ := io.ReadAll(r); string(b) != `{"a":1}` {
		t.Errorf("Open() read %q, want the file", b)
	}
}

func TestFakeHomeRefusesPathsOutsideIt(t *testing.T) {
	f, home := fakeFS(t)
	outside := filepath.Join(t.TempDir(), "real-config.json")
	write(t, outside, []byte("real"))

	for name, path := range map[string]string{
		"other absolute path": outside,
		"parent dir escape":   filepath.Join(home, "..", filepath.Base(filepath.Dir(outside)), "real-config.json"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := f.ReadFile(path); !errors.Is(err, ErrOutsideHome) {
				t.Errorf("ReadFile() error = %v, want ErrOutsideHome", err)
			}
			if _, err := f.Stat(path); !errors.Is(err, ErrOutsideHome) {
				t.Errorf("Stat() error = %v, want ErrOutsideHome", err)
			}
			if _, err := f.Open(path); !errors.Is(err, ErrOutsideHome) {
				t.Errorf("Open() error = %v, want ErrOutsideHome", err)
			}
			if _, err := f.ReadDir(filepath.Dir(path)); !errors.Is(err, ErrOutsideHome) {
				t.Errorf("ReadDir() error = %v, want ErrOutsideHome", err)
			}
			err := f.Walk(filepath.Dir(path), func(string, fs.DirEntry) error { return nil })
			if !errors.Is(err, ErrOutsideHome) {
				t.Errorf("Walk() error = %v, want ErrOutsideHome", err)
			}
		})
	}
}

func TestFakeHomeBlocksSymlinkEscape(t *testing.T) {
	f, home := fakeFS(t)
	outside := filepath.Join(t.TempDir(), "secret.txt")
	write(t, outside, []byte("real secret"))
	link := filepath.Join(home, "link.txt")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("can't make symlinks here: %v", err)
	}

	got, err := f.ReadFile(link)

	if err == nil {
		t.Fatalf("ReadFile() = %q, want an error for a symlink leaving the home", got)
	}
}

func TestRelativePathsAreRejected(t *testing.T) {
	f, _ := fakeFS(t)

	if _, err := f.ReadFile(filepath.Join(".claude", "settings.json")); !errors.Is(err, ErrNotAbsolute) {
		t.Errorf("ReadFile() error = %v, want ErrNotAbsolute", err)
	}
}

func TestRealMachineReadsAbsolutePaths(t *testing.T) {
	env, err := platform.Real()
	if err != nil {
		t.Fatal(err)
	}
	f, err := New(env)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = f.Close() }()
	// A temp file, never a real config.
	path := filepath.Join(t.TempDir(), "x.txt")
	write(t, path, []byte("hi"))

	if got, err := f.ReadFile(path); err != nil || string(got) != "hi" {
		t.Errorf("ReadFile() = %q, %v; want the file", got, err)
	}
}

func TestReadFileOverTheCapIsRecordedNotSilent(t *testing.T) {
	f, home := fakeFS(t)
	big := filepath.Join(home, "CLAUDE.md")
	write(t, big, bytes.Repeat([]byte("a"), MaxReadSize+1))
	small := filepath.Join(home, "AGENTS.md")
	write(t, small, []byte("ok"))

	_, err := f.ReadFile(big)
	_, _ = f.ReadFile(small)

	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("ReadFile() error = %v, want ErrTooLarge", err)
	}
	want := []Skip{{Path: big, Size: MaxReadSize + 1, Reason: "too large"}}
	if got := f.Skips(); !slices.Equal(got, want) {
		t.Errorf("Skips() = %+v, want %+v", got, want)
	}
}

func TestReadFileAtTheCapIsRead(t *testing.T) {
	f, home := fakeFS(t)
	path := filepath.Join(home, "CLAUDE.md")
	write(t, path, bytes.Repeat([]byte("a"), MaxReadSize))

	got, err := f.ReadFile(path)

	if err != nil || len(got) != MaxReadSize {
		t.Errorf("ReadFile() = %d bytes, %v; want %d bytes", len(got), err, MaxReadSize)
	}
	if skips := f.Skips(); len(skips) != 0 {
		t.Errorf("Skips() = %+v, want none", skips)
	}
}

func TestWalkSkipsBulkDirsButKeepsAgentFiles(t *testing.T) {
	f, home := fakeFS(t)
	repo := filepath.Join(home, "repo")
	for _, rel := range []string{
		"main.go",
		"src/app.go",
		"node_modules/pkg/index.js",
		"node_modules/pkg/CLAUDE.md",
		"node_modules/pkg/AGENTS.md",
		"node_modules/pkg/.claude/settings.json",
		"vendor/x/.mcp.json",
		"build/.codex/config.toml",
		"dist/.agents/skills/s/SKILL.md",
		".venv/lib/claude.md",
		"target/AGENTS.override.md",
		"out/CLAUDE.local.md",
		".git/config",
		".git/hooks/CLAUDE.md",
		"__pycache__/x.pyc",
	} {
		write(t, filepath.Join(repo, filepath.FromSlash(rel)), []byte("x"))
	}

	var got []string
	err := f.Walk(repo, func(path string, _ fs.DirEntry) error {
		rel, _ := filepath.Rel(repo, path)
		got = append(got, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		t.Fatalf("Walk() error = %v", err)
	}

	want := []string{
		".git/hooks/CLAUDE.md",
		".venv/lib/claude.md",
		"build/.codex/config.toml",
		"dist/.agents/skills/s/SKILL.md",
		"main.go",
		"node_modules/pkg/.claude/settings.json",
		"node_modules/pkg/AGENTS.md",
		"node_modules/pkg/CLAUDE.md",
		"out/CLAUDE.local.md",
		"src/app.go",
		"target/AGENTS.override.md",
		"vendor/x/.mcp.json",
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("Walk() yielded\n  %s\nwant\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
}

func TestWalkDoesNotFollowSymlinkedDirs(t *testing.T) {
	realEnv, err := platform.Real()
	if err != nil {
		t.Fatal(err)
	}
	modes := map[string]func(t *testing.T) (*FS, string){
		"fake home": fakeFS,
		// Real mode over a temp dir, never a real config. Here nothing but
		// Walk itself stops a symlinked dir from being followed.
		"real machine": func(t *testing.T) (*FS, string) {
			t.Helper()
			f, err := New(realEnv)
			if err != nil {
				t.Fatal(err)
			}
			return f, t.TempDir()
		},
	}
	for name, newFS := range modes {
		t.Run(name, func(t *testing.T) {
			f, base := newFS(t)
			repo := filepath.Join(base, "repo")
			write(t, filepath.Join(base, "elsewhere", "CLAUDE.md"), []byte("x"))
			write(t, filepath.Join(repo, "main.go"), []byte("x"))
			// A relative target, so os.Root allows the link and only Walk
			// decides whether to follow it.
			if err := os.Symlink(filepath.Join("..", "elsewhere"), filepath.Join(repo, "linked")); err != nil {
				t.Skipf("can't make symlinks here: %v", err)
			}

			var got []string
			if err := f.Walk(repo, func(path string, _ fs.DirEntry) error {
				got = append(got, filepath.Base(path))
				return nil
			}); err != nil {
				t.Fatalf("Walk() error = %v", err)
			}

			// The link itself is yielded (agents read through symlinked
			// files, like AGENTS.md -> CLAUDE.md), but Walk never descends
			// into it, so elsewhere/CLAUDE.md must not show up.
			slices.Sort(got)
			if !slices.Equal(got, []string{"linked", "main.go"}) {
				t.Errorf("Walk() yielded %q, want [linked main.go]: the link but nothing behind it", got)
			}
		})
	}
}

func TestSkipped(t *testing.T) {
	tests := map[string]bool{
		"src/app.go":                      false,
		"README.md":                       false,
		"node_modules":                    true,
		"node_modules/pkg/index.js":       true,
		"a/b/vendor/x.go":                 true,
		".git/config":                     true,
		"node_modules/pkg/CLAUDE.md":      false,
		"node_modules/pkg/agents.md":      false,
		"vendor/x/.mcp.json":              false,
		"build/.claude/settings.json":     false,
		"dist/.codex/config.toml":         false,
		".venv/.agents/skills/s/SKILL.md": false,
		"node_modules/.claude":            false,
	}
	for rel, want := range tests {
		if got := Skipped(rel); got != want {
			t.Errorf("Skipped(%q) = %v, want %v", rel, got, want)
		}
	}
}

func TestASkippedFileIsRecordedOnce(t *testing.T) {
	f, home := fakeFS(t)
	big := filepath.Join(home, "big.json")
	write(t, big, make([]byte, MaxReadSize+1))

	for range 3 {
		if _, err := f.ReadFile(big); !errors.Is(err, ErrTooLarge) {
			t.Fatalf("ReadFile() error = %v, want ErrTooLarge", err)
		}
	}

	if got := f.Skips(); len(got) != 1 {
		t.Errorf("skips = %+v, want the file once", got)
	}
}
