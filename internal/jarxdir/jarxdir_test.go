package jarxdir

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/nickelsec/jarx/internal/platform"
)

func openDir(t *testing.T) (*Dir, platform.Env) {
	t.Helper()
	env, err := platform.FromHome(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	d, err := Open(env)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d, env
}

func TestOpenCreatesTheStateDir(t *testing.T) {
	_, env := openDir(t)

	info, err := os.Stat(env.StateDir)
	if err != nil || !info.IsDir() {
		t.Fatalf("state dir %s: %v, want a dir", env.StateDir, err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 {
		t.Errorf("state dir mode = %v, want 0700", info.Mode().Perm())
	}
}

func TestWriteThenReadBack(t *testing.T) {
	d, _ := openDir(t)

	if err := d.WriteFile("config", []byte("v1")); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := d.WriteFile("config", []byte("v2")); err != nil {
		t.Fatalf("WriteFile() overwrite error = %v", err)
	}

	got, err := d.ReadFile("config")
	if err != nil || string(got) != "v2" {
		t.Errorf("ReadFile() = %q, %v; want v2", got, err)
	}
}

func TestWriteCreatesParentDirsAndLeavesNoTempFiles(t *testing.T) {
	d, env := openDir(t)

	if err := d.WriteFile("snapshots/1.json", []byte("{}")); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	entries, err := d.ReadDir("snapshots")
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "1.json" {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("snapshots/ holds %q, want only 1.json", names)
	}
	info, err := os.Stat(filepath.Join(env.StateDir, "snapshots", "1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Errorf("file mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestRemove(t *testing.T) {
	d, _ := openDir(t)
	if err := d.WriteFile("old.json", []byte("x")); err != nil {
		t.Fatal(err)
	}

	if err := d.Remove("old.json"); err != nil {
		t.Fatalf("Remove() error = %v", err)
	}
	if _, err := d.ReadFile("old.json"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("ReadFile() after Remove error = %v, want not exist", err)
	}
}

func TestNamesMustStayInsideTheStateDir(t *testing.T) {
	d, env := openDir(t)
	outside := filepath.Join(filepath.Dir(env.StateDir), "escaped")

	for name, bad := range map[string]string{
		"parent dir": "../escaped",
		"absolute":   outside,
		"empty":      "",
	} {
		t.Run(name, func(t *testing.T) {
			if err := d.WriteFile(bad, []byte("x")); err == nil {
				t.Errorf("WriteFile(%q) error = nil, want an error", bad)
			}
			if _, err := d.ReadFile(bad); err == nil {
				t.Errorf("ReadFile(%q) error = nil, want an error", bad)
			}
			if err := d.Remove(bad); err == nil {
				t.Errorf("Remove(%q) error = nil, want an error", bad)
			}
		})
	}
	if _, err := os.Stat(outside); !os.IsNotExist(err) {
		t.Errorf("%s exists, a write escaped the state dir", outside)
	}
}
