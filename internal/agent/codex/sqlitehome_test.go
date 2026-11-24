package codex

import (
	"path/filepath"
	"testing"
)

func TestSQLiteHomeDefaultsToCodexHome(t *testing.T) {
	c := fakeHome(t, map[string]string{".codex/config.toml": "model = \"x\"\n"})

	if got, want := (Adapter{}).SQLiteHome(c), filepath.Join(c.Env.Home, ".codex"); got != want {
		t.Errorf("SQLiteHome() = %q, want %q", got, want)
	}
}

func TestSQLiteHomeComesFromTheUserConfig(t *testing.T) {
	c := fakeHome(t, map[string]string{".codex/config.toml": "sqlite_home = \"/dbs\"\n"})

	// A path from config maps into the fake home, like every agent record.
	if got, want := (Adapter{}).SQLiteHome(c), filepath.Join(c.Env.Home, "dbs"); got != want {
		t.Errorf("SQLiteHome() = %q, want %q", got, want)
	}
}
