package fsys

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestDBPathGivesAPathInsideTheHome(t *testing.T) {
	f, home := fakeFS(t)
	db := filepath.Join(home, ".codex", "state_5.sqlite")
	write(t, db, []byte("SQLite format 3\x00"))

	got, err := f.DBPath(db)
	if err != nil {
		t.Fatalf("DBPath() error = %v", err)
	}
	if got != db {
		t.Errorf("DBPath() = %q, want %q", got, db)
	}
}

func TestDBPathRefusesWhatAReadWould(t *testing.T) {
	f, home := fakeFS(t)
	outside := filepath.Join(t.TempDir(), "state_5.sqlite")
	write(t, outside, []byte("SQLite format 3\x00"))
	creds := filepath.Join(home, ".aws", "credentials")
	write(t, creds, []byte("[default]\n"))
	dir := filepath.Join(home, ".codex", "dir.sqlite")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}

	for name, tc := range map[string]struct {
		path string
		want error
	}{
		"outside the home": {outside, ErrOutsideHome},
		"a credential":     {creds, ErrCredential},
		"not a file":       {dir, ErrNotRegular},
	} {
		if _, err := f.DBPath(tc.path); !errors.Is(err, tc.want) {
			t.Errorf("%s: DBPath() error = %v, want %v", name, err, tc.want)
		}
	}
}

func TestDBPathChecksTheFilesSQLiteOpensNextToIt(t *testing.T) {
	f, home := fakeFS(t)
	db := filepath.Join(home, ".codex", "state_5.sqlite")
	write(t, db, []byte("SQLite format 3\x00"))
	// A planted -wal that links out of the home: SQLite would open it.
	outside := filepath.Join(t.TempDir(), "elsewhere")
	write(t, outside, []byte("x"))
	makeLink(t, outside, db+"-wal", false)

	if _, err := f.DBPath(db); err == nil {
		t.Error("DBPath() worked, want the -wal link out of the home refused")
	}
}

func TestDBPathFollowsALinkToItsEnd(t *testing.T) {
	f, home := fakeFS(t)
	target := filepath.Join(home, ".codex", "real.sqlite")
	write(t, target, []byte("SQLite format 3\x00"))
	link := filepath.Join(home, ".codex", "state_5.sqlite")
	makeLink(t, target, link, false)

	got, err := f.DBPath(link)
	if err != nil || got != target {
		t.Errorf("DBPath() = %q, %v, want %q: the driver gets the checked end of the link", got, err, target)
	}
}
