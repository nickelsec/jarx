package fsys

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadlinkGivesALinksTargetWithoutFollowingIt(t *testing.T) {
	f, home := fakeFS(t)
	versions := filepath.Join(home, ".local", "share", "claude", "versions")
	write(t, filepath.Join(versions, "2.1.200"), []byte("binary"))
	link := filepath.Join(home, ".local", "bin", "claude")
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	makeLink(t, filepath.Join(versions, "2.1.200"), link, false)

	info, err := f.Lstat(link)
	if err != nil {
		t.Fatalf("Lstat() error = %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Errorf("Lstat() mode = %v, want a symlink", info.Mode())
	}
	got, err := f.Readlink(link)
	if err != nil {
		t.Fatalf("Readlink() error = %v", err)
	}
	if filepath.Base(got) != "2.1.200" {
		t.Errorf("Readlink() = %q, want the version file it points to", got)
	}
}

func TestReadlinkStaysInsideTheFakeHome(t *testing.T) {
	f, _ := fakeFS(t)

	if _, err := f.Readlink(filepath.Join(t.TempDir(), "claude")); err == nil {
		t.Error("Readlink() outside the fake home worked, want ErrOutsideHome")
	}
	if _, err := f.Lstat(filepath.Join(t.TempDir(), "claude")); err == nil {
		t.Error("Lstat() outside the fake home worked, want ErrOutsideHome")
	}
}
