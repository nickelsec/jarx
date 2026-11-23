package fsys

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/nickelsec/jarx/internal/platform"
)

const fakeKey = "-----BEGIN OPENSSH PRIVATE KEY----- made up for tests"

func TestCredentialFilesAreNeverRead(t *testing.T) {
	f, home := fakeFS(t)
	key := filepath.Join(home, ".ssh", "id_ed25519")
	env := filepath.Join(home, "proj", ".env")
	write(t, key, []byte(fakeKey))
	write(t, env, []byte("TOKEN=made-up"))

	for _, p := range []string{key, env} {
		if _, err := f.ReadFile(p); !errors.Is(err, ErrCredential) {
			t.Errorf("ReadFile(%s) error = %v, want ErrCredential", p, err)
		}
		if _, err := f.Open(p); !errors.Is(err, ErrCredential) {
			t.Errorf("Open(%s) error = %v, want ErrCredential", p, err)
		}
		if _, err := f.Stat(p); err != nil {
			t.Errorf("Stat(%s) error = %v, want existence checks to still work", p, err)
		}
	}
}

func TestSymlinksToCredentialFilesAreNeverRead(t *testing.T) {
	f, home := fakeFS(t)
	write(t, filepath.Join(home, ".ssh", "id_ed25519"), []byte(fakeKey))
	write(t, filepath.Join(home, "proj", ".env"), []byte("TOKEN=made-up"))
	links := map[string]string{
		filepath.Join(home, "proj", "CLAUDE.md"):                     filepath.Join("..", ".ssh", "id_ed25519"),
		filepath.Join(home, "proj", ".claude", "rules", "shared.md"): filepath.Join("..", "..", ".env"),
		filepath.Join(home, "proj", "linkdir"):                       filepath.Join("..", ".ssh"),
	}
	for link, to := range links {
		if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(to, link); err != nil {
			t.Skipf("can't make symlinks here: %v", err)
		}
	}
	paths := []string{
		filepath.Join(home, "proj", "CLAUDE.md"),
		filepath.Join(home, "proj", ".claude", "rules", "shared.md"),
		filepath.Join(home, "proj", "linkdir", "id_ed25519"),
	}

	for name, fs := range map[string]*FS{"fake home": f, "real machine": {}} {
		for _, p := range paths {
			if _, err := fs.ReadFile(p); !errors.Is(err, ErrCredential) {
				t.Errorf("%s: ReadFile(%s) error = %v, want ErrCredential", name, p, err)
			}
		}
	}
}

func TestTheGuardKnowsTheHome(t *testing.T) {
	home := t.TempDir()
	write(t, filepath.Join(home, ".aws", "credentials"), []byte("[default]"))
	env, err := platform.FromHome(home)
	if err != nil {
		t.Fatal(err)
	}
	f, err := New(env)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })

	if _, err := f.ReadFile(filepath.Join(home, ".aws", "credentials")); !errors.Is(err, ErrCredential) {
		t.Errorf("ReadFile(~/.aws/credentials) error = %v, want ErrCredential", err)
	}
}

func TestOrdinaryFilesStillRead(t *testing.T) {
	f, home := fakeFS(t)
	p := filepath.Join(home, "proj", "CLAUDE.md")
	write(t, p, []byte("# hi"))

	if got, err := f.ReadFile(p); err != nil || string(got) != "# hi" {
		t.Errorf("ReadFile() = %q, %v; want the file", got, err)
	}
}
