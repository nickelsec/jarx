// Package jarxdir is the only way jarx writes files. Everything goes inside
// jarx's own state dir (platform.Env.StateDir), opened with os.Root so a name
// can't escape it. jarx never writes anywhere else, and never writes agent
// config.
package jarxdir

import (
	"crypto/rand"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/nickelsec/jarx/internal/platform"
)

const (
	dirMode  = 0o700
	fileMode = 0o600
)

// Dir is jarx's state dir. Names passed to its methods are slash or
// OS-separated paths relative to it.
type Dir struct {
	root *os.Root
}

// Open creates env.StateDir if needed and opens it.
func Open(env platform.Env) (*Dir, error) {
	if err := os.MkdirAll(env.StateDir, dirMode); err != nil {
		return nil, fmt.Errorf("creating state dir: %w", err)
	}
	root, err := os.OpenRoot(env.StateDir)
	if err != nil {
		return nil, fmt.Errorf("opening state dir: %w", err)
	}
	return &Dir{root: root}, nil
}

// Close releases the state dir.
func (d *Dir) Close() error {
	if err := d.root.Close(); err != nil {
		return fmt.Errorf("closing state dir: %w", err)
	}
	return nil
}

// ReadFile reads name.
func (d *Dir) ReadFile(name string) ([]byte, error) {
	if err := check(name); err != nil {
		return nil, err
	}
	data, err := d.root.ReadFile(name)
	if err != nil {
		return nil, fmt.Errorf("reading state: %w", err)
	}
	return data, nil
}

// WriteFile writes name atomically: it writes a temp file next to it, then
// renames it into place. Parent dirs are created as needed.
func (d *Dir) WriteFile(name string, data []byte) error {
	if err := check(name); err != nil {
		return err
	}
	if dir := filepath.Dir(name); dir != "." {
		if err := d.root.MkdirAll(dir, dirMode); err != nil {
			return fmt.Errorf("creating state dir %s: %w", dir, err)
		}
	}
	tmp := name + ".tmp-" + rand.Text()
	if err := d.root.WriteFile(tmp, data, fileMode); err != nil {
		return fmt.Errorf("writing state: %w", err)
	}
	if err := d.root.Rename(tmp, name); err != nil {
		_ = d.root.Remove(tmp)
		return fmt.Errorf("writing state: %w", err)
	}
	return nil
}

// ReadDir lists the dir name.
func (d *Dir) ReadDir(name string) ([]fs.DirEntry, error) {
	if err := check(name); err != nil {
		return nil, err
	}
	dir, err := d.root.Open(name)
	if err != nil {
		return nil, fmt.Errorf("listing state: %w", err)
	}
	defer func() { _ = dir.Close() }()
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return nil, fmt.Errorf("listing state: %w", err)
	}
	return entries, nil
}

// Remove deletes the file or empty dir name.
func (d *Dir) Remove(name string) error {
	if err := check(name); err != nil {
		return err
	}
	if err := d.root.Remove(name); err != nil {
		return fmt.Errorf("removing state: %w", err)
	}
	return nil
}

// check rejects names that aren't plain paths inside the state dir. os.Root
// blocks escapes too; this just gives a clear error first.
func check(name string) error {
	if !filepath.IsLocal(name) {
		return fmt.Errorf("state name %q must be a relative path inside the state dir", name)
	}
	return nil
}

// ReadState reads one state file without creating the state dir, so a scan
// that ends up saving nothing writes nothing. A missing dir or file is
// fs.ErrNotExist.
func ReadState(env platform.Env, name string) ([]byte, error) {
	if err := check(name); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(env.StateDir)
	if err != nil {
		return nil, fmt.Errorf("opening state dir: %w", err)
	}
	defer func() { _ = root.Close() }()
	data, err := root.ReadFile(name)
	if err != nil {
		return nil, fmt.Errorf("reading state: %w", err)
	}
	return data, nil
}
