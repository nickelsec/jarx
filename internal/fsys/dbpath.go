package fsys

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
)

// DBPath checks a SQLite file the way a read would be checked and returns
// the path to hand the driver: where its symlinks end. The driver opens
// the file itself, so this is how it stays inside fsys's rules: inside the
// fake home under --home, not a network path, not a credential location,
// and a regular file. SQLite also opens <db>-wal and <db>-shm next to it,
// so each of those that exists gets the same checks.
//
// Only internal/history opens SQLite, read-only (see .golangci.yml).
func (f *FS) DBPath(path string) (string, error) {
	if err := f.guard(path); err != nil {
		return "", err
	}
	final, err := f.contained(path)
	if err != nil {
		return "", err
	}
	info, err := f.Stat(final)
	if err != nil {
		return "", err
	}
	if err := regular(path, info); err != nil {
		return "", err
	}
	for _, side := range []string{final + "-wal", final + "-shm", final + "-journal"} {
		if _, err := f.Lstat(side); errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err := f.guard(side); err != nil {
			return "", fmt.Errorf("%s: %w", side, err)
		}
		if _, err := f.contained(side); err != nil {
			return "", fmt.Errorf("%s: %w", side, err)
		}
	}
	return final, nil
}

// contained is where path's links end, which under --home has to be inside
// the fake home. os.Root keeps fsys's own reads in; a driver that opens the
// file itself needs this check instead.
func (f *FS) contained(path string) (string, error) {
	final, err := f.finalPath(path)
	if err != nil {
		return "", err
	}
	if f.root != nil {
		if rel, err := filepath.Rel(f.home, filepath.Clean(final)); err != nil || !filepath.IsLocal(rel) {
			return "", fmt.Errorf("%s: %w", path, ErrOutsideHome)
		}
	}
	return final, nil
}
