// Package fsys is the only way jarx reads files. It has no write methods.
//
// On the real machine it reads absolute paths anywhere. Under --home every
// read is confined to the fake home with os.Root, so a fixture that points at
// a real path, a ".." trick or a symlink can't reach the real machine.
//
// ReadFile refuses files over MaxReadSize and records each one, so a skipped
// file always shows up (as a finding, once findings exist) and is never
// silently dropped.
package fsys

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"

	"github.com/nickelsec/jarx/internal/platform"
)

// MaxReadSize is the most ReadFile reads from one file: 10 MiB. Config and
// instruction files are far smaller. Big streams like history use Open.
const MaxReadSize = 10 << 20

var (
	// ErrTooLarge means ReadFile refused a file over MaxReadSize.
	ErrTooLarge = errors.New("skipped, too large")
	// ErrOutsideHome means a --home read pointed outside the fake home.
	ErrOutsideHome = errors.New("outside the fake home")
	// ErrNotAbsolute means a path was relative. Every path must be absolute
	// so reads never depend on the working directory.
	ErrNotAbsolute = errors.New("not an absolute path")
)

// Skip is a file jarx refused to read.
type Skip struct {
	Path   string
	Size   int64
	Reason string
}

// FS reads files. Use New to build one.
type FS struct {
	home string       // fake home, "" on the real machine
	root *os.Root     // open on home under --home, nil on the real machine
	env  platform.Env // for credmeta.Location, which needs the home and config dirs

	mu    sync.Mutex
	skips []Skip
}

// New returns an FS for env. Under --home it's confined to env.Home.
func New(env platform.Env) (*FS, error) {
	if !env.Fake() {
		return &FS{env: env}, nil
	}
	root, err := os.OpenRoot(env.Home)
	if err != nil {
		return nil, fmt.Errorf("opening fake home: %w", err)
	}
	return &FS{home: env.Home, root: root, env: env}, nil
}

// Close releases the fake home root.
func (f *FS) Close() error {
	if f.root == nil {
		return nil
	}
	if err := f.root.Close(); err != nil {
		return fmt.Errorf("closing fake home: %w", err)
	}
	return nil
}

// Skips returns every file ReadFile refused, in order.
func (f *FS) Skips() []Skip {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Skip(nil), f.skips...)
}

// Stat returns the file info for path.
func (f *FS) Stat(path string) (fs.FileInfo, error) {
	rel, err := f.resolve(path)
	if err != nil {
		return nil, err
	}
	var info fs.FileInfo
	if f.root != nil {
		info, err = f.root.Stat(rel)
	} else {
		info, err = os.Stat(path)
	}
	if err != nil {
		return nil, fmt.Errorf("stat: %w", err)
	}
	return info, nil
}

// Open opens path for streaming. It has no size cap. Only plain files open.
func (f *FS) Open(path string) (io.ReadCloser, error) {
	file, err := f.openFile(path)
	if err != nil {
		return nil, err
	}
	return file, nil
}

// ReadFile reads path. A file over MaxReadSize is refused with ErrTooLarge
// and recorded in Skips. Only plain files are read.
func (f *FS) ReadFile(path string) ([]byte, error) {
	file, err := f.openFile(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat: %w", err)
	}
	if info.Size() > MaxReadSize {
		return nil, f.tooLarge(path, info.Size())
	}
	// Read one byte past the cap in case the file grew since the stat.
	data, err := io.ReadAll(io.LimitReader(file, MaxReadSize+1))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	if len(data) > MaxReadSize {
		return nil, f.tooLarge(path, int64(len(data)))
	}
	return data, nil
}

// ReadDir lists the dir at path.
func (f *FS) ReadDir(path string) ([]fs.DirEntry, error) {
	dir, err := f.open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = dir.Close() }()
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return nil, fmt.Errorf("listing %s: %w", path, err)
	}
	return entries, nil
}

// Walk calls fn for every file under root, with its absolute path. A symlink
// is yielded as an entry but never descended into, so a symlinked dir can't
// pull in files from elsewhere. Inside the dirs on the skip list it only
// yields agent files (see Skipped).
func (f *FS) Walk(root string, fn func(path string, d fs.DirEntry) error) error {
	rel, err := f.resolve(root)
	if err != nil {
		return err
	}
	fsys, start := f.walkFS(root, rel)
	err = fs.WalkDir(fsys, start, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		inRoot, _ := strings.CutPrefix(p, start+"/")
		if start == "." {
			inRoot = p
		}
		if Skipped(inRoot) {
			return nil
		}
		return fn(filepath.Join(root, filepath.FromSlash(inRoot)), d)
	})
	if err != nil {
		return fmt.Errorf("walking %s: %w", root, err)
	}
	return nil
}

// walkFS returns the fs.FS to walk and the start path inside it.
func (f *FS) walkFS(root, rel string) (fs.FS, string) {
	if f.root != nil {
		return f.root.FS(), filepath.ToSlash(rel)
	}
	return os.DirFS(root), "."
}

// openFile opens a plain file. It stats first, so a FIFO or device is refused
// before an open could block on it, and checks again after, in case the path
// changed in between.
func (f *FS) openFile(path string) (*os.File, error) {
	if err := f.guard(path); err != nil {
		return nil, err
	}
	return f.openPlain(path)
}

// openPlain is openFile without the credential guard. Only CredentialFacts
// uses it, and it hands the file to credmeta's parsers, never to a caller.
func (f *FS) openPlain(path string) (*os.File, error) {
	info, err := f.Stat(path)
	if err != nil {
		return nil, err
	}
	if err := regular(path, info); err != nil {
		return nil, err
	}
	file, err := f.open(path)
	if err != nil {
		return nil, err
	}
	info, err = file.Stat()
	if err == nil {
		err = regular(path, info)
	}
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func (f *FS) open(path string) (*os.File, error) {
	rel, err := f.resolve(path)
	if err != nil {
		return nil, err
	}
	var file *os.File
	if f.root != nil {
		file, err = f.root.Open(rel)
	} else {
		// Reading any path is the point on the real machine. --home goes
		// through the root above instead.
		file, err = os.Open(path) //nolint:gosec // G304: arbitrary reads are by design here
	}
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	return file, nil
}

// resolve checks path and, under --home, returns it relative to the home.
func (f *FS) resolve(path string) (string, error) {
	if networkPath(runtime.GOOS, path) {
		return "", fmt.Errorf("%s: %w", path, ErrNetworkPath)
	}
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("%s: %w", path, ErrNotAbsolute)
	}
	if f.root == nil {
		// The real machine follows symlinks, so check where they lead first.
		// Under --home, os.Root keeps every link inside the fake home.
		if _, err := resolveLinks(runtime.GOOS, osLinks{}, path); err != nil {
			return "", err
		}
		return path, nil
	}
	rel, err := filepath.Rel(f.home, filepath.Clean(path))
	if err != nil || !filepath.IsLocal(rel) && rel != "." {
		return "", fmt.Errorf("%s: %w", path, ErrOutsideHome)
	}
	return rel, nil
}

// tooLarge records a refused file, once per path however often it's read.
func (f *FS) tooLarge(path string, size int64) error {
	f.mu.Lock()
	if !slices.ContainsFunc(f.skips, func(s Skip) bool { return s.Path == path }) {
		f.skips = append(f.skips, Skip{Path: path, Size: size, Reason: "too large"})
	}
	f.mu.Unlock()
	return fmt.Errorf("%s (%d bytes, cap %d): %w", path, size, MaxReadSize, ErrTooLarge)
}
