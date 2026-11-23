package fsys

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/nickelsec/jarx/internal/credmeta"
)

var (
	// ErrNetworkPath means a path, or a symlink on the way to it, names a
	// network location. Even looking one up can contact the host it names
	// (and on Windows, send it the user's NTLM hash), so jarx never touches
	// it. Claude Code refuses these too, per
	// code.claude.com/docs/en/memory#share-rules-across-projects-with-symlinks.
	ErrNetworkPath = errors.New("network path, not read")
	// ErrCredential means ReadFile or Open was pointed at a credential
	// location, directly or through a symlink. jarx never reads credential
	// values (credmeta.Location says what counts), so content reads refuse
	// them; Stat still works, for existence checks.
	ErrCredential = errors.New("credential file, not read")
	// ErrNotRegular means ReadFile or Open was pointed at something that
	// isn't a plain file: a dir, a FIFO, a device. Opening a FIFO would
	// block forever and a device could read without end.
	ErrNotRegular = errors.New("not a regular file")
)

// maxLinks caps how many symlinks one path may pass through, like the OS.
const maxLinks = 40

// networkPath says whether p names a network location on goos. It only looks
// at the text, so it never contacts anything.
func networkPath(goos, p string) bool {
	if goos != "windows" {
		return p == "/net" || strings.HasPrefix(p, "/net/") ||
			p == "/Network" || strings.HasPrefix(p, "/Network/")
	}
	p = strings.ToLower(strings.ReplaceAll(p, "/", `\`))
	if !strings.HasPrefix(p, `\\`) {
		return false
	}
	return windowsNetwork(p)
}

// windowsNetwork classifies a lowercased Windows path that starts with two
// backslashes.
func windowsNetwork(p string) bool {
	switch {
	case strings.HasPrefix(p, `\\?\unc\`):
		return true
	case strings.HasPrefix(p, `\\?\`):
		// \\?\C:\... is a long local path. Anything else in that namespace
		// (GLOBALROOT, volume GUIDs) is refused rather than guessed at.
		rest := p[len(`\\?\`):]
		return len(rest) < len("c:") || rest[1] != ':'
	case strings.HasPrefix(p, `\\.\`):
		return true // devices and pipes, never files to read
	case strings.HasPrefix(p, `\\wsl$\`), strings.HasPrefix(p, `\\wsl.localhost\`):
		return false // WSL's own share, which the docs say isn't a network path
	default:
		return true // \\host\share
	}
}

// linker reads links: the real machine, or an os.Root on the fake home.
type linker interface {
	Lstat(name string) (fs.FileInfo, error)
	Readlink(name string) (string, error)
}

type osLinks struct{}

func (osLinks) Lstat(name string) (fs.FileInfo, error) {
	info, err := os.Lstat(name)
	if err != nil {
		return nil, fmt.Errorf("lstat: %w", err)
	}
	return info, nil
}

func (osLinks) Readlink(name string) (string, error) {
	target, err := os.Readlink(name)
	if err != nil {
		return "", fmt.Errorf("readlink: %w", err)
	}
	return target, nil
}

// resolveLinks follows p one component at a time through every symlink and
// returns where it ends up. It refuses p if any link on the way points at a
// network path; each target is checked as text before anything looks it up.
// A part that doesn't exist ends the walk, and the real open reports it.
func resolveLinks(goos string, l linker, p string) (string, error) {
	for links := 0; ; links++ {
		if links > maxLinks {
			return "", fmt.Errorf("%s: too many symlinks", p)
		}
		next, done, err := stepLinks(goos, l, p)
		if err != nil {
			return "", err
		}
		if done {
			return p, nil
		}
		p = next
	}
}

// stepLinks walks p until it reaches the first symlink and returns the path
// with that link replaced by its target. done means there was no link left.
func stepLinks(goos string, l linker, p string) (string, bool, error) {
	vol := filepath.VolumeName(p)
	cur := ""
	if filepath.IsAbs(p) {
		cur = vol + string(filepath.Separator)
	}
	parts := strings.FieldsFunc(p[len(vol):], func(r rune) bool { return r == '/' || r == filepath.Separator })
	for i, part := range parts {
		here := filepath.Join(cur, part)
		info, err := l.Lstat(here)
		if err != nil {
			return "", true, nil //nolint:nilerr // missing: the real open reports it
		}
		if info.Mode()&fs.ModeSymlink == 0 {
			cur = here
			continue
		}
		target, err := linkTarget(goos, l, cur, here)
		if err != nil {
			return "", true, err
		}
		return filepath.Join(append([]string{target}, parts[i+1:]...)...), false, nil
	}
	return "", true, nil
}

// linkTarget reads the link at here, in dir, and returns where it points. A
// network target is refused before anything looks it up.
func linkTarget(goos string, l linker, dir, here string) (string, error) {
	target, err := l.Readlink(here)
	if err != nil {
		return "", fmt.Errorf("reading link %s: %w", here, err)
	}
	if !filepath.IsAbs(target) && filepath.VolumeName(target) == "" && !strings.HasPrefix(target, `\`) {
		target = filepath.Join(dir, target)
	}
	if networkPath(goos, target) {
		return "", fmt.Errorf("%s links to %s: %w", here, target, ErrNetworkPath)
	}
	return target, nil
}

// regular refuses anything that isn't a plain file.
func regular(path string, info fs.FileInfo) error {
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s: %w", path, ErrNotRegular)
	}
	return nil
}

// guard refuses a content read of a credential location, checking both the
// path as given and where its symlinks lead.
func (f *FS) guard(path string) error {
	final, err := f.finalPath(path)
	if err != nil {
		return err
	}
	for _, p := range []string{path, final} {
		if _, ok := credmeta.Location(f.env, p); ok {
			return fmt.Errorf("%s: %w", path, ErrCredential)
		}
	}
	return nil
}

// finalPath is where path ends up after every symlink.
func (f *FS) finalPath(path string) (string, error) {
	rel, err := f.resolve(path)
	if err != nil {
		return "", err
	}
	if f.root == nil {
		return resolveLinks(runtime.GOOS, osLinks{}, path)
	}
	end, err := resolveLinks(runtime.GOOS, f.root, rel)
	if err != nil {
		return "", err
	}
	if filepath.IsAbs(end) {
		return end, nil
	}
	return filepath.Join(f.home, end), nil
}
