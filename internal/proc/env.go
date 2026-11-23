package proc

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/nickelsec/jarx/internal/fsys"
	"github.com/nickelsec/jarx/internal/platform"
)

const goosWindows = "windows"

// baseline is the env a server gets from jarx's own env so launchers like
// npx and uvx work: where programs and home are, temp dirs, and what
// Windows needs to start a program at all. Nothing else from jarx's env
// goes along, so a token in it can't reach a server that didn't ask for it.
//
//nolint:gochecknoglobals // fixed list, read only
var baseline = []string{
	"PATH", "PATHEXT", "HOME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH",
	"SystemRoot", "SystemDrive", "WINDIR", "ComSpec",
	"TEMP", "TMP", "TMPDIR", "APPDATA", "LOCALAPPDATA", "ProgramData", "ProgramFiles",
	"LANG", "USER", "LOGNAME",
}

// Env is the env a server starts with: the baseline from env, then the
// vars its config declares, which win over the baseline. Names match
// without case on Windows, as the OS does.
func Env(env platform.Env, declared [][2]string) []string {
	same := func(a, b string) bool {
		if env.GOOS == goosWindows {
			return strings.EqualFold(a, b)
		}
		return a == b
	}
	out := make([]string, 0, len(baseline)+len(declared))
	for _, name := range baseline {
		if slices.ContainsFunc(declared, func(d [2]string) bool { return same(d[0], name) }) {
			continue
		}
		if v, ok := env.Lookup(name); ok {
			out = append(out, name+"="+v)
		}
	}
	for _, d := range declared {
		out = append(out, d[0]+"="+d[1])
	}
	return out
}

// defaultPathExt is what Windows uses when PATHEXT isn't set.
const defaultPathExt = ".COM;.EXE;.BAT;.CMD"

// Find resolves a server's command the way a shell would, on env's PATH and
// through fsys. Under --home it finds nothing: the demo and tests never
// start a program from a fake PATH.
func Find(f *fsys.FS, env platform.Env, name string) (string, error) {
	if env.Fake() {
		return "", ErrFakeHome
	}
	ext, ok := env.Lookup("PATHEXT")
	if !ok || ext == "" {
		ext = defaultPathExt
	}
	return find(f, env.GOOS, env.Path, ext, name)
}

// find looks for name in each dir of path. A name with a dir in it must be
// absolute and is checked as it is. On Windows a name without one of
// pathext's extensions gets each in turn; on unix the file needs an exec
// bit.
func find(f *fsys.FS, goos string, path []string, pathext, name string) (string, error) {
	var exts []string
	if goos == goosWindows {
		exts = strings.Split(strings.ToLower(pathext), ";")
	}
	if strings.ContainsAny(name, `/\`) {
		if !filepath.IsAbs(name) {
			return "", fmt.Errorf("%s: a relative path has to be resolved against the server's dir first: %w", name, ErrNotFound)
		}
		if p, ok := runnable(f, goos, exts, name); ok {
			return p, nil
		}
		return "", fmt.Errorf("%s: %w", name, ErrNotFound)
	}
	for _, dir := range path {
		if p, ok := runnable(f, goos, exts, filepath.Join(dir, name)); ok {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s: %w", name, ErrNotFound)
}

// runnable checks one candidate, trying each extension on Windows when the
// name has none of them.
func runnable(f *fsys.FS, goos string, exts []string, p string) (string, bool) {
	cands := []string{p}
	if goos == goosWindows && !slices.Contains(exts, strings.ToLower(filepath.Ext(p))) {
		cands = cands[:0]
		for _, e := range exts {
			if e != "" {
				cands = append(cands, p+e)
			}
		}
	}
	for _, c := range cands {
		info, err := f.Stat(c)
		if err != nil || info.IsDir() {
			continue
		}
		if goos != goosWindows && info.Mode().Perm()&0o111 == 0 {
			continue
		}
		return c, true
	}
	return "", false
}
