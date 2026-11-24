package discover

import (
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/nickelsec/jarx/internal/agent"
	"github.com/nickelsec/jarx/internal/model"
)

// installs asks every adapter where its agent is installed, then marks the
// install whose command comes first on PATH. A command on PATH that no
// install claims is an install of its own, at an unknown place. Nothing is
// run: PATH is only looked at.
func installs(c agent.Context, adapters []agent.Adapter) []model.Install {
	var out []model.Install
	for _, a := range adapters {
		r, ok := a.(agent.InstallReader)
		if !ok {
			continue
		}
		ins := r.Installs(c)
		if cmd, found := firstOnPath(c, r.Command()); found {
			ins = markWinner(c, a.Agent(), ins, cmd)
		}
		out = append(out, ins...)
	}
	return out
}

func markWinner(c agent.Context, a model.Agent, ins []model.Install, cmd string) []model.Install {
	dir := filepath.Dir(cmd)
	for i := range ins {
		if sameDir(c.Env.GOOS, ins[i].BinDir.Raw(), dir) {
			ins[i].OnPath = true
			return ins
		}
	}
	from, _ := c.Scrub.Scrub("not at an install location the docs name")
	return append(ins, model.Install{
		Agent: a, Method: model.InstallUnknown, Path: model.NewPath(c.Scrub, cmd), BinDir: model.NewPath(c.Scrub, dir),
		VersionFrom: from, OnPath: true,
	})
}

func sameDir(goos, a, b string) bool {
	a, b = filepath.Clean(a), filepath.Clean(b)
	if goos == goosWindows {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// firstOnPath is the file a shell would run for name: the first PATH dir
// that holds it, trying PATHEXT's extensions in order on Windows. Relative
// PATH entries are skipped, as are dirs fsys won't look in.
func firstOnPath(c agent.Context, name string) (string, bool) {
	names := []string{name}
	if c.Env.GOOS == goosWindows {
		names = names[:0]
		for _, ext := range pathExts(c) {
			names = append(names, name+ext)
		}
	}
	for _, dir := range c.Env.Path {
		if !filepath.IsAbs(dir) {
			continue
		}
		for _, n := range names {
			p := filepath.Join(dir, n)
			if info, err := c.Files.Stat(p); err == nil && runnable(c.Env.GOOS, info) {
				return p, true
			}
		}
	}
	return "", false
}

// runnable is a plain file, executable by someone on Unix.
func runnable(goos string, info fs.FileInfo) bool {
	if !info.Mode().IsRegular() {
		return false
	}
	return goos == goosWindows || info.Mode().Perm()&0o111 != 0
}

// pathExts is PATHEXT, or cmd's default list when it isn't set.
func pathExts(c agent.Context) []string {
	v, ok := c.Env.Lookup("PATHEXT")
	if !ok || v == "" {
		v = ".COM;.EXE;.BAT;.CMD"
	}
	var out []string
	for ext := range strings.SplitSeq(v, ";") {
		if ext = strings.TrimSpace(ext); strings.HasPrefix(ext, ".") {
			out = append(out, strings.ToLower(ext))
		}
	}
	return out
}
