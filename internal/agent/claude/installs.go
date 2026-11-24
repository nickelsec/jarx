package claude

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"

	"github.com/nickelsec/jarx/internal/agent"
	"github.com/nickelsec/jarx/internal/model"
)

// Command is Claude Code's command name.
func (Adapter) Command() string { return "claude" }

// Installs finds Claude Code's installs at the places the setup docs name
// (code.claude.com/docs/en/setup): the native installer's launcher in
// ~/.local/bin (claude.exe on Windows) and its versions in
// ~/.local/share/claude/versions, and the npm package
// @anthropic-ai/claude-code, which installs the same native binary. On
// macOS and Linux the docs say the launcher is a symlink into the versions
// dir, so the link names the version. Homebrew, WinGet and the Linux
// package managers are supported too, but the docs don't say where they put
// it, so jarx doesn't guess: those show up through PATH instead.
func (Adapter) Installs(c agent.Context) []model.Install {
	var out []model.Install
	if in, ok := nativeInstall(c); ok {
		out = append(out, in)
	}
	return append(out, agent.NPMInstalls(c, model.AgentClaude, "@anthropic-ai/claude-code")...)
}

func nativeInstall(c agent.Context) (model.Install, bool) {
	bin := filepath.Join(c.Env.Home, ".local", "bin")
	launcher := filepath.Join(bin, "claude")
	if c.Env.GOOS == "windows" {
		launcher += ".exe"
	}
	versionsDir := filepath.Join(c.Env.Home, ".local", "share", "claude", "versions")
	var versions []string
	if entries, err := c.Files.ReadDir(versionsDir); err == nil {
		for _, e := range entries {
			versions = append(versions, e.Name())
		}
		slices.Sort(versions)
	}
	info, err := c.Files.Lstat(launcher)
	if err != nil && len(versions) == 0 {
		return model.Install{}, false
	}
	in := model.Install{Agent: model.AgentClaude, Method: model.InstallNative, Path: model.NewPath(c.Scrub, launcher), BinDir: model.NewPath(c.Scrub, bin)}
	if err != nil {
		in.Path = model.NewPath(c.Scrub, versionsDir)
	}
	version, from := nativeVersion(c, launcher, info, versions)
	in.Version, in.VersionFrom = c.Text(version), c.Text(from)
	return in, true
}

// nativeVersion is the version the launcher runs, and how jarx knows.
func nativeVersion(c agent.Context, launcher string, info fs.FileInfo, versions []string) (string, string) {
	if info != nil && info.Mode()&fs.ModeSymlink != 0 {
		target, err := c.Files.Readlink(launcher)
		if err == nil && filepath.Base(filepath.Dir(target)) == "versions" {
			return filepath.Base(target), "launcher link"
		}
		return "", "the launcher links outside the versions dir"
	}
	switch len(versions) {
	case 0:
		return "", "no versions dir"
	case 1:
		return versions[0], "only installed version"
	}
	return "", fmt.Sprintf("%d versions, and the launcher isn't a link to one", len(versions))
}
