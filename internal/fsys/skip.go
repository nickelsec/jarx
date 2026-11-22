package fsys

import (
	"path"
	"strings"
)

// skipDirs are bulk dirs that hold dependencies, build output or git data.
// Walking them in full would be slow and mostly noise.
var skipDirs = []string{ //nolint:gochecknoglobals // fixed list, read only
	".git", ".next", ".venv", "__pycache__", "build", "dist",
	"node_modules", "out", "target", "vendor", "venv",
}

// agentDirs and agentFiles are what the agents read. They're never skipped,
// even inside a skip dir: a package in node_modules can ship its own
// CLAUDE.md or .claude/ dir.
var (
	agentDirs  = []string{".agents", ".claude", ".codex"} //nolint:gochecknoglobals // fixed list, read only
	agentFiles = []string{                                //nolint:gochecknoglobals // fixed list, read only
		".mcp.json", "AGENTS.md", "AGENTS.override.md", "CLAUDE.md", "CLAUDE.local.md",
	}
)

// Skipped reports whether rel (slash-separated, relative to a repo root) is
// inside a skip dir and isn't an agent file. Names match ignoring case.
func Skipped(rel string) bool {
	parts := strings.Split(path.Clean(rel), "/")
	inSkipDir := false
	for _, p := range parts {
		if matchAny(p, agentDirs) {
			return false
		}
		if matchAny(p, skipDirs) {
			inSkipDir = true
		}
	}
	if !inSkipDir {
		return false
	}
	return !matchAny(parts[len(parts)-1], agentFiles)
}

func matchAny(name string, list []string) bool {
	for _, s := range list {
		if strings.EqualFold(name, s) {
			return true
		}
	}
	return false
}
