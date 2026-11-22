// Package platform is the one place jarx learns about the machine it runs on:
// the home dir, the OS, the env, PATH, jarx's own state dir and the system
// roots. Everything else gets an Env passed in, so tests and --home never
// touch the real machine.
//
// platform knows OS facts only. Agent paths (like ~/.claude or /etc/codex)
// belong to the adapters, which join them onto Home and SystemRoots.
package platform

import (
	"strings"
)

// StateDirName is jarx's state dir inside a fake home (--home). The repo's
// .gitignore ignores it under testdata, so demo runs never dirty the tree.
const StateDirName = ".jarx-state"

const goosWindows = "windows"

// Env is everything jarx knows about the machine.
type Env struct {
	GOOS     string
	Home     string
	StateDir string // jarx's own state dir, the only place jarx writes
	Path     []string

	vars   map[string]string
	system bool
	fake   bool
}

// Roots are the OS-level dirs that managed and system config hangs off. A
// field is empty when it doesn't apply to the OS or couldn't be found.
type Roots struct {
	Etc               string // unix
	LibraryAppSupport string // macOS
	ProgramData       string // Windows, from %ProgramData%
	ProgramFiles      string // Windows, from %ProgramFiles%
}

// newEnv builds an Env from environ ("KEY=VALUE" entries). system says
// whether system roots may be read, and fake marks a --home Env.
func newEnv(goos, home, stateDir string, environ []string, system, fake bool) Env {
	env := Env{
		GOOS:     goos,
		Home:     home,
		StateDir: stateDir,
		vars:     make(map[string]string, len(environ)),
		system:   system,
		fake:     fake,
	}
	for _, kv := range environ {
		key, value, ok := strings.Cut(kv, "=")
		if !ok || key == "" { // also skips Windows' hidden "=C:=C:\" entries
			continue
		}
		env.vars[env.normalize(key)] = value
	}
	if path, ok := env.Lookup("PATH"); ok {
		env.Path = splitPath(goos, path)
	}
	return env
}

// Lookup returns the env var's value and whether it's set. An empty value
// counts as set. Names ignore case on Windows, like the OS does.
func (e Env) Lookup(name string) (string, bool) {
	value, ok := e.vars[e.normalize(name)]
	return value, ok
}

// VarCount is how many env vars are set.
func (e Env) VarCount() int { return len(e.vars) }

// Fake reports whether this Env comes from --home.
func (e Env) Fake() bool { return e.fake }

// SystemRoots returns the system roots, or false when jarx must not read
// system locations (under --home).
func (e Env) SystemRoots() (Roots, bool) {
	if !e.system {
		return Roots{}, false
	}
	switch e.GOOS {
	case goosWindows:
		data, _ := e.Lookup("ProgramData")
		files, _ := e.Lookup("ProgramFiles")
		return Roots{ProgramData: data, ProgramFiles: files}, true
	case "darwin":
		return Roots{Etc: "/etc", LibraryAppSupport: "/Library/Application Support"}, true
	default:
		return Roots{Etc: "/etc"}, true
	}
}

func (e Env) normalize(name string) string {
	if e.GOOS == goosWindows {
		return strings.ToUpper(name)
	}
	return name
}

// splitPath splits a PATH value with goos's separator and drops empty
// entries.
func splitPath(goos, path string) []string {
	sep := ":"
	if goos == goosWindows {
		sep = ";"
	}
	var out []string
	for entry := range strings.SplitSeq(path, sep) {
		if entry != "" {
			out = append(out, entry)
		}
	}
	return out
}
