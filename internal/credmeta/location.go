// Package credmeta knows where credentials live and, from phase 5, reads the
// safe metadata about them. It never reads a credential value.
//
// Location is the first piece: other packages ask it before reading a path
// someone else chose (like the target of a CLAUDE.md @import), so jarx never
// opens a credential file by following a pointer to it. It checks Places
// (where each CLI's docs say its credentials are, env vars included) and
// the defaults under the home dir even when a var moved them, since an old
// file there may still hold a secret.
package credmeta

import (
	"path/filepath"
	"slices"
	"strings"

	"github.com/nickelsec/jarx/internal/platform"
)

// homeFiles are the default credential files under the home dir, keyed by
// slash path relative to it. Places has the full, env-aware list; these
// stay guarded whatever the env says.
//
//nolint:gochecknoglobals // fixed list, read only
var homeFiles = map[string]string{
	".netrc":                  KindNetrc,
	"_netrc":                  KindNetrc,
	".git-credentials":        KindGit,
	".config/git/credentials": KindGit,
	".docker/config.json":     KindDocker,
	".kube/config":            KindKube,
	".npmrc":                  KindNpm,
	".pypirc":                 KindPypi,
	".config/gh/hosts.yml":    KindGH,
}

// homeDirs are dirs under the home dir where every file counts.
//
//nolint:gochecknoglobals // fixed list, read only
var homeDirs = map[string]string{
	".ssh":           KindSSH,
	".aws":           KindAWS,
	".gnupg":         KindGnupg,
	".azure":         KindAzure,
	".config/gcloud": KindGcloud,
}

// keyNames and keyExts mark private keys anywhere.
//
//nolint:gochecknoglobals // fixed list, read only
var (
	keyNames = []string{"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"}
	keyExts  = []string{".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".ppk"}
)

// Location says whether path is a credential location, and which kind. It
// only looks at the path, never at the file.
func Location(env platform.Env, path string) (string, bool) {
	p := normalize(env, path)
	for _, check := range []func(platform.Env, string) (string, bool){loginFile, placeLocation, homeLocation, byName} {
		if kind, ok := check(env, p); ok {
			return kind, true
		}
	}
	return "", false
}

// normalize cleans p and lowercases it on every OS. Windows and the default
// macOS file system ignore case, so ~/.SSH is ~/.ssh there, and a key named
// server.KEY is a key anywhere. On Linux this can match a file that isn't a
// credential; refusing to read one of those is the safe mistake.
func normalize(_ platform.Env, p string) string {
	return strings.ToLower(filepath.Clean(p))
}

// loginFile matches the agents' own login files.
func loginFile(env platform.Env, p string) (string, bool) {
	switch p {
	case normalize(env, filepath.Join(configDir(env, "CLAUDE_CONFIG_DIR", ".claude"), ".credentials.json")):
		return KindClaudeLogin, true
	case normalize(env, filepath.Join(configDir(env, "CODEX_HOME", ".codex"), "auth.json")):
		return KindCodexLogin, true
	}
	return "", false
}

// placeLocation matches the places env says credentials are.
func placeLocation(env platform.Env, p string) (string, bool) {
	for _, pl := range Places(env) {
		at := normalize(env, pl.Path)
		if p == at || pl.Dir && strings.HasPrefix(p, at+string(filepath.Separator)) {
			return pl.Kind, true
		}
	}
	return "", false
}

// homeLocation matches the fixed credential files and dirs under the home.
func homeLocation(env platform.Env, p string) (string, bool) {
	rel, err := filepath.Rel(normalize(env, env.Home), p)
	if err != nil || !filepath.IsLocal(rel) {
		return "", false
	}
	rel = filepath.ToSlash(rel)
	if kind, ok := homeFiles[rel]; ok {
		return kind, true
	}
	for dir, kind := range homeDirs {
		if strings.HasPrefix(rel, dir+"/") {
			return kind, true
		}
	}
	return "", false
}

// byName matches .env files, .npmrc files and private keys anywhere.
func byName(_ platform.Env, p string) (string, bool) {
	base := filepath.Base(p)
	switch {
	case base == ".env" || strings.HasPrefix(base, ".env."):
		return KindEnvFile, true
	case base == ".npmrc": // a project's own npmrc can hold a registry token
		return KindNpm, true
	case slices.Contains(keyNames, base), slices.Contains(keyExts, filepath.Ext(base)):
		return KindPrivateKey, true
	}
	return "", false
}

// configDir is an agent's config dir: the env var's dir when set, or
// <home>/<fallback>.
func configDir(env platform.Env, envVar, fallback string) string {
	if dir, ok := env.Lookup(envVar); ok && dir != "" {
		return env.MapPath(dir)
	}
	return filepath.Join(env.Home, fallback)
}

// Located is a credential path's kind, its path inside its place, and
// whether jarx reads its metadata.
type Located struct {
	Kind string
	// Rel is the path inside a credential dir (like "active_config" in
	// gcloud's), or the file name. It's lowercase and slash-separated, like
	// everything Location compares.
	Rel  string
	Read bool
}

// Locate is Location plus the path's place in it, so the parsers can tell
// a credential's files apart.
func Locate(env platform.Env, path string) (Located, bool) {
	kind, ok := Location(env, path)
	if !ok {
		return Located{}, false
	}
	p := normalize(env, path)
	if at, ok := inPlace(env, kind, p); ok {
		return at, true
	}
	for dir, k := range homeDirs {
		if r, in := inside(env, filepath.Join(env.Home, filepath.FromSlash(dir)), p); k == kind && in {
			return Located{kind, r, Reads(kind, r)}, true
		}
	}
	rel := filepath.Base(p)
	return Located{kind, rel, Reads(kind, rel)}, true
}

// inPlace finds the place of the kind that p is, or is in.
func inPlace(env platform.Env, kind, p string) (Located, bool) {
	for _, pl := range Places(env) {
		if pl.Kind != kind {
			continue
		}
		if !pl.Dir && p == normalize(env, pl.Path) {
			rel := filepath.Base(p)
			return Located{kind, rel, !pl.NoRead && Reads(kind, rel)}, true
		}
		if r, in := inside(env, pl.Path, p); pl.Dir && in {
			return Located{kind, r, !pl.NoRead && Reads(kind, r)}, true
		}
	}
	return Located{}, false
}

// inside is p's path inside dir, slash-separated, when it's in it.
func inside(env platform.Env, dir, p string) (string, bool) {
	r, err := filepath.Rel(normalize(env, dir), p)
	if err != nil || !filepath.IsLocal(r) {
		return "", false
	}
	return filepath.ToSlash(r), true
}
