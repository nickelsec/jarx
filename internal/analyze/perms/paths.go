package perms

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/nickelsec/jarx/internal/credmeta"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/platform"
)

// matcher tests whether a grant covers an absolute path.
type matcher func(path string) bool

func all(string) bool { return true }

// slashPath is p with forward slashes, lowercased, for matching. Windows
// and default macOS ignore case, and over-matching a credential is the safe
// mistake.
func slashPath(p string) string { return strings.ToLower(filepath.ToSlash(filepath.Clean(p))) }

// claudeMatcher resolves a Claude Read or Edit rule's pattern. The
// permissions docs: //path is from the filesystem root, ~/path from home,
// /path from the settings source (~/.claude for user settings, the project
// for project and local ones), and anything else from the working dir. An
// empty pattern covers the whole tool. So does *, which the docs settle
// only for Bash; reading it broadly is the safe mistake. ** has no prefix,
// so it's everything under the working dir.
func claudeMatcher(env platform.Env, project string, o model.Origin, pattern string) matcher {
	switch pattern {
	case "", "*":
		return all
	}
	var abs string
	switch {
	case strings.HasPrefix(pattern, "//"):
		rest := pattern[2:]
		if driveRe.MatchString(rest) {
			abs = rest
		} else {
			abs = "/" + rest
		}
	case pattern == "~" || strings.HasPrefix(pattern, "~/"):
		abs = env.Home + pattern[1:]
	case strings.HasPrefix(pattern, "/"):
		base := project
		if o.Scope == model.ScopeUser {
			base = filepath.Join(env.Home, ".claude")
		}
		abs = base + pattern
	default:
		abs = filepath.Join(project, pattern)
	}
	return globMatcher(abs)
}

// pathMatcher resolves a plain path grant: an additional directory, a
// sandbox path or a Codex profile path. Special tokens like Codex's
// :workspace_roots aren't credential paths, so they match nothing here.
func pathMatcher(env platform.Env, project, p string) matcher {
	switch {
	case p == "" || strings.HasPrefix(p, ":"):
		return func(string) bool { return false }
	case p == "~" || strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`):
		p = env.Home + p[1:]
	case !filepath.IsAbs(p) && !strings.HasPrefix(p, "/"):
		p = filepath.Join(project, p)
	}
	return globMatcher(p)
}

// globMatcher matches gitignore-style globs. A path with no glob also
// covers everything under it.
func globMatcher(pattern string) matcher {
	p := slashPath(pattern)
	if !strings.ContainsAny(p, "*?") {
		return func(path string) bool {
			s := slashPath(path)
			return s == p || strings.HasPrefix(s, strings.TrimSuffix(p, "/")+"/")
		}
	}
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(p); i++ {
		switch {
		case strings.HasPrefix(p[i:], "**/"):
			b.WriteString("(?:.*/)?")
			i += 2
		case strings.HasPrefix(p[i:], "**"):
			b.WriteString(".*")
			i++
		case p[i] == '*':
			b.WriteString("[^/]*")
		case p[i] == '?':
			b.WriteString("[^/]")
		default:
			b.WriteString(regexp.QuoteMeta(p[i : i+1]))
		}
	}
	b.WriteString("$")
	re := regexp.MustCompile(b.String())
	return func(path string) bool { return re.MatchString(slashPath(path)) }
}

// covered is the credential samples m covers.
func covered(samples []credmeta.Sample, m matcher) []credmeta.Sample {
	var out []credmeta.Sample
	for _, s := range samples {
		if m(s.Path) {
			out = append(out, s)
		}
	}
	return out
}
