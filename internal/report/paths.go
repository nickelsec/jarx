package report

import (
	"strings"

	"github.com/nickelsec/jarx/internal/model"
)

// short is path as the report shows it: relative to base when it's inside
// it, else from ~ when it's inside the home dir, else in full. It works on
// the masked text, so it never shows more than the path's masked form.
func (p *Printer) short(path, base, home model.Path) string {
	full := path.Text().String()
	if d := base.Text().String(); d != "" {
		if rest, ok := cutPathPrefix(full, d); ok {
			return rest
		}
	}
	if d := home.Text().String(); d != "" {
		if rest, ok := cutPathPrefix(full, d); ok {
			return "~" + string(full[len(d)]) + rest
		}
	}
	return full
}

// cutPathPrefix returns full past dir and a separator, ignoring case as
// Windows and default macOS do.
func cutPathPrefix(full, dir string) (string, bool) {
	if len(full) <= len(dir)+1 || !strings.EqualFold(full[:len(dir)], dir) {
		return "", false
	}
	if c := full[len(dir)]; c != '/' && c != '\\' {
		return "", false
	}
	return full[len(dir)+1:], true
}

// shortenIn shortens the paths inside s the way short does: paths in the
// base dir lose it, and paths in the home dir start from ~. Evidence names
// files in full; on a terminal that's noise.
func shortenIn(s string, base, home model.Path) string {
	for _, d := range []struct {
		dir  model.Path
		with string
	}{{base, ""}, {home, "~"}} {
		dir := d.dir.Text().String()
		if dir == "" {
			continue
		}
		for _, sep := range []string{`\`, "/"} {
			to := ""
			if d.with != "" {
				to = d.with + sep
			}
			s = replaceFold(s, dir+sep, to)
		}
	}
	return s
}

// replaceFold replaces every old in s with with, ignoring case, as paths
// on Windows and default macOS do.
func replaceFold(s, old, with string) string {
	if old == "" {
		return s
	}
	var b strings.Builder
	for {
		i := strings.Index(strings.ToLower(s), strings.ToLower(old))
		if i < 0 {
			b.WriteString(s)
			return b.String()
		}
		b.WriteString(s[:i])
		b.WriteString(with)
		s = s[i+len(old):]
	}
}
