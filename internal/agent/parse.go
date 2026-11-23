package agent

import (
	"strings"
	"unicode"
)

// MaxImportsPerFile caps how many @imports one file can name, so a file
// full of them can't blow up a scan.
const MaxImportsPerFile = 500

// Import is one @path import in an instruction file. Path is as written,
// with escaped spaces turned into spaces. Line is 1-based.
type Import struct {
	Path string
	Line int
}

// Imports finds the @path imports in a CLAUDE.md style file, the way
// code.claude.com/docs/en/memory#import-additional-files describes them: an
// @ that starts a word, then the path up to the first space that isn't
// escaped with a backslash. A path in quotes isn't an import, and neither is
// anything in a code span or fenced code block. It stops at
// MaxImportsPerFile.
func Imports(text string) []Import {
	var out []Import
	fence := ""
	for n, line := range strings.Split(text, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if f := fenceMarker(line); f != "" {
			switch {
			case fence == "":
				fence = f
			case strings.HasPrefix(f, fence):
				fence = ""
			}
			continue
		}
		if fence != "" {
			continue
		}
		for _, p := range lineImports(line) {
			if len(out) == MaxImportsPerFile {
				return out
			}
			out = append(out, Import{Path: p, Line: n + 1})
		}
	}
	return out
}

// fenceMarker returns the run of ``` or ~~~ that opens or closes a fenced
// code block on line, or "".
func fenceMarker(line string) string {
	t := strings.TrimLeft(line, " ")
	if len(line)-len(t) > maxFenceIndent || len(t) < minFence {
		return ""
	}
	c := t[0]
	if c != '`' && c != '~' {
		return ""
	}
	n := 0
	for n < len(t) && t[n] == c {
		n++
	}
	if n < minFence {
		return ""
	}
	return t[:n]
}

// A fence is at least three backticks or tildes, indented at most three
// spaces, as in CommonMark.
const (
	minFence       = 3
	maxFenceIndent = 3
)

// lineImports returns the import paths on one line outside code spans.
func lineImports(line string) []string {
	var out []string
	rs := []rune(line)
	for i := 0; i < len(rs); i++ {
		switch {
		case rs[i] == '`':
			i = skipCodeSpan(rs, i)
		case rs[i] == '@' && (i == 0 || unicode.IsSpace(rs[i-1])):
			path, end := importPath(rs, i+1)
			if path != "" {
				out = append(out, path)
			}
			i = end - 1
		}
	}
	return out
}

// skipCodeSpan returns the index of the last backtick of the code span that
// opens at i, or the end of the opening run when it never closes (then the
// backticks are plain text).
func skipCodeSpan(rs []rune, i int) int {
	n := run(rs, i, '`')
	for j := i + n; j < len(rs); j++ {
		if rs[j] != '`' {
			continue
		}
		m := run(rs, j, '`')
		if m == n {
			return j + m - 1
		}
		j += m - 1
	}
	return i + n - 1
}

func run(rs []rune, i int, r rune) int {
	n := 0
	for i+n < len(rs) && rs[i+n] == r {
		n++
	}
	return n
}

// importPath reads a path starting at i, up to the first space not escaped
// with a backslash. A path that starts with a quote isn't an import.
func importPath(rs []rune, i int) (string, int) {
	if i >= len(rs) || rs[i] == '"' || rs[i] == '\'' {
		return "", i
	}
	var b strings.Builder
	for ; i < len(rs); i++ {
		if rs[i] == '\\' && i+1 < len(rs) && rs[i+1] == ' ' {
			b.WriteRune(' ')
			i++
			continue
		}
		if unicode.IsSpace(rs[i]) {
			break
		}
		b.WriteRune(rs[i])
	}
	return b.String(), i
}

// bom is the byte order mark some editors put at the top of a file.
const bom = rune(0xFEFF)

// Frontmatter splits a --- delimited header off the top of text. It returns
// the header's top-level keys with their values as plain strings (quotes
// removed, "" for a key whose value is on the following lines), the body
// after the header, and whether there was a header. It is not a YAML parser:
// jarx only needs to know which keys are set and a few simple values.
func Frontmatter(text string) (map[string]string, string, bool) {
	lines, body, ok := frontmatterLines(text)
	if !ok {
		return nil, text, false
	}
	keys := map[string]string{}
	for _, line := range lines {
		if key, value, ok := topLevelKey(line); ok {
			keys[key] = value
		}
	}
	return keys, body, true
}

// topLevelKey reads "key: value" at the start of a line.
func topLevelKey(line string) (string, string, bool) {
	key, value, ok := strings.Cut(line, ":")
	if !ok || key == "" || strings.ContainsFunc(key, notKeyRune) {
		return "", "", false
	}
	value = strings.TrimSpace(value)
	if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
		value = value[1 : len(value)-1]
	}
	return key, value, true
}

// notKeyRune is a rune that can't be in a frontmatter key.
func notKeyRune(r rune) bool {
	return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' && r != '-'
}
