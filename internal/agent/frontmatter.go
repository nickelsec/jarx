package agent

import (
	"strings"
)

// fence opens and closes a frontmatter header.
const fence = "---"

// frontmatterLines returns the lines between the --- markers at the top of
// text, without line endings, and the body after the closing marker.
func frontmatterLines(text string) ([]string, string, bool) {
	t := strings.TrimPrefix(text, string(bom))
	first, rest, ok := strings.Cut(t, "\n")
	if !ok || strings.TrimSuffix(first, "\r") != fence {
		return nil, "", false
	}
	var lines []string
	for rest != "" {
		var line string
		line, rest, _ = strings.Cut(rest, "\n")
		line = strings.TrimSuffix(line, "\r")
		if line == fence {
			return lines, rest, true
		}
		lines = append(lines, line)
	}
	return nil, "", false
}

// FrontmatterBlock returns a top-level frontmatter key's raw value: the
// inline value after "key:" when there is one, or else every indented line
// under it, as written. jarx keeps nested values like a skill's hooks as
// text instead of parsing YAML.
func FrontmatterBlock(text, key string) (string, bool) {
	lines, _, ok := frontmatterLines(text)
	if !ok {
		return "", false
	}
	for i, line := range lines {
		k, value, ok := topLevelKey(line)
		if !ok || k != key {
			continue
		}
		if value != "" {
			return value, true
		}
		var b strings.Builder
		for _, next := range lines[i+1:] {
			if next != "" && next[0] != ' ' && next[0] != '\t' {
				break
			}
			b.WriteString(next)
			b.WriteString("\n")
		}
		return b.String(), true
	}
	return "", false
}

// ToolList reads a tool list from frontmatter in any documented form: a
// space- or comma-separated string, a [a, b] flow list, or a YAML list of
// "- item" lines. Parentheses keep their contents together, so
// "Bash(git add *) Read" is two tools.
func ToolList(text, key string) []string {
	block, ok := FrontmatterBlock(text, key)
	if !ok {
		return nil
	}
	if !strings.Contains(block, "\n") {
		return splitTools(block)
	}
	var out []string
	for line := range strings.SplitSeq(block, "\n") {
		item, ok := strings.CutPrefix(strings.TrimSpace(line), "- ")
		if ok {
			if v := unquote(strings.TrimSpace(item)); v != "" {
				out = append(out, v)
			}
		}
	}
	return out
}

// splitTools splits a one-line tool list on commas and spaces outside
// parentheses.
func splitTools(raw string) []string {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]") {
		raw = raw[1 : len(raw)-1]
	}
	var t toolSplitter
	for _, r := range raw {
		t.add(r)
	}
	t.flush()
	return t.out
}

// toolSplitter splits on commas and spaces outside parentheses.
type toolSplitter struct {
	out   []string
	cur   strings.Builder
	depth int
}

func (t *toolSplitter) add(r rune) {
	switch {
	case r == '(':
		t.depth++
	case r == ')' && t.depth > 0:
		t.depth--
	case t.depth == 0 && (r == ',' || r == ' ' || r == '\t'):
		t.flush()
		return
	}
	t.cur.WriteRune(r)
}

func (t *toolSplitter) flush() {
	if v := unquote(strings.TrimSpace(t.cur.String())); v != "" {
		t.out = append(t.out, v)
	}
	t.cur.Reset()
}

// unquote drops one pair of matching quotes around s.
func unquote(s string) string {
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}
