package credmeta

import (
	"io"
	"slices"
	"strings"
)

// jarx has no YAML parser, and doesn't want one reading secret files. These
// line readers know two shapes, gh's hosts.yml and kubeconfig, keep the few
// keys they need, and drop every other value as they go. A line they don't
// understand is dropped, never kept.

// yamlLine is one line split into its indent, key and value.
type yamlLine struct {
	indent int
	dash   bool // the line starts a list item ("- key: value")
	key    string
	value  string
}

// listDash starts a list item. Its keys line up after it.
const listDash = "- "

func splitYAML(line string) (yamlLine, bool) {
	t := strings.TrimLeft(line, " ")
	if t == "" || t[0] == '#' {
		return yamlLine{}, false
	}
	y := yamlLine{indent: len(line) - len(t)}
	if rest, ok := strings.CutPrefix(t, listDash); ok {
		y.dash, y.indent, t = true, y.indent+len(listDash), strings.TrimLeft(rest, " ")
	}
	k, v, ok := strings.Cut(t, ":")
	quotedKey := strings.HasPrefix(k, "\"") && strings.HasSuffix(k, "\"")
	if !ok || !quotedKey && strings.ContainsAny(k, " \t\"'{[") {
		return yamlLine{}, false
	}
	y.key, y.value = unquote(k), unquote(stripComment(v))
	return y, true
}

// stripComment drops a trailing " #comment" from an unquoted value.
func stripComment(v string) string {
	if t := strings.TrimSpace(v); t != "" && t[0] != '"' && t[0] != '\'' {
		if before, _, found := strings.Cut(v, " #"); found {
			return before
		}
	}
	return v
}

// parseGH keeps each host in hosts.yml, its user, and whether a token sits
// in the file (gh keeps it in the OS keyring when it can).
func parseGH(_ string, r io.Reader) ([]Fact, error) {
	var g ghReader
	err := lines(r, g.line)
	return g.facts(), err
}

type ghHost struct {
	name, user string
	token      bool
}

type ghReader struct {
	hosts []ghHost
	inner int // the indent of the current host's own keys, 0 until seen
}

func (g *ghReader) line(line string) {
	y, ok := splitYAML(line)
	switch {
	case !ok:
	case y.indent == 0 && y.value == "":
		g.hosts, g.inner = append(g.hosts, ghHost{name: y.key}), 0
	case len(g.hosts) > 0 && y.indent > 0:
		g.hostLine(y)
	}
}

// hostLine reads a line inside a host's block.
func (g *ghReader) hostLine(y yamlLine) {
	h := &g.hosts[len(g.hosts)-1]
	if g.inner == 0 {
		g.inner = y.indent
	}
	if y.indent == g.inner && y.key == "user" && name.MatchString(y.value) {
		h.user = y.value
	}
	h.token = h.token || y.key == "oauth_token"
}

func (g *ghReader) facts() []Fact {
	out := make([]Fact, 0, len(g.hosts))
	for _, h := range g.hosts {
		if !name.MatchString(h.name) {
			continue
		}
		parts := []string{"no token in the file"}
		if h.token {
			parts[0] = "token in the file"
		}
		if h.user != "" {
			parts = append([]string{"user " + h.user}, parts...)
		}
		out = append(out, Fact{"host " + h.name, strings.Join(parts, ", ")})
	}
	return out
}

// kubeUserKinds names what kind of credential a kubeconfig user has, from
// its key names.
//
//nolint:gochecknoglobals // fixed table, read only
var kubeUserKinds = []struct{ label, keys string }{
	{"token", "token tokenFile"},
	{"client key", "client-key-data client-key"},
	{"exec", "exec"},
	{"auth provider", "auth-provider"},
	{keyPassword, keyPassword},
}

// parseKube keeps cluster, context and user names, current-context, and
// the kind of credential each user has.
func parseKube(_ string, r io.Reader) ([]Fact, error) {
	k := kubeReader{itemIndent: -1}
	err := lines(r, k.line)
	return k.facts(), err
}

type kubeItem struct {
	section, name string
	keys          []string
}

type kubeReader struct {
	section, current string
	items            []kubeItem
	itemIndent       int // the indent of a list item's own keys, -1 until seen
}

func (k *kubeReader) line(line string) {
	y, ok := splitYAML(line)
	switch {
	case !ok:
	case y.indent == 0 && !y.dash:
		k.section, k.itemIndent = y.key, -1
		if y.key == "current-context" && name.MatchString(y.value) {
			k.current = y.value
		}
	case k.section == "clusters" || k.section == "contexts" || k.section == "users":
		k.itemLine(y)
	}
}

// itemLine reads a line inside a list of clusters, contexts or users.
func (k *kubeReader) itemLine(y yamlLine) {
	if y.dash && (k.itemIndent < 0 || y.indent == k.itemIndent) {
		k.itemIndent = y.indent
		k.items = append(k.items, kubeItem{section: k.section})
	}
	if len(k.items) == 0 {
		return
	}
	it := &k.items[len(k.items)-1]
	switch {
	case y.indent == k.itemIndent && y.key == "name":
		if name.MatchString(y.value) {
			it.name = y.value
		}
	case y.indent > k.itemIndent:
		it.keys = append(it.keys, y.key)
	}
}

func (k *kubeReader) facts() []Fact {
	var out []Fact
	add := func(sec, label string) {
		for _, it := range k.items {
			if it.section == sec && it.name != "" {
				out = append(out, Fact{label + " " + it.name, userKinds(it)})
			}
		}
	}
	add("clusters", "cluster")
	add("contexts", "context")
	if k.current != "" {
		out = append(out, Fact{"current context", k.current})
	}
	add("users", "user")
	return out
}

// userKinds names a kubeconfig user's kinds of credential, or "" for a
// cluster or context.
func userKinds(it kubeItem) string {
	if it.section != "users" {
		return ""
	}
	var kinds []string
	for _, uk := range kubeUserKinds {
		if slices.ContainsFunc(strings.Fields(uk.keys), func(key string) bool { return slices.Contains(it.keys, key) }) {
			kinds = append(kinds, uk.label)
		}
	}
	return strings.Join(kinds, ", ")
}
