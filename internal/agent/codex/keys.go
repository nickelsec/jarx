package codex

import (
	_ "embed" // the key table
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/nickelsec/jarx/internal/agent"
	"github.com/nickelsec/jarx/internal/model"
)

// keysTSV is every key in the config reference's tables, for config.toml and
// for requirements.toml.
//
//go:embed keys.tsv
var keysTSV string

// The tables in keys.tsv.
const (
	tableConfig       = "config"
	tableRequirements = "requirements"
	keyColumns        = 3
)

// keyRow is one documented key, split into segments. * is a name you
// choose and *[] is each table in an array of tables. The table's kind
// column marks maps whose keys are names you choose; no rows sit under
// those, so the walk never goes inside them.
type keyRow struct {
	segs []string
}

//nolint:gochecknoglobals // parsed once from the embedded table, never written
var loadKeys = sync.OnceValues(func() (map[string][]keyRow, error) { return parseKeys(keysTSV) })

func parseKeys(body string) (map[string][]keyRow, error) {
	out := map[string][]keyRow{}
	for n, line := range strings.Split(body, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		cols := strings.Split(line, "\t")
		if len(cols) != keyColumns || (cols[0] != tableConfig && cols[0] != tableRequirements) || cols[1] == "" {
			return nil, fmt.Errorf("codex keys.tsv line %d: want config or requirements, key and kind", n+1)
		}
		segs := strings.Split(cols[1], ".")
		for i, s := range segs {
			segs[i] = strings.Trim(s, `"`)
		}
		out[cols[0]] = append(out[cols[0]], keyRow{segs: segs})
	}
	return out, nil
}

// legacyKeys are the profile keys Codex ignores; LegacyProfiles reports
// them, so they aren't unknown too.
func legacyKey(top string) bool { return top == "profile" || top == "profiles" }

func segMatch(pattern, seg string) bool {
	switch pattern {
	case "*":
		return !strings.HasSuffix(seg, "[]")
	case "*[]":
		return strings.HasSuffix(seg, "[]")
	}
	return pattern == seg
}

func prefixMatch(pattern, path []string) bool {
	if len(pattern) < len(path) {
		return false
	}
	for i := range path {
		if !segMatch(pattern[i], path[i]) {
			return false
		}
	}
	return true
}

// keyWalker finds the keys in one decoded file that its table doesn't list.
type keyWalker struct {
	rows []keyRow
	out  []model.Unknown
	mk   func(key, near string) model.Unknown
}

func (w *keyWalker) find(path []string) (keyRow, bool) {
	for _, r := range w.rows {
		if len(r.segs) == len(path) && prefixMatch(r.segs, path) {
			return r, true
		}
	}
	return keyRow{}, false
}

func (w *keyWalker) hasChildren(path []string) bool {
	for _, r := range w.rows {
		if len(r.segs) > len(path) && prefixMatch(r.segs, path) {
			return true
		}
	}
	return false
}

// walk checks every key in m under path. It goes into a table or an array
// of tables only when the reference lists keys under it, since some tables
// hold names you choose.
func (w *keyWalker) walk(path []string, m map[string]any) {
	for _, k := range sortedKeys(m) {
		if len(path) == 0 && legacyKey(k) {
			continue
		}
		p := append(slices.Clone(path), k)
		// A table with documented keys under it counts as known, like
		// [features], even when the table has no row of its own.
		if _, ok := w.find(p); !ok && !w.hasChildren(p) && !w.hasChildren(append(slices.Clone(path), k+"[]")) {
			w.out = append(w.out, w.mk(strings.Join(p, "."), w.near(p)))
			continue
		}
		w.walkValue(path, k, m[k])
	}
}

func (w *keyWalker) walkValue(path []string, k string, v any) {
	switch x := v.(type) {
	case map[string]any:
		if p := append(slices.Clone(path), k); w.hasChildren(p) {
			w.walk(p, x)
		}
	case []map[string]any:
		if p := append(slices.Clone(path), k+"[]"); w.hasChildren(p) {
			for _, e := range x {
				w.walk(p, e)
			}
		}
	case []any:
		p := append(slices.Clone(path), k+"[]")
		if !w.hasChildren(p) {
			return
		}
		for _, e := range x {
			if m, ok := e.(map[string]any); ok {
				w.walk(p, m)
			}
		}
	}
}

// near is the documented key at the same level that path's last part is
// most likely a typo of, as a full key, or "".
func (w *keyWalker) near(path []string) string {
	parent := path[:len(path)-1]
	var names []string
	for _, r := range w.rows {
		if len(r.segs) != len(path) || !prefixMatch(r.segs[:len(parent)], parent) {
			continue
		}
		if last := r.segs[len(r.segs)-1]; last != "*" && last != "*[]" && !slices.Contains(names, last) {
			names = append(names, last)
		}
	}
	slices.Sort(names)
	n := agent.NearKey(path[len(path)-1], names)
	if n == "" {
		return ""
	}
	return strings.Join(append(slices.Clone(parent), n), ".")
}

// unknownKeys lists the keys in raw that the table doesn't document.
func unknownKeys(table string, raw map[string]any, mk func(key, near string) model.Unknown) []model.Unknown {
	keys, err := loadKeys()
	if err != nil {
		return nil
	}
	w := &keyWalker{rows: keys[table], mk: mk}
	w.walk(nil, raw)
	return w.out
}
