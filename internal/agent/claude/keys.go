package claude

import (
	_ "embed" // the key table
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"

	"github.com/nickelsec/jarx/internal/model"
)

// keysTSV is the Settings index from code.claude.com/docs/en/settings-reference:
// every settings key and the files it may be set in.
//
//go:embed keys.tsv
var keysTSV string

//nolint:gochecknoglobals // parsed once from the embedded table, never written
var loadKeys = sync.OnceValues(func() (map[string][]model.Scope, error) { return parseKeys(keysTSV) })

// docScopes maps a scope as the settings index writes it to the settings
// files it covers. "Global config" keys live in ~/.claude.json, so no
// settings file counts for them.
func docScopes(scope string) ([]model.Scope, bool) {
	switch scope {
	case "Any file":
		return []model.Scope{model.ScopeUser, model.ScopeProject, model.ScopeLocal, model.ScopeManaged}, true
	case "User or managed":
		return []model.Scope{model.ScopeUser, model.ScopeManaged}, true
	case "User, local, or managed":
		return []model.Scope{model.ScopeUser, model.ScopeLocal, model.ScopeManaged}, true
	case "User":
		return []model.Scope{model.ScopeUser}, true
	case "Managed":
		return []model.Scope{model.ScopeManaged}, true
	case "Global config":
		return nil, true
	default:
		return nil, false
	}
}

// parseKeys reads "key<TAB>scope" rows. Blank lines and # comments are
// skipped. A scope the table doesn't know is an error, so a docs change
// can't slip in unread.
func parseKeys(body string) (map[string][]model.Scope, error) {
	keys := map[string][]model.Scope{}
	for n, line := range strings.Split(body, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, scope, ok := strings.Cut(line, "\t")
		if !ok || key == "" {
			return nil, fmt.Errorf("keys.tsv line %d: want key<TAB>scope", n+1)
		}
		scopes, ok := docScopes(scope)
		if !ok {
			return nil, fmt.Errorf("keys.tsv line %d: unknown scope %q", n+1, scope)
		}
		if _, dup := keys[key]; dup {
			return nil, fmt.Errorf("keys.tsv line %d: %s is listed twice", n+1, key)
		}
		keys[key] = scopes
	}
	if len(keys) == 0 {
		return nil, errors.New("keys.tsv has no keys")
	}
	return keys, nil
}

// keyAllowed returns whether key is in the settings index (a dotted path
// like permissions.allow), and whether Claude reads it from a file of scope
// s.
func keyAllowed(key string, s model.Scope) (bool, bool) {
	keys, err := loadKeys()
	if err != nil {
		return false, false // the table test catches this at build time
	}
	scopes, ok := keys[key]
	if !ok {
		return false, false
	}
	return true, slices.Contains(scopes, s)
}

// hasKnownChild says whether the index lists a key under key, like
// sandbox.network for sandbox, so a parent with no row of its own still
// counts as known.
func hasKnownChild(key string) bool {
	keys, err := loadKeys()
	if err != nil || key == "" {
		return false
	}
	for k := range keys {
		if strings.HasPrefix(k, key+".") {
			return true
		}
	}
	return false
}

// sortedKeys returns m's keys in order, so output is stable.
func sortedKeys[V any](m map[string]V) []string {
	return slices.Sorted(maps.Keys(m))
}
