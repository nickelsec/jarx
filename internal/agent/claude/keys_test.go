package claude

import (
	"testing"

	"github.com/nickelsec/jarx/internal/model"
)

func TestKeyScopesFollowTheSettingsIndex(t *testing.T) {
	user, project, local, managed := model.ScopeUser, model.ScopeProject, model.ScopeLocal, model.ScopeManaged
	for _, tc := range []struct {
		key     string
		scope   model.Scope
		allowed bool
	}{
		{"permissions.allow", project, true},               // Any file
		{"permissions.allow", local, true},                 // Any file
		{"permissions.denyInsteadOfPrompting", user, true}, // User or managed
		{"permissions.denyInsteadOfPrompting", project, false},
		{"permissions.denyInsteadOfPrompting", local, false},
		{"skipDangerousModePermissionPrompt", local, true}, // User, local, or managed
		{"skipDangerousModePermissionPrompt", project, false},
		{"allowManagedPermissionRulesOnly", managed, true}, // Managed
		{"allowManagedPermissionRulesOnly", user, false},
		{"autoConnectIde", user, false}, // Global config: ~/.claude.json only
		{"autoConnectIde", managed, false},
	} {
		known, allowed := keyAllowed(tc.key, tc.scope)
		if !known || allowed != tc.allowed {
			t.Errorf("keyAllowed(%q, %s) = %v, %v; want true, %v", tc.key, tc.scope, known, allowed, tc.allowed)
		}
	}
}

func TestUnknownKeysAreNotKnown(t *testing.T) {
	for _, key := range []string{"notARealSetting", "permissions.notARealOne", "Permissions.allow", ""} {
		if known, _ := keyAllowed(key, model.ScopeUser); known {
			t.Errorf("keyAllowed(%q) known = true, want false", key)
		}
	}
}

func TestEveryRowInTheKeyTableParses(t *testing.T) {
	keys, err := parseKeys(keysTSV)
	if err != nil {
		t.Fatalf("parseKeys() error = %v", err)
	}
	if len(keys) < 200 {
		t.Errorf("parsed %d keys, want the whole index (250 as of 2026-11-22)", len(keys))
	}
}

func TestBadKeyTableRowsAreErrors(t *testing.T) {
	for name, body := range map[string]string{
		"unknown scope": "model\tSometimes\n",
		"no tab":        "model Any file\n",
		"duplicate":     "model\tAny file\nmodel\tAny file\n",
	} {
		if _, err := parseKeys(body); err == nil {
			t.Errorf("%s: parseKeys() error = nil, want one", name)
		}
	}
}
