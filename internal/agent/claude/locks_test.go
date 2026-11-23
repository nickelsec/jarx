package claude

import (
	"strings"
	"testing"

	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/redact"
)

// modeLayer returns the defaultMode layer from scope.
func modeLayer(t *testing.T, p model.Permissions, scope model.Scope) model.Layer[redact.Text] {
	t.Helper()
	for _, l := range p.DefaultMode.Layers {
		if l.Origin.Scope == scope {
			return l
		}
	}
	t.Fatalf("no defaultMode layer from %s in %+v", scope, p.DefaultMode.Layers)
	return model.Layer[redact.Text]{}
}

func optionNamed(p model.Permissions, key string) (model.Option, bool) {
	for _, o := range p.Options {
		if o.Key.String() == key {
			return o, true
		}
	}
	return model.Option{}, false
}

func TestDisablingBypassTurnsOffABypassDefaultMode(t *testing.T) {
	// The settings reference: disableBypassPermissionsMode works from any
	// scope, and the strictest value any source sets wins.
	c := fakeHome(t, map[string]string{
		".claude/settings.json":   `{"permissions": {"defaultMode": "bypassPermissions"}}`,
		"p/.claude/settings.json": `{"permissions": {"disableBypassPermissionsMode": "disable"}}`,
	})

	perm, _, _ := settingsFor(t, c, model.TrustTrusted)

	l := modeLayer(t, perm, model.ScopeUser)
	if l.Origin.InEffect || !strings.Contains(l.Origin.Why.String(), "disableBypassPermissionsMode") ||
		!strings.Contains(l.Origin.Why.String(), "settings.json") {
		t.Errorf("bypass mode in effect = %v (%q), want off because of the lock and where it is", l.Origin.InEffect, l.Origin.Why)
	}
	if _, ok := perm.DefaultMode.Effective(); ok {
		t.Errorf("a defaultMode is in effect, want none: the docs don't say which mode Claude falls back to")
	}
	if o, ok := optionNamed(perm, "disableBypassPermissionsMode"); !ok || len(o.Setting.InEffect()) != 1 {
		t.Errorf("options = %+v, want the lock shown with its layer", perm.Options)
	}
}

func TestDisablingAutoStartsInDefaultInstead(t *testing.T) {
	for name, body := range map[string]string{
		"top level":         `{"disableAutoMode": "disable"}`,
		"under permissions": `{"permissions": {"disableAutoMode": "disable"}}`,
	} {
		c := managedHome(t,
			map[string]string{
				".claude/settings.json":   `{"permissions": {"defaultMode": "acceptEdits"}}`,
				"p/.claude/settings.json": body,
			},
			map[string]string{"managed-settings.json": `{"permissions": {"defaultMode": "auto"}}`},
			nil)

		perm, _, _ := settingsFor(t, c, model.TrustTrusted)

		auto := modeLayer(t, perm, model.ScopeManaged)
		if auto.Origin.InEffect || !strings.Contains(auto.Origin.Why.String(), "starts in default") {
			t.Errorf("%s: auto in effect = %v (%q), want off: Claude starts in default", name, auto.Origin.InEffect, auto.Origin.Why)
		}
		if user := modeLayer(t, perm, model.ScopeUser); user.Origin.InEffect {
			t.Errorf("%s: user acceptEdits in effect, want not: the docs say the session starts in default", name)
		}
	}
}

func TestALockFromAnUntrustedProjectIsntCounted(t *testing.T) {
	c := fakeHome(t, map[string]string{
		".claude/settings.json":   `{"permissions": {"defaultMode": "bypassPermissions"}}`,
		"p/.claude/settings.json": `{"permissions": {"disableBypassPermissionsMode": "disable"}}`,
	})

	perm, _, _ := settingsFor(t, c, model.TrustUntrusted)

	if l := modeLayer(t, perm, model.ScopeUser); !l.Origin.InEffect {
		t.Errorf("bypass mode off (%q), want in effect: hiding a live bypass is the worse mistake", l.Origin.Why)
	}
	o, ok := optionNamed(perm, "disableBypassPermissionsMode")
	if !ok || len(o.Setting.InEffect()) != 0 || len(o.Setting.Layers) != 1 || !strings.Contains(o.Setting.Layers[0].Origin.Why.String(), "trust") {
		t.Errorf("lock option = %+v, want shown but not counted, with a trust reason", o)
	}
}

func TestAModeOffForAnotherReasonDoesntBlockLowerOnes(t *testing.T) {
	// The project's bypass is ignored from project files anyway, so the
	// lock doesn't stop anything there, and the user's mode still applies.
	c := fakeHome(t, map[string]string{
		".claude/settings.json":   `{"permissions": {"defaultMode": "acceptEdits"}}`,
		"p/.claude/settings.json": `{"permissions": {"defaultMode": "bypassPermissions", "disableBypassPermissionsMode": "disable"}}`,
	})

	perm, _, _ := settingsFor(t, c, model.TrustTrusted)

	if eff, ok := perm.DefaultMode.Effective(); !ok || eff.Value.String() != "acceptEdits" {
		t.Errorf("effective mode = %+v (ok %v), want the user's acceptEdits", eff, ok)
	}
}

func TestOnlyTheDisableValueLocks(t *testing.T) {
	c := fakeHome(t, map[string]string{
		".claude/settings.json": `{"permissions": {"defaultMode": "bypassPermissions", "disableBypassPermissionsMode": "off"}}`,
	})

	perm, _, _ := settingsFor(t, c, model.TrustTrusted)

	if l := modeLayer(t, perm, model.ScopeUser); !l.Origin.InEffect {
		t.Errorf("bypass mode off (%q), want in effect: only \"disable\" locks", l.Origin.Why)
	}
}

func TestAnUnlockedModeIsUntouched(t *testing.T) {
	c := fakeHome(t, map[string]string{
		".claude/settings.json": `{"permissions": {"defaultMode": "acceptEdits", "disableBypassPermissionsMode": "disable"}}`,
	})

	perm, _, _ := settingsFor(t, c, model.TrustTrusted)

	if eff, ok := perm.DefaultMode.Effective(); !ok || eff.Value.String() != "acceptEdits" {
		t.Errorf("effective mode = %+v, want acceptEdits: the lock only stops bypass", eff)
	}
}
