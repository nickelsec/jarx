package claude

import (
	"strings"
	"testing"

	"github.com/nickelsec/jarx/internal/finding"
	"github.com/nickelsec/jarx/internal/model"
)

func unknownByKey(us []model.Unknown) map[string]model.Unknown {
	out := map[string]model.Unknown{}
	for _, u := range us {
		out[u.Key.String()] = u
	}
	return out
}

func TestDocumentedExtrasArentUnknown(t *testing.T) {
	// The settings page shows a $schema line, and the settings reference
	// lists two marketplace aliases.
	c := fakeHome(t, map[string]string{".claude/settings.json": `{
		"$schema": "https://json.schemastore.org/claude-code-settings.json",
		"additionalMarketplaces": {}, "allowedMarketplaces": []}`})

	_, unknown, _ := settingsFor(t, c, model.TrustTrusted)

	if len(unknown) != 0 {
		t.Errorf("unknown = %+v, want none", unknown)
	}
}

func TestTyposGetTheKeyTheyWereMeantToBe(t *testing.T) {
	c := fakeHome(t, map[string]string{".claude/settings.json": `{
		"permisions": {"deny": ["Read(./.env)"]},
		"permissions": {"defaultMod": "plan"},
		"brandNewKey": true}`})

	_, unknown, _ := settingsFor(t, c, model.TrustTrusted)

	got := unknownByKey(unknown)
	for key, near := range map[string]string{
		"permisions":             "permissions",
		"permissions.defaultMod": "permissions.defaultMode",
		"brandNewKey":            "",
	} {
		u, ok := got[key]
		if !ok || u.Near.String() != near {
			t.Errorf("%s = %+v (found %v), want near %q", key, u, ok, near)
		}
	}
}

func TestADeprecatedKeySaysWhatReplacedIt(t *testing.T) {
	c := fakeHome(t, map[string]string{".claude/settings.json": `{"ignorePatterns": ["secrets/**"]}`})

	_, unknown, _ := settingsFor(t, c, model.TrustTrusted)

	u, ok := unknownByKey(unknown)["ignorePatterns"]
	if !ok || !strings.Contains(u.Note.String(), "permissions.deny") {
		t.Errorf("ignorePatterns = %+v, want a note naming permissions.deny", u)
	}
}

func TestAnAliasNextToItsCanonicalKeyIsIgnored(t *testing.T) {
	c := fakeHome(t, map[string]string{".claude/settings.json": `{
		"extraKnownMarketplaces": {}, "additionalMarketplaces": {}}`})

	_, _, fs := settingsFor(t, c, model.TrustTrusted)

	var f finding.Finding
	for _, x := range fs {
		if x.RuleID == "JARX-CLAUDE-005" {
			f = x
		}
	}
	if f.RuleID == "" || !strings.Contains(f.Evidence.String(), "additionalMarketplaces") {
		t.Errorf("findings = %+v, want CLAUDE-005 naming the ignored alias", fs)
	}
}
