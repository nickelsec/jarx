package agent

import "testing"

func TestNearKeyFindsLikelyTypos(t *testing.T) {
	known := []string{"permissions", "approval_policy", "defaultMode", "model", "theme", "sandbox_mode", "sandbox_workspace_write"}
	for key, want := range map[string]string{
		"permisions":      "permissions",     // a dropped letter
		"permissoins":     "permissions",     // swapped letters count as one edit
		"aproval_policy":  "approval_policy", // a dropped letter
		"approval-policy": "approval_policy", // one changed char
		"DefaultMode":     "defaultMode",     // case only
		"sandbox_mod":     "sandbox_mode",
		"mdl":             "",      // too short to guess: model is two edits away
		"teme":            "theme", // short keys allow one edit
		"completelynew":   "",
		"sandbox_modes":   "sandbox_mode",
	} {
		if got := NearKey(key, known); got != want {
			t.Errorf("NearKey(%q) = %q, want %q", key, got, want)
		}
	}
}

func TestASwapIsOneEdit(t *testing.T) {
	// mdoe is one swap from mode but two plain edits, and a key under five
	// chars only allows one.
	if got := NearKey("mdoe", []string{"mode"}); got != "mode" {
		t.Errorf("NearKey(mdoe) = %q, want mode", got)
	}
}

func TestCaseDoesntCountAsEdits(t *testing.T) {
	// All caps and a dropped letter: three edits if case counted.
	if got := NearKey("ALLOWEDMCPSERVER", []string{"allowedMcpServers"}); got != "allowedMcpServers" {
		t.Errorf("NearKey() = %q, want allowedMcpServers", got)
	}
}

func TestNearKeyGivesNoGuessOnATie(t *testing.T) {
	if got := NearKey("modex", []string{"model", "modes"}); got != "" {
		t.Errorf("NearKey() = %q, want no guess between two keys one edit away", got)
	}
}
