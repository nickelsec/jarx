package model

import (
	"testing"

	"github.com/nickelsec/jarx/internal/redact"
)

func TestChangeWordSplitsTheToolName(t *testing.T) {
	s, err := redact.New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"delete_repo": "delete", "files.write": "write", "pushFiles": "push", "send-mail": "send",
		"list_notes": "", "readFile": "", "deleted_items": "", "reset": "",
	} {
		n, _ := s.Scrub(name)
		if got := (Offer{Name: n}).ChangeWord(); got != want {
			t.Errorf("ChangeWord(%q) = %q, want %q", name, got, want)
		}
	}
}
