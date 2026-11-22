package platform

import (
	"errors"
	"io/fs"
	"testing"
)

func TestWindowsRegistryMissingKeyIsNotExist(t *testing.T) {
	// Reads a key that can't exist, so no real setting is ever read.
	_, err := windowsRegistry{}.String(HKCU, `SOFTWARE\jarx-test-key-that-does-not-exist`, "Settings")

	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("String() error = %v, want fs.ErrNotExist", err)
	}
}
