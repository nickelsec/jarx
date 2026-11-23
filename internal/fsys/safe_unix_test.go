//go:build !windows

package fsys

import (
	"errors"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestReadFileRefusesAFIFOWithoutBlocking(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "CLAUDE.md")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("can't make a fifo here: %v", err)
	}

	done := make(chan error, 1)
	go func() { _, err := (&FS{}).ReadFile(fifo); done <- err }()

	select {
	case err := <-done:
		if !errors.Is(err, ErrNotRegular) {
			t.Errorf("ReadFile(fifo) error = %v, want ErrNotRegular", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ReadFile(fifo) blocked")
	}
}
