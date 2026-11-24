package jarxdir

import (
	"errors"
	"io/fs"
	"os"
	"testing"

	"github.com/nickelsec/jarx/internal/platform"
)

func TestReadStateNeverCreatesTheStateDir(t *testing.T) {
	env, err := platform.FromHome(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	if _, err := ReadState(env, "history-cursor.json"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("ReadState() error = %v, want fs.ErrNotExist", err)
	}
	if _, err := os.Stat(env.StateDir); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("state dir stat = %v, want it still missing: reading creates nothing", err)
	}
}

func TestReadStateReadsWhatWasWritten(t *testing.T) {
	d, env := openDir(t)
	if err := d.WriteFile("history-cursor.json", []byte("{}")); err != nil {
		t.Fatal(err)
	}

	got, err := ReadState(env, "history-cursor.json")
	if err != nil || string(got) != "{}" {
		t.Errorf("ReadState() = %q, %v, want {}", got, err)
	}
	if _, err := ReadState(env, "../outside"); err == nil {
		t.Error("ReadState(../outside) worked, want it refused")
	}
}
