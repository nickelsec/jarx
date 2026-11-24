package platform

import (
	"bytes"
	"os"
	"testing"
)

func envOf(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		v, ok := m[k]
		return v, ok
	}
}

func TestTermDecisions(t *testing.T) {
	utf8Linux := map[string]string{"LANG": "en_US.UTF-8"}
	for name, tc := range map[string]struct {
		facts termFacts
		want  Term
	}{
		"windows console with VT and UTF-8": {
			termFacts{tty: true, width: 120, vt: true, utf8: true, goos: "windows", env: envOf(nil)},
			Term{TTY: true, Width: 120, Color: true, Unicode: true},
		},
		"old windows console: no VT, legacy code page": {
			termFacts{tty: true, width: 80, goos: "windows", env: envOf(nil)},
			Term{TTY: true, Width: 80},
		},
		"piped: no color, ASCII, default width": {
			termFacts{goos: "linux", vt: true, env: envOf(utf8Linux)},
			Term{Width: DefaultWidth},
		},
		"piped with COLUMNS": {
			termFacts{goos: "linux", env: envOf(map[string]string{"COLUMNS": "100"})},
			Term{Width: 100},
		},
		"a bad COLUMNS is ignored": {
			termFacts{goos: "linux", env: envOf(map[string]string{"COLUMNS": "wide"})},
			Term{Width: DefaultWidth},
		},
		"linux terminal with a UTF-8 locale": {
			termFacts{tty: true, width: 60, vt: true, goos: "linux", env: envOf(utf8Linux)},
			Term{TTY: true, Width: 60, Color: true, Unicode: true},
		},
		"LC_ALL wins over LANG": {
			termFacts{tty: true, width: 80, vt: true, goos: "linux", env: envOf(map[string]string{"LC_ALL": "C", "LANG": "en_US.UTF-8"})},
			Term{TTY: true, Width: 80, Color: true},
		},
		"utf8 spelled without the dash": {
			termFacts{tty: true, width: 80, vt: true, goos: "darwin", env: envOf(map[string]string{"LC_CTYPE": "en_US.utf8"})},
			Term{TTY: true, Width: 80, Color: true, Unicode: true},
		},
		"NO_COLOR": {
			termFacts{tty: true, width: 80, vt: true, goos: "linux", env: envOf(map[string]string{"NO_COLOR": "1", "LANG": "en_US.UTF-8"})},
			Term{TTY: true, Width: 80, Unicode: true},
		},
		"an empty NO_COLOR doesn't count": {
			termFacts{tty: true, width: 80, vt: true, goos: "linux", env: envOf(map[string]string{"NO_COLOR": "", "LANG": "en_US.UTF-8"})},
			Term{TTY: true, Width: 80, Color: true, Unicode: true},
		},
		"TERM=dumb": {
			termFacts{tty: true, width: 80, vt: true, goos: "linux", env: envOf(map[string]string{"TERM": "dumb", "LANG": "en_US.UTF-8"})},
			Term{TTY: true, Width: 80},
		},
		"a terminal that won't say its width": {
			termFacts{tty: true, vt: true, goos: "linux", env: envOf(utf8Linux)},
			Term{TTY: true, Width: DefaultWidth, Color: true, Unicode: true},
		},
	} {
		if got := decideTerm(tc.facts); got != tc.want {
			t.Errorf("%s: decideTerm() = %+v, want %+v", name, got, tc.want)
		}
	}
}

func TestIsTerminalIsFalseForBuffersPipesAndFiles(t *testing.T) {
	if IsTerminal(&bytes.Buffer{}) {
		t.Error("IsTerminal(buffer) = true, want false")
	}
	f, err := os.CreateTemp(t.TempDir(), "in")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if IsTerminal(f) {
		t.Error("IsTerminal(file) = true, want false")
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close(); _ = w.Close() }()
	if IsTerminal(r) {
		t.Error("IsTerminal(pipe) = true, want false")
	}
}
