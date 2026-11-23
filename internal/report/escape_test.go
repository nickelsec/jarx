package report

import "testing"

func TestValuesCantDriveTheTerminal(t *testing.T) {
	p, s, out, _ := setup(t)
	// A hostile file name or file text: an ANSI color and cursor move, a
	// fake second line, a carriage return that overwrites the line, a bell,
	// an 8-bit CSI, and a bidi override that flips how text reads.
	v, _ := s.Scrub("a\x1b[31mred\x1b[2Jb\nfake line\rover\a\u009b1m\u202edcba\u2066x\u2069")

	p.Out.Printf("value: %s\n", v)

	want := `value: a\x1b[31mred\x1b[2Jb\x0afake line\x0dover\x07\u009b1m\u202edcba\u2066x\u2069` + "\n"
	if out.String() != want {
		t.Errorf("stdout = %q, want %q", out.String(), want)
	}
}

func TestOnlyControlCharsAreEscaped(t *testing.T) {
	p, s, out, _ := setup(t)
	v, _ := s.Scrub(`C:\work\app  tab	here, ünïcödé, ελληνικά`)

	p.Out.Printf("%s\n", v)

	if want := "C:\\work\\app  tab\\x09here, ünïcödé, ελληνικά\n"; out.String() != want {
		t.Errorf("stdout = %q, want %q", out.String(), want)
	}
}
