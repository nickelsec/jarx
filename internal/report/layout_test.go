package report

import (
	"bytes"
	"strings"
	"testing"
)

func TestCellsCountScreenColumns(t *testing.T) {
	for s, want := range map[string]int{
		"abc":           3,
		"├─ │":          4,
		"\u65e5\u672c":  4, // wide chars take two columns
		"é":            1, // a combining accent takes none
		"\x1b[31m":      len(`\x1b[31m`),
		"tab\there":     len(`tab\x09here`), // escape shows a tab as \x09
		"plain · words": 13,
	} {
		if got := cells(escape(s)); got != want {
			t.Errorf("cells(escape(%q)) = %d, want %d", s, got, want)
		}
	}
}

func TestFitCutsToTheWidthWithAnEllipsis(t *testing.T) {
	for _, st := range []Style{{Unicode: true}, {}} {
		l := line{{text: "HIGH  "}, {text: "a title that goes on and on"}, {text: "  PERMS-001"}}

		got := st.fit(l, 20)

		if c := got.cells(); c != 20 {
			t.Errorf("unicode %v: fit gave %d cells, want 20: %q", st.Unicode, c, got.plain())
		}
		if ell := st.glyphs().ell; !strings.HasSuffix(got.plain(), ell) {
			t.Errorf("unicode %v: %q doesn't end in %q", st.Unicode, got.plain(), ell)
		}
		if short := st.fit(line{{text: "short"}}, 20); short.plain() != "short" {
			t.Errorf("a short line changed: %q", short.plain())
		}
	}
}

func TestWideCharsAreNeverCutInHalf(t *testing.T) {
	got := Style{Unicode: true}.fit(line{{text: "\u65e5\u672c\u8a9e\u306e\u30d1\u30b9"}}, 6)

	if c := got.cells(); c > 6 {
		t.Errorf("fit gave %d cells (%q), want at most 6", c, got.plain())
	}
}

func TestTreesUseTheRightGlyphs(t *testing.T) {
	for st, want := range map[Style]string{
		{Unicode: true}: "├─ one\n│  more\n└─ two\n",
		{}:              "+- one\n|  more\n\\- two\n",
	} {
		var out bytes.Buffer
		p := &Printer{Out: &Stream{w: &out}, Style: st}
		p.tree([]node{{line{{text: "one"}}, line{{text: "more"}}}, {line{{text: "two"}}}})
		if out.String() != want {
			t.Errorf("unicode %v: tree =\n%s\nwant\n%s", st.Unicode, out.String(), want)
		}
	}
}

func TestColorsComeOnlyFromJarx(t *testing.T) {
	var out bytes.Buffer
	p := &Printer{Out: &Stream{w: &out}, Style: Style{Width: 80, Color: true}}

	// A file's text with its own escape codes, trying to recolor the line.
	p.emit(line{{text: escape("evil\x1b[32m green"), tone: plain}, {text: "HIGH", tone: red}})

	got := out.String()
	if strings.Count(got, "\x1b[") != 2 || !strings.Contains(got, `evil\x1b[32m green`) {
		t.Errorf("output = %q, want the file's escape shown as text and only jarx's red and reset as codes", got)
	}
	out.Reset()
	p.Style.Color = false
	p.emit(line{{text: "HIGH", tone: red}})
	if strings.Contains(out.String(), "\x1b") {
		t.Errorf("output = %q, want no codes with color off", out.String())
	}
}
