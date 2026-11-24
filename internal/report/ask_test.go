package report

import (
	"strings"
	"testing"

	"github.com/nickelsec/jarx/internal/redact"
)

func TestAnswerNotesHangOffTheAnswerWithTheTermsGlyphs(t *testing.T) {
	p, s, out, _ := setup(t)
	p.Style = Style{Width: 44, Unicode: true}

	p.AnswerOK(text(s, "https · llm.example.com"), text(s, "12ms"))
	p.AnswerNote(text(s, "plain http only goes to loopback (127.0.0.1, ::1, localhost)"))

	want := "     └─ ok  https · llm.example.com  12ms\n" +
		"     └─ plain http only goes to loopback\n" +
		"        (127.0.0.1, ::1, localhost)\n"
	if out.String() != want {
		t.Errorf("got\n%s\nwant\n%s", out, want)
	}
}

func TestCommandsAreNeverCut(t *testing.T) {
	p, s, out, _ := setup(t)
	p.Style = Style{Width: 40}
	long := "$env:K = [Net.NetworkCredential]::new('', (Read-Host -AsSecureString 'key')).Password"

	p.Commands([]Command{{Label: text(s, "powershell"), Text: text(s, long)}})

	if want := "        powershell  " + long + "\n"; out.String() != want {
		t.Errorf("got %q, want %q", out, want)
	}
}

func TestQuestionHintsWrapInsteadOfBeingCut(t *testing.T) {
	p, s, out, _ := setup(t)
	p.Style = Style{Width: 30}

	p.Question(1, 3, text(s, "model"), text(s, "m-1"), []redact.Text{text(s, "the model name your endpoint expects")})

	want := "1/3  model  [m-1]\n" +
		"     the model name your\n" +
		"     endpoint expects\n"
	if out.String() != want {
		t.Errorf("got\n%s\nwant\n%s", out, want)
	}
	if strings.Contains(out.String(), "...") {
		t.Error("a hint was cut")
	}
}

func TestYesNoShowsTheDefaultInCapitals(t *testing.T) {
	p, s, out, _ := setup(t)

	p.YesNo(text(s, "save?"), true, nil)
	p.YesNo(text(s, "send?"), false, nil)

	if want := "save?  [Y/n]\nsend?  [y/N]\n"; out.String() != want {
		t.Errorf("got %q, want %q", out, want)
	}
}

func text(s *redact.Scrubber, v string) redact.Text {
	t, _ := s.Scrub(v)
	return t
}
