package report

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/nickelsec/jarx/internal/redact"
)

const canary = "tok_Xq7Lm2Pz9Rw4Tb8Nc1Vd" // made up for tests

func setup(t *testing.T) (*Printer, *redact.Scrubber, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	s, err := redact.New([]redact.Pattern{
		{Kind: "test_token", Re: regexp.MustCompile(`tok_[A-Za-z0-9]{16,}`)},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var out, errw bytes.Buffer
	return New(&out, &errw, s), s, &out, &errw
}

func TestOutPrintfWritesMaskedTextToStdout(t *testing.T) {
	p, s, out, errw := setup(t)
	v, _ := s.Scrub("key " + canary)

	p.Out.Printf("value: %s\n", v)

	if out.String() != "value: key REDACTED:test_token\n" {
		t.Errorf("stdout = %q, want the masked value", out.String())
	}
	if errw.Len() != 0 {
		t.Errorf("stderr = %q, want empty", errw.String())
	}
}

func TestErrPrintfWritesToStderr(t *testing.T) {
	p, s, out, errw := setup(t)
	v, _ := s.Scrub("frobnicate")

	p.Err.Printf("jarx: unknown command %q\n", v)

	if errw.String() != "jarx: unknown command \"frobnicate\"\n" {
		t.Errorf("stderr = %q", errw.String())
	}
	if out.Len() != 0 {
		t.Errorf("stdout = %q, want empty", out.String())
	}
}

func TestErrorScrubsTheErrorText(t *testing.T) {
	// A parser error can quote the offending line, secret and all.
	p, _, _, errw := setup(t)
	err := fmt.Errorf("reading config: %w", errors.New(`line 3: bad value "`+canary+`"`))

	p.Error(err)

	if strings.Contains(errw.String(), canary) {
		t.Errorf("stderr = %q, leaks the secret from the error", errw.String())
	}
	if errw.String() != "jarx: reading config: line 3: bad value \"REDACTED:test_token\"\n" {
		t.Errorf("stderr = %q, want the scrubbed error", errw.String())
	}
}
