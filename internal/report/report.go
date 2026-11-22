// Package report is the only package that writes jarx's output. Lint bans
// fmt.Print*, fmt.Fprint*, os.Stdout, os.Stderr, print, println, log and
// log/slog everywhere else.
//
// Values only go in as redact.Text. The format string has the unexported
// type format, so callers can pass a string literal or an untyped constant,
// but never a string variable: a raw string can't sneak in as the format.
package report

import (
	"fmt"
	"io"

	"github.com/nickelsec/jarx/internal/redact"
)

// format is a printf format. Only untyped constants convert to it
// implicitly, and other packages can't name it to convert explicitly.
type format string

// Stream is one output stream, stdout or stderr.
type Stream struct {
	w io.Writer
}

// Printf writes to the stream.
func (s *Stream) Printf(f format, args ...redact.Text) {
	vals := make([]any, len(args))
	for i, a := range args {
		vals[i] = a.String()
	}
	_, _ = fmt.Fprintf(s.w, string(f), vals...)
}

// Printer writes jarx's output.
type Printer struct {
	Out *Stream
	Err *Stream

	scrub *redact.Scrubber
}

// New returns a Printer that writes to out and errw. scrub masks error text
// in Error.
func New(out, errw io.Writer, scrub *redact.Scrubber) *Printer {
	return &Printer{Out: &Stream{w: out}, Err: &Stream{w: errw}, scrub: scrub}
}

// Error writes "jarx: <err>" to stderr. The error text is scrubbed first,
// since a parser error can quote the line it failed on.
func (p *Printer) Error(err error) {
	text, _ := p.scrub.Scrub(err.Error())
	p.Err.Printf("jarx: %s\n", text)
}
