package model

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/nickelsec/jarx/internal/redact"
)

// Path is a file path. It keeps the raw path for reads through fsys and a
// masked copy for everything else. Printing it with any fmt verb, or encoding
// it as JSON, gives the masked copy, so the raw path can't slip into output,
// an error message or a snapshot.
type Path struct {
	raw   string
	shown redact.Text
}

// NewPath makes a Path from raw, masking it with s.
func NewPath(s *redact.Scrubber, raw string) Path {
	shown, _ := s.Scrub(raw)
	return Path{raw: raw, shown: shown}
}

// Raw returns the raw path. Use it only to read the file through fsys.
func (p Path) Raw() string { return p.raw }

// Text returns the masked path, for anything shown or stored.
func (p Path) Text() redact.Text { return p.shown }

// IsZero reports whether p is unset.
func (p Path) IsZero() bool { return p.raw == "" }

// Format prints the masked path for every verb, including %+v and %#v.
func (p Path) Format(f fmt.State, verb rune) {
	if verb == 'q' {
		_, _ = io.WriteString(f, fmt.Sprintf("%q", p.shown.String()))
		return
	}
	_, _ = io.WriteString(f, p.shown.String())
}

// MarshalJSON encodes the masked path.
func (p Path) MarshalJSON() ([]byte, error) {
	b, err := json.Marshal(p.shown)
	if err != nil {
		return nil, fmt.Errorf("encoding path: %w", err)
	}
	return b, nil
}
