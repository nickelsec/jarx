package fsys

import (
	"errors"
	"fmt"

	"github.com/nickelsec/jarx/internal/credmeta"
)

// ErrNotCredential means CredentialFacts was pointed at a path that isn't a
// credential location.
var ErrNotCredential = errors.New("not a credential location")

// CredentialFacts reads a credential file's safe metadata. It's the one
// way past the credential guard: the file goes straight to credmeta's
// parser for its kind, which keeps only the allowed fields, so no caller
// ever gets the file's bytes. Every other check a read makes still applies.
// A credential that's only checked for existence gives credmeta.ErrNotRead.
func (f *FS) CredentialFacts(path string) ([]credmeta.Fact, error) {
	final, err := f.finalPath(path)
	if err != nil {
		return nil, err
	}
	at, ok := credmeta.Locate(f.env, final)
	if !ok {
		at, ok = credmeta.Locate(f.env, path)
	}
	if !ok {
		return nil, fmt.Errorf("%s: %w", path, ErrNotCredential)
	}
	if !at.Read {
		return nil, fmt.Errorf("%s: %w", path, credmeta.ErrNotRead)
	}
	file, err := f.openPlain(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	facts, err := credmeta.Parse(at.Kind, at.Rel, file)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return facts, nil
}
