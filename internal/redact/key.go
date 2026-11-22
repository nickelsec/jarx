package redact

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"

	"github.com/nickelsec/jarx/internal/jarxdir"
	"github.com/nickelsec/jarx/internal/platform"
)

const (
	keyFile = "fingerprint.key"
	keySize = 32
)

// KeyFromState returns a KeySource backed by fingerprint.key in jarx's state
// dir. Nothing is created until the first fingerprint is needed, so a scan
// that finds no secret writes nothing.
func KeyFromState(env platform.Env) KeySource {
	return stateKey{env: env}
}

type stateKey struct {
	env platform.Env
}

// Key reads the key, or makes a new random one if there's none yet. A key of
// the wrong size is an error and is left alone, since replacing it would
// quietly change every fingerprint.
func (k stateKey) Key() ([]byte, error) {
	dir, err := jarxdir.Open(k.env)
	if err != nil {
		return nil, fmt.Errorf("fingerprint key: %w", err)
	}
	defer func() { _ = dir.Close() }()

	key, err := dir.ReadFile(keyFile)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		key = make([]byte, keySize)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("making fingerprint key: %w", err)
		}
		if err := dir.WriteFile(keyFile, key); err != nil {
			return nil, fmt.Errorf("saving fingerprint key: %w", err)
		}
		return key, nil
	case err != nil:
		return nil, fmt.Errorf("fingerprint key: %w", err)
	case len(key) != keySize:
		return nil, fmt.Errorf("fingerprint key %s is damaged; delete it to make a new one (fingerprints will change)",
			filepath.Join(k.env.StateDir, keyFile))
	default:
		return key, nil
	}
}
