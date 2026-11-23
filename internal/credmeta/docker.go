package credmeta

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
)

// dockerAuthKeys hold a registry credential inline in config.json.
//
//nolint:gochecknoglobals // fixed list, read only
var dockerAuthKeys = []string{"auth", "identitytoken", "registrytoken", keyPassword}

// parseDocker keeps the registries in auths and whether each holds a
// credential inline, and the credsStore and credHelpers helper names. It
// walks the JSON a token at a time and skips every other value.
func parseDocker(_ string, r io.Reader) ([]Fact, error) {
	d := json.NewDecoder(r)
	var out []Fact
	err := objectKeys(d, func(key string) error {
		switch key {
		case "auths":
			return objectKeys(d, func(host string) error { return dockerAuth(d, host, &out) })
		case "credsStore":
			s, err := stringValue(d)
			if err == nil && name.MatchString(s) {
				out = append(out, Fact{"creds store", s})
			}
			return err
		case "credHelpers":
			return objectKeys(d, func(host string) error {
				s, err := stringValue(d)
				if err == nil && name.MatchString(host) && name.MatchString(s) {
					out = append(out, Fact{"cred helper " + host, s})
				}
				return err
			})
		}
		return skipValue(d)
	})
	return out, err
}

// dockerAuth reads one registry's entry in auths: its key names only.
func dockerAuth(d *json.Decoder, host string, out *[]Fact) error {
	var keys []string
	if err := objectKeys(d, func(k string) error { keys = append(keys, k); return skipValue(d) }); err != nil {
		return err
	}
	if !name.MatchString(host) {
		return nil
	}
	inline := ""
	if slices.ContainsFunc(keys, func(k string) bool { return slices.Contains(dockerAuthKeys, k) }) {
		inline = "inline auth"
	}
	*out = append(*out, Fact{"registry " + host, inline})
	return nil
}

var errShape = errors.New("not the expected JSON shape")

// objectKeys reads a JSON object, calling fn with each key. fn must read
// the key's value.
func objectKeys(d *json.Decoder, fn func(key string) error) error {
	t, err := d.Token()
	if err != nil {
		return fmt.Errorf("reading: %w", err)
	}
	if t != json.Delim('{') {
		return errShape
	}
	for d.More() {
		t, err := d.Token()
		if err != nil {
			return fmt.Errorf("reading: %w", err)
		}
		k, ok := t.(string)
		if !ok {
			return errShape
		}
		if err := fn(k); err != nil {
			return err
		}
	}
	if _, err := d.Token(); err != nil { // the closing }
		return fmt.Errorf("reading: %w", err)
	}
	return nil
}

// stringValue reads a value that should be a string; anything else is
// skipped and gives "".
func stringValue(d *json.Decoder) (string, error) {
	t, err := d.Token()
	if err != nil {
		return "", fmt.Errorf("reading: %w", err)
	}
	if s, ok := t.(string); ok {
		return s, nil
	}
	return "", skipRest(d, t)
}

// skipValue reads one value and drops it.
func skipValue(d *json.Decoder) error {
	t, err := d.Token()
	if err != nil {
		return fmt.Errorf("reading: %w", err)
	}
	return skipRest(d, t)
}

// skipRest drops the rest of a value whose first token was t.
func skipRest(d *json.Decoder, t json.Token) error {
	depth := 0
	for {
		if delim, ok := t.(json.Delim); ok {
			if delim == '{' || delim == '[' {
				depth++
			} else {
				depth--
			}
		}
		if depth == 0 {
			return nil
		}
		var err error
		if t, err = d.Token(); err != nil {
			return fmt.Errorf("reading: %w", err)
		}
	}
}
