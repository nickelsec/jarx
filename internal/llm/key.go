// Package llm is the optional LLM review's client. It talks to an
// OpenAI-compatible endpoint through netguard, with the key read from the
// env var the user named. jarx never stores the key.
package llm

import "fmt"

// Key is the LLM key, read from the env var the user named. Like
// model.Launch it keeps its value unexported: it prints as [key] for every
// fmt verb and encodes as JSON null, so it can't reach output, a log or a
// file by accident. Only this package reads the value, to set the
// Authorization header.
type Key struct {
	value string
}

const keyMask = "[key]"

// KeyFrom reads the key from the env var name through lookup. jarx passes
// the real terminal's env, even with --home: the key is set in the
// terminal jarx runs in, never in a file. An unset or empty var is no key.
func KeyFrom(lookup func(string) (string, bool), name string) (Key, bool) {
	if lookup == nil {
		return Key{}, false
	}
	v, ok := lookup(name)
	if !ok || v == "" {
		return Key{}, false
	}
	return Key{value: v}, true
}

// String is the mask, never the key.
func (Key) String() string { return keyMask }

// GoString is the mask, for %#v.
func (Key) GoString() string { return keyMask }

// Format writes the mask for every verb.
func (Key) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(keyMask)) }

// MarshalJSON encodes the key as null.
func (Key) MarshalJSON() ([]byte, error) { return []byte("null"), nil }
