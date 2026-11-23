package platform

import (
	"errors"
	"fmt"
	"io/fs"

	"golang.org/x/sys/windows/registry"
)

// windowsRegistry reads the real registry, 64-bit view, read-only.
type windowsRegistry struct{}

func realRegistry() Registry { return windowsRegistry{} }

func (windowsRegistry) String(h Hive, key, name string) (string, error) {
	root := registry.LOCAL_MACHINE
	if h == HKCU {
		root = registry.CURRENT_USER
	}
	where := h.String() + `\` + key + `\` + name
	k, err := registry.OpenKey(root, key, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if errors.Is(err, registry.ErrNotExist) {
		return "", fs.ErrNotExist
	}
	if err != nil {
		return "", fmt.Errorf("opening %s: %w", where, err)
	}
	defer func() { _ = k.Close() }()

	size, _, err := k.GetValue(name, nil)
	if errors.Is(err, registry.ErrNotExist) {
		return "", fs.ErrNotExist
	}
	if err != nil && !errors.Is(err, registry.ErrShortBuffer) {
		return "", fmt.Errorf("reading %s: %w", where, err)
	}
	if size > MaxRegistryValue {
		return "", fmt.Errorf("%s is over %d bytes", where, MaxRegistryValue)
	}
	v, _, err := k.GetStringValue(name)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", where, err)
	}
	return v, nil
}
