package platform

import "fmt"

// Hive is a Windows registry root.
type Hive int

// Hives jarx reads.
const (
	HKLM Hive = iota + 1 // HKEY_LOCAL_MACHINE
	HKCU                 // HKEY_CURRENT_USER
)

func (h Hive) String() string {
	switch h {
	case HKLM:
		return "HKLM"
	case HKCU:
		return "HKCU"
	default:
		return fmt.Sprintf("Hive(%d)", int(h))
	}
}

// MaxRegistryValue caps how big a registry value jarx reads, like fsys's
// file cap.
const MaxRegistryValue = 10 << 20

// Registry reads string values (REG_SZ or REG_EXPAND_SZ, returned as
// stored). A missing key or value is fs.ErrNotExist.
type Registry interface {
	String(h Hive, key, name string) (string, error)
}

// Registry returns the registry, or false when there's none to read: off
// Windows, and always under --home.
func (e Env) Registry() (Registry, bool) {
	return e.registry, e.registry != nil
}

// WithRegistry returns a copy of e that reads r as its registry. Tests use it
// to stand in a fake one.
func (e Env) WithRegistry(r Registry) Env {
	e.registry = r
	return e
}

// WithSystemRoots returns a copy of e with r as its system roots, turned on.
// Tests use it to point managed config dirs inside a fake home.
func (e Env) WithSystemRoots(r Roots) Env {
	e.roots = &r
	e.system = true
	return e
}
