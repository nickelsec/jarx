package platform

import (
	"errors"
	"io/fs"
	"runtime"
	"testing"
)

type fakeRegistry map[string]string

func (f fakeRegistry) String(h Hive, key, name string) (string, error) {
	if v, ok := f[h.String()+`\`+key+`\`+name]; ok {
		return v, nil
	}
	return "", fs.ErrNotExist
}

func TestFakeHomeHasNoRegistry(t *testing.T) {
	env, err := FromHome(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := env.Registry(); ok {
		t.Error("Registry() ok = true under --home, want false")
	}
}

func TestRealHasARegistryOnlyOnWindows(t *testing.T) {
	env, err := Real()
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := env.Registry(); ok != (runtime.GOOS == goosWindows) {
		t.Errorf("Registry() ok = %v on %s, want %v", ok, runtime.GOOS, runtime.GOOS == goosWindows)
	}
}

func TestWithRegistryInjectsOne(t *testing.T) {
	env, err := FromHome(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	fake := fakeRegistry{`HKLM\SOFTWARE\Policies\X\Settings`: "{}"}

	r, ok := env.WithRegistry(fake).Registry()

	if !ok {
		t.Fatal("Registry() ok = false, want the injected one")
	}
	if v, err := r.String(HKLM, `SOFTWARE\Policies\X`, "Settings"); err != nil || v != "{}" {
		t.Errorf("String() = %q, %v; want the fake's value", v, err)
	}
	if _, err := r.String(HKCU, `SOFTWARE\Policies\X`, "Settings"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("String() missing error = %v, want fs.ErrNotExist", err)
	}
}

func TestWithSystemRootsTurnsThemOn(t *testing.T) {
	env, err := FromHome(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	want := Roots{Etc: env.Home + "/etc"}

	got, ok := env.WithSystemRoots(want).SystemRoots()

	if !ok || got != want {
		t.Errorf("SystemRoots() = %+v, %v; want %+v, true", got, ok, want)
	}
}

func TestHiveNames(t *testing.T) {
	if HKLM.String() != "HKLM" || HKCU.String() != "HKCU" {
		t.Errorf("hive names = %s, %s; want HKLM, HKCU", HKLM, HKCU)
	}
}
