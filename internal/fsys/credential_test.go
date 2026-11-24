package fsys

import (
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/nickelsec/jarx/internal/credmeta"
)

func factStrings(fs []credmeta.Fact) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.Key+"="+f.Value)
	}
	return out
}

func TestCredentialFactsReadsOnlyTheSafeMetadata(t *testing.T) {
	f, home := fakeFS(t)
	creds := filepath.Join(home, ".aws", "credentials")
	write(t, creds, []byte("[dev]\naws_access_key_id = JARX-CANARY-1\naws_secret_access_key = JARX-CANARY-2\n"))

	got, err := f.CredentialFacts(creds)

	if err != nil || !slices.Equal(factStrings(got), []string{"profile dev=static keys"}) {
		t.Fatalf("CredentialFacts = %q, %v; want the profile and its kind", factStrings(got), err)
	}
	if strings.Contains(strings.Join(factStrings(got), " "), "CANARY") {
		t.Error("the facts hold a secret")
	}
	if _, err := f.ReadFile(creds); !errors.Is(err, ErrCredential) {
		t.Errorf("ReadFile error = %v, want the guard to still refuse it", err)
	}
}

func TestCredentialFactsRefusesWhatsExistenceOnly(t *testing.T) {
	f, home := fakeFS(t)
	for _, p := range []string{
		filepath.Join(home, ".aws", "sso", "cache", "token.json"),
		filepath.Join(home, ".config", "gcloud", "application_default_credentials.json"),
		filepath.Join(home, ".claude", ".credentials.json"),
	} {
		write(t, p, []byte("[x]\nJARX-CANARY=1\n"))
		if got, err := f.CredentialFacts(p); !errors.Is(err, credmeta.ErrNotRead) || len(got) != 0 {
			t.Errorf("CredentialFacts(%s) = %q, %v; want ErrNotRead", p, factStrings(got), err)
		}
	}
}

func TestCredentialFactsRefusesWhatIsntACredential(t *testing.T) {
	f, home := fakeFS(t)
	notes := filepath.Join(home, "proj", "notes.md")
	write(t, notes, []byte("just notes"))

	if _, err := f.CredentialFacts(notes); !errors.Is(err, ErrNotCredential) {
		t.Errorf("CredentialFacts(notes.md) error = %v, want ErrNotCredential", err)
	}
}

func TestCredentialFactsKeepsTheOtherGuards(t *testing.T) {
	f, home := fakeFS(t)
	write(t, filepath.Join(home, ".ssh", "keys", "x"), []byte("x"))
	for path, want := range map[string]error{
		filepath.Join(filepath.Dir(home), "outside", ".aws", "credentials"): ErrOutsideHome,
		filepath.Join(home, ".ssh", "keys"):                                 ErrNotRegular,
		"relative/.aws/credentials":                                         ErrNotAbsolute,
	} {
		if _, err := f.CredentialFacts(path); !errors.Is(err, want) {
			t.Errorf("CredentialFacts(%s) error = %v, want %v", path, err, want)
		}
	}
}
