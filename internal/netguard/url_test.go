package netguard

import (
	"errors"
	"strings"
	"testing"
)

func TestCheckURLAllowsHTTPSAndLoopbackHTTP(t *testing.T) {
	for _, raw := range []string{
		"https://api.example.com/v1",
		"https://llm.internal:8080/v1",
		"https://10.0.0.5/v1", // private is fine, only plain http has to be loopback
		"http://127.0.0.1:11434/v1",
		"http://127.8.9.1/v1",
		"http://[::1]:8000/v1",
		"http://localhost:1234/v1",
		"http://LOCALHOST./v1",
	} {
		if err := CheckURL(raw); err != nil {
			t.Errorf("CheckURL(%q) = %v, want nil", raw, err)
		}
	}
}

func TestCheckURLRefusesWhatARequestWouldRefuse(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want error
	}{
		{"http://llm.internal:8080/v1", ErrInsecure},
		{"http://10.0.0.5/v1", ErrInsecure},
		{"http://localhost.evil.example/v1", ErrInsecure},
		{"ftp://example.com/v1", ErrInsecure},
		{"https://169.254.169.254/latest", ErrBlocked},
		{"https://[fe80::1]/v1", ErrBlocked},
		{"https://metadata.google.internal/v1", ErrBlocked},
		{"https://0.0.0.0/v1", ErrBlocked},
	} {
		if err := CheckURL(tc.raw); !errors.Is(err, tc.want) {
			t.Errorf("CheckURL(%q) = %v, want %v", tc.raw, err, tc.want)
		}
	}
}

func TestCheckURLRefusesPlacesKeysHide(t *testing.T) {
	// A user, a password or a query string is where keys end up in URLs,
	// and jarx never saves a key.
	for _, raw := range []string{
		"https://user:pass@api.example.com/v1",
		"https://token@api.example.com/v1",
		"https://api.example.com/v1?api-key=abc",
		"https://api.example.com/v1?",
		"https://api.example.com/v1#frag",
	} {
		if err := CheckURL(raw); !errors.Is(err, ErrURLSecretSpot) {
			t.Errorf("CheckURL(%q) = %v, want ErrURLSecretSpot", raw, err)
		}
	}
}

func TestCheckURLRefusesWhatIsNotAFullURL(t *testing.T) {
	for _, raw := range []string{"", "api.example.com/v1", "https://", "https:///v1", "/v1", "https://exa mple.com"} {
		if err := CheckURL(raw); !errors.Is(err, ErrBadURL) {
			t.Errorf("CheckURL(%q) = %v, want ErrBadURL", raw, err)
		}
	}
}

func TestCheckURLErrorsDoNotQuoteTheURL(t *testing.T) {
	const canary = "CANARYc4n4ry"
	for _, raw := range []string{
		"https://" + canary + "@api.example.com/v1",
		"https://api.example.com/v1?k=" + canary,
		"http://" + canary + ".example.com/v1",
	} {
		err := CheckURL(raw)
		if err == nil {
			t.Fatalf("CheckURL(%q) = nil, want an error", raw)
		}
		if strings.Contains(err.Error(), canary) {
			t.Errorf("CheckURL(%q) error %q quotes the URL", raw, err)
		}
	}
}
