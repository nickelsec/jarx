package llm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nickelsec/jarx/internal/netguard"
	"github.com/nickelsec/jarx/internal/platform"
)

const canaryKey = "CANARYk3y-0000-not-real"

// envWith is a fake --home env with the given .jarx-env content.
func envWith(t *testing.T, jarxEnv string) platform.Env {
	t.Helper()
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, ".jarx-env"), []byte(jarxEnv), 0o600); err != nil {
		t.Fatal(err)
	}
	env, err := platform.FromHome(home)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func TestKeyFromReadsOnlyTheNamedVar(t *testing.T) {
	env := envWith(t, "JARX_LLM_KEY="+canaryKey+"\nOPENAI_API_KEY=other\nEMPTY=\n")

	if _, ok := KeyFrom(env.Lookup, "JARX_LLM_KEY"); !ok {
		t.Error("KeyFrom(JARX_LLM_KEY) not found, want it")
	}
	if _, ok := KeyFrom(env.Lookup, "MISSING"); ok {
		t.Error("KeyFrom(MISSING) found, want not set")
	}
	if _, ok := KeyFrom(env.Lookup, "EMPTY"); ok {
		t.Error("KeyFrom(EMPTY) found, want an empty var to count as no key")
	}
}

func TestKeyNeverPrintsOrEncodes(t *testing.T) {
	env := envWith(t, "K="+canaryKey+"\n")
	key, _ := KeyFrom(env.Lookup, "K")

	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d"} {
		if got := fmt.Sprintf(verb, key); strings.Contains(got, canaryKey) || strings.Contains(got, fmt.Sprintf("%x", canaryKey)) {
			t.Errorf("Sprintf(%s, key) = %q, shows the key", verb, got)
		}
	}
	if got := fmt.Sprintf("%v", struct {
		K Key `json:"k"`
	}{key}); strings.Contains(got, canaryKey) {
		t.Errorf("key in a struct prints as %q", got)
	}
	data, err := json.Marshal(struct {
		K Key `json:"k"`
	}{key})
	if err != nil || strings.Contains(string(data), canaryKey) {
		t.Errorf("json.Marshal = %s, %v; want no key", data, err)
	}
}

// fakeEndpoint is an OpenAI-compatible endpoint on loopback that records
// what it got.
type fakeEndpoint struct {
	status int
	reply  string
	got    []*http.Request
	bodies []string
}

func (f *fakeEndpoint) serve(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.got = append(f.got, r)
		f.bodies = append(f.bodies, string(body))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(f.status)
		_, _ = io.WriteString(w, f.reply)
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/v1"
}

const okReply = `{"id":"x","object":"chat.completion","model":"m-1","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`

func testKey(t *testing.T) Key {
	t.Helper()
	key, ok := KeyFrom(envWith(t, "K="+canaryKey+"\n").Lookup, "K")
	if !ok {
		t.Fatal("no test key")
	}
	return key
}

func TestPingSendsOneFixedChatRequestWithTheKeyInTheHeader(t *testing.T) {
	f := &fakeEndpoint{status: http.StatusOK, reply: okReply}
	base := f.serve(t)

	if _, err := Ping(context.Background(), netguard.New(), base, "m-1", testKey(t)); err != nil {
		t.Fatalf("Ping() error = %v", err)
	}

	if len(f.got) != 1 {
		t.Fatalf("endpoint got %d requests, want 1", len(f.got))
	}
	r := f.got[0]
	if r.Method != http.MethodPost || r.URL.Path != "/v1/chat/completions" {
		t.Errorf("request = %s %s, want POST /v1/chat/completions", r.Method, r.URL.Path)
	}
	if got := r.Header.Get("Authorization"); got != "Bearer "+canaryKey {
		t.Errorf("Authorization = %q, want the bearer key", got)
	}
	if strings.Contains(f.bodies[0], canaryKey) || r.URL.RawQuery != "" {
		t.Errorf("the key went somewhere other than the header: body %q, query %q", f.bodies[0], r.URL.RawQuery)
	}
	checkPingBody(t, f.bodies[0])
}

// checkPingBody checks the body is the model and only the fixed ping text.
func checkPingBody(t *testing.T, raw string) {
	t.Helper()
	var body struct {
		Model    string `json:"model"`
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		t.Fatalf("body isn't JSON: %v", err)
	}
	if body.Model != "m-1" || len(body.Messages) != 1 || body.Messages[0].Content != PingText {
		t.Errorf("body = %+v, want model m-1 and only the fixed ping text", body)
	}
}

func TestPingTrimsATrailingSlashOnTheBaseURL(t *testing.T) {
	f := &fakeEndpoint{status: http.StatusOK, reply: okReply}
	base := f.serve(t)

	if _, err := Ping(context.Background(), netguard.New(), base+"/", "m-1", testKey(t)); err != nil {
		t.Fatalf("Ping() error = %v", err)
	}
	if got := f.got[0].URL.Path; got != "/v1/chat/completions" {
		t.Errorf("path = %q, want /v1/chat/completions", got)
	}
}

func TestPingFailuresSayWhatKindWithoutQuotingAnything(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		reply  string
		want   error
	}{
		{"key rejected", http.StatusUnauthorized, `{"error":"bad key ` + canaryKey + `"}`, ErrKeyRejected},
		{"forbidden", http.StatusForbidden, `{}`, ErrKeyRejected},
		{"not found", http.StatusNotFound, canaryKey, ErrStatus},
		{"server error", http.StatusInternalServerError, canaryKey, ErrStatus},
		{"not json", http.StatusOK, "hello " + canaryKey, ErrBadReply},
		{"no choices", http.StatusOK, `{"choices":[]}`, ErrBadReply},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeEndpoint{status: tc.status, reply: tc.reply}
			base := f.serve(t)

			_, err := Ping(context.Background(), netguard.New(), base, "m-1", testKey(t))

			if !errors.Is(err, tc.want) {
				t.Fatalf("Ping() error = %v, want %v", err, tc.want)
			}
			if strings.Contains(err.Error(), canaryKey) || strings.Contains(err.Error(), "127.0.0.1") {
				t.Errorf("error %q quotes the reply, key or URL", err)
			}
		})
	}
}

func TestPingStatusErrorNamesTheCode(t *testing.T) {
	f := &fakeEndpoint{status: http.StatusNotFound, reply: "{}"}
	base := f.serve(t)

	_, err := Ping(context.Background(), netguard.New(), base, "m-1", testKey(t))

	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("Ping() error = %v, want it to name 404", err)
	}
}

func TestPingUnreachableDoesNotQuoteTheURL(t *testing.T) {
	// A closed loopback port: the connection is refused.
	srv := httptest.NewServer(http.NotFoundHandler())
	base := srv.URL + "/v1/" + canaryKey
	srv.Close()

	_, err := Ping(context.Background(), netguard.New(), base, "m-1", testKey(t))

	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("Ping() error = %v, want ErrUnreachable", err)
	}
	if strings.Contains(err.Error(), canaryKey) {
		t.Errorf("error %q quotes the URL", err)
	}
}

func TestPingRefusesAURLCheckURLRefuses(t *testing.T) {
	f := &fakeEndpoint{status: http.StatusOK, reply: okReply}
	f.serve(t)

	_, err := Ping(context.Background(), netguard.New(), "http://llm.example.com/v1", "m-1", testKey(t))

	if !errors.Is(err, netguard.ErrInsecure) || len(f.got) != 0 {
		t.Errorf("Ping() error = %v with %d requests, want ErrInsecure and none sent", err, len(f.got))
	}
}
