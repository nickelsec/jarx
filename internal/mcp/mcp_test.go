package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nickelsec/jarx/internal/fakemcp"
	"github.com/nickelsec/jarx/internal/netguard"
)

func tools(n int) []json.RawMessage {
	out := make([]json.RawMessage, 0, n)
	for i := range n {
		out = append(out, json.RawMessage(`{"name": "t`+string(rune('a'+i))+`", "inputSchema": {"type": "object"}}`))
	}
	return out
}

func somePrompts() []json.RawMessage {
	return []json.RawMessage{json.RawMessage(`{"name": "summarize"}`)}
}

func someResources() []json.RawMessage {
	return []json.RawMessage{json.RawMessage(`{"uri": "file:///notes.md", "name": "notes"}`)}
}

// stdio runs a fake server on pipes and lists it.
func stdio(t *testing.T, sc fakemcp.Script, opts Options) (Listing, *fakemcp.Server, error) {
	t.Helper()
	srv := fakemcp.New(sc)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	go func() {
		_ = srv.ServeStdio(ctx, inR, outW, io.Discard)
		_ = outW.Close()
	}()
	l, err := ListStdio(ctx, inW, outR, opts)
	_ = inW.Close()
	return l, srv, err
}

func names(items []json.RawMessage) []string {
	out := make([]string, 0, len(items))
	for _, it := range items {
		var v struct {
			Name string `json:"name"`
		}
		_ = json.Unmarshal(it, &v)
		out = append(out, v.Name)
	}
	return out
}

func onlyListed(t *testing.T, srv *fakemcp.Server) {
	t.Helper()
	if f := srv.Forbidden(); len(f) > 0 {
		t.Errorf("the client sent %q, want only discovery and lists", f)
	}
}

func TestAModernStdioServerIsListed(t *testing.T) {
	l, srv, err := stdio(t, fakemcp.Script{Tools: tools(2), Prompts: somePrompts(), Resources: someResources(), Instructions: "hi"}, Options{})

	if err != nil {
		t.Fatal(err)
	}
	if l.Era != EraModern || l.Version != "2026-07-28" || l.Instructions != "hi" {
		t.Errorf("listing = %s %s %q, want modern 2026-07-28 with the instructions", l.Era, l.Version, l.Instructions)
	}
	if !slices.Equal(names(l.Tools), []string{"ta", "tb"}) || len(l.Prompts) != 1 || len(l.Resources) != 1 {
		t.Errorf("tools %q, %d prompts, %d resources; want 2, 1, 1", names(l.Tools), len(l.Prompts), len(l.Resources))
	}
	if got := srv.Received(); slices.Contains(got, "initialize") {
		t.Errorf("received %q, want no initialize for a modern server", got)
	}
	onlyListed(t, srv)
}

func TestALegacyStdioServerGetsInitialize(t *testing.T) {
	l, srv, err := stdio(t, fakemcp.Script{Era: fakemcp.EraLegacy, Tools: tools(1)}, Options{})

	if err != nil {
		t.Fatal(err)
	}
	if l.Era != EraLegacy || l.Version != "2025-11-25" || len(l.Tools) != 1 {
		t.Errorf("listing = %s %s with %d tools, want legacy 2025-11-25 with 1", l.Era, l.Version, len(l.Tools))
	}
	got := srv.Received()
	if i := slices.Index(got, "initialize"); i < 0 || !slices.Contains(got[i:], "notifications/initialized") {
		t.Errorf("received %q, want initialize then notifications/initialized", got)
	}
	onlyListed(t, srv)
}

func TestASilentDiscoverFallsBackToInitialize(t *testing.T) {
	sc := fakemcp.Script{Era: fakemcp.EraLegacy, Tools: tools(1), Bad: fakemcp.Bad{Hang: []string{"server/discover"}}}

	l, srv, err := stdio(t, sc, Options{DiscoverWait: 100 * time.Millisecond})

	if err != nil || l.Era != EraLegacy || len(l.Tools) != 1 {
		t.Fatalf("listing = %+v, %v; want legacy with the tool", l, err)
	}
	onlyListed(t, srv)
}

func TestListsAreFollowedPageByPage(t *testing.T) {
	l, srv, err := stdio(t, fakemcp.Script{Tools: tools(5), PageSize: 2}, Options{})

	if err != nil || !slices.Equal(names(l.Tools), []string{"ta", "tb", "tc", "td", "te"}) {
		t.Errorf("tools = %q, %v; want all five", names(l.Tools), err)
	}
	onlyListed(t, srv)
}

func TestARepeatingCursorStopsThePaging(t *testing.T) {
	l, srv, err := stdio(t, fakemcp.Script{Tools: tools(1), Bad: fakemcp.Bad{LoopCursor: true}}, Options{})

	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, m := range srv.Received() {
		if m == "tools/list" {
			n++
		}
	}
	if n > 2 || !hasNote(l, "cursor") {
		t.Errorf("tools/list sent %d times, notes %q; want it to stop when the cursor repeats", n, l.Notes)
	}
}

func hasNote(l Listing, word string) bool {
	return slices.ContainsFunc(l.Notes, func(n string) bool { return strings.Contains(n, word) })
}

func TestPagingStopsAtTheCap(t *testing.T) {
	// A fresh cursor every page: one tool per page, more pages than the cap.
	l, srv, err := stdio(t, fakemcp.Script{Tools: tools(26), PageSize: 1}, Options{MaxPages: 10})

	if err != nil {
		t.Fatal(err)
	}
	if len(l.Tools) != 10 || !hasNote(l, "pages") {
		t.Errorf("%d tools, notes %q; want 10 and a note about the page cap", len(l.Tools), l.Notes)
	}
	onlyListed(t, srv)
}

func TestTheClientNeverAnswersTheServer(t *testing.T) {
	sc := fakemcp.Script{Tools: tools(1), Bad: fakemcp.Bad{ServerRequests: true, Notifications: 2, WrongID: true, Garbage: true}}

	l, srv, err := stdio(t, sc, Options{})

	if err != nil || len(l.Tools) != 1 {
		t.Fatalf("listing = %+v, %v; want the tool despite the noise", l, err)
	}
	onlyListed(t, srv) // a response to sampling/createMessage would show here
	if l.Noise.ServerRequests == 0 || l.Noise.Notifications == 0 || l.Noise.WrongIDs == 0 || l.Noise.NotJSON == 0 {
		t.Errorf("noise = %+v, want each kind counted", l.Noise)
	}
}

func TestAListThatAsksForInputGivesNothing(t *testing.T) {
	l, srv, err := stdio(t, fakemcp.Script{Tools: tools(1), Bad: fakemcp.Bad{InputRequired: true}}, Options{})

	if err != nil || len(l.Tools) != 0 || !hasNote(l, "input") {
		t.Errorf("listing = %+v, %v; want no tools and a note", l, err)
	}
	onlyListed(t, srv)
}

func TestAHungListTimesOut(t *testing.T) {
	srv := fakemcp.New(fakemcp.Script{Tools: tools(1), Bad: fakemcp.Bad{Hang: []string{"tools/list"}}})
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	go func() { _ = srv.ServeStdio(context.Background(), inR, outW, io.Discard) }()
	defer func() { _ = inW.Close(); _ = outW.Close() }()

	_, err := ListStdio(ctx, inW, outR, Options{})

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want the deadline", err)
	}
}

func TestAHugeLineIsRefused(t *testing.T) {
	_, _, err := stdio(t, fakemcp.Script{Bad: fakemcp.Bad{Pad: MaxMessage + 1}}, Options{})

	if !errors.Is(err, ErrTooLarge) {
		t.Errorf("err = %v, want ErrTooLarge", err)
	}
}

func TestOnlyListMethodsCanBeSent(t *testing.T) {
	for _, m := range []string{"tools/call", "resources/read", "prompts/get", "sampling/createMessage", "completion/complete", "logging/setLevel", "subscriptions/listen", ""} {
		if _, err := encode(1, m, nil); !errors.Is(err, ErrForbiddenMethod) {
			t.Errorf("encode(%q) = %v, want ErrForbiddenMethod", m, err)
		}
	}
	for _, m := range []string{methodDiscover, methodInitialize, methodToolsList, methodPromptsList, methodResourcesList} {
		if _, err := encode(1, m, nil); err != nil {
			t.Errorf("encode(%q) = %v, want it allowed", m, err)
		}
	}
}

// serve runs the fake server over loopback HTTP.
func serve(t *testing.T, sc fakemcp.Script) (*fakemcp.Server, string) {
	t.Helper()
	srv := fakemcp.New(sc)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return srv, ts.URL
}

func listHTTP(t *testing.T, url string, h http.Header) (Listing, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	return ListHTTP(ctx, netguard.New(), url, h, Options{})
}

func TestAModernHTTPServerIsListed(t *testing.T) {
	srv, url := serve(t, fakemcp.Script{Tools: tools(2)})

	l, err := listHTTP(t, url+"/mcp", nil)

	if err != nil || l.Era != EraModern || l.Transport != TransportHTTP || len(l.Tools) != 2 {
		t.Fatalf("listing = %+v, %v; want modern streamable HTTP with 2 tools", l, err)
	}
	onlyListed(t, srv)
}

func TestAnSSEAnswerIsRead(t *testing.T) {
	srv, url := serve(t, fakemcp.Script{Tools: tools(1), Bad: fakemcp.Bad{SSE: true, Notifications: 1}})

	l, err := listHTTP(t, url+"/mcp", nil)

	if err != nil || len(l.Tools) != 1 {
		t.Fatalf("listing = %+v, %v; want the tool from the SSE answer", l, err)
	}
	onlyListed(t, srv)
}

func TestALegacyHTTPServerFallsBackToInitialize(t *testing.T) {
	srv, url := serve(t, fakemcp.Script{Era: fakemcp.EraLegacy, Tools: tools(1)})

	l, err := listHTTP(t, url+"/mcp", nil)

	if err != nil || l.Era != EraLegacy || l.Transport != TransportHTTP || len(l.Tools) != 1 {
		t.Fatalf("listing = %+v, %v; want legacy streamable HTTP with the tool", l, err)
	}
	onlyListed(t, srv)
}

func TestTheOldSSETransportIsTheLastFallback(t *testing.T) {
	srv, url := serve(t, fakemcp.Script{Era: fakemcp.EraLegacy, Tools: tools(1), Bad: fakemcp.Bad{LegacySSE: true}})

	l, err := listHTTP(t, url+"/sse", nil)

	if err != nil || l.Transport != TransportSSE || len(l.Tools) != 1 {
		t.Fatalf("listing = %+v, %v; want the tool over HTTP+SSE", l, err)
	}
	onlyListed(t, srv)
}

func TestAuthFailuresSayWhichStatus(t *testing.T) {
	_, url := serve(t, fakemcp.Script{Bad: fakemcp.Bad{RequireBearer: "tok_right"}})

	_, err := listHTTP(t, url+"/mcp", nil)

	var se *StatusError
	if !errors.As(err, &se) || se.Code != http.StatusUnauthorized {
		t.Errorf("err = %v, want a 401 StatusError", err)
	}
}

func TestConfiguredHeadersAreSent(t *testing.T) {
	srv, url := serve(t, fakemcp.Script{Tools: tools(1), Bad: fakemcp.Bad{RequireBearer: "tok_right"}})

	l, err := listHTTP(t, url+"/mcp", http.Header{"Authorization": {"Bearer tok_right"}})

	if err != nil || len(l.Tools) != 1 {
		t.Fatalf("listing = %+v, %v; want the tool with the token sent", l, err)
	}
	onlyListed(t, srv)
}

func TestARedirectIsNotFollowed(t *testing.T) {
	_, url := serve(t, fakemcp.Script{Bad: fakemcp.Bad{Redirect: "http://169.254.169.254/latest/meta-data/"}})

	_, err := listHTTP(t, url+"/mcp", nil)

	if !errors.Is(err, netguard.ErrRedirect) {
		t.Errorf("err = %v, want netguard.ErrRedirect", err)
	}
}

func TestAnSSEEndpointOnAnotherOriginIsRefused(t *testing.T) {
	// A legacy SSE stream that tells the client to post somewhere else.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "no", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "event: endpoint\ndata: https://collector.example.net/messages\n\n")
	}))
	t.Cleanup(ts.Close)

	_, err := listHTTP(t, ts.URL+"/sse", nil)

	if !errors.Is(err, ErrOtherOrigin) {
		t.Errorf("err = %v, want ErrOtherOrigin", err)
	}
}

func TestAModernOnlyServerGetsTheVersionInEveryRequest(t *testing.T) {
	l, srv, err := stdio(t, fakemcp.Script{Era: fakemcp.EraModern, Tools: tools(1), Prompts: somePrompts()}, Options{})

	if err != nil || len(l.Tools) != 1 || len(l.Prompts) != 1 {
		t.Fatalf("listing = %+v, %v; want the tool and prompt from a strict modern server", l, err)
	}
	onlyListed(t, srv)
}

func TestOnlyWhatTheServerHasIsListed(t *testing.T) {
	_, srv, err := stdio(t, fakemcp.Script{Tools: tools(1), Capabilities: []string{"tools"}}, Options{})

	if err != nil {
		t.Fatal(err)
	}
	if got := srv.Received(); slices.Contains(got, "prompts/list") || slices.Contains(got, "resources/list") {
		t.Errorf("received %q, want only the tools list", got)
	}
}

// scripted is a stdio server that answers each method with a fixed reply.
func scripted(t *testing.T, replies map[string]string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	go func() {
		defer func() { _ = outW.Close() }()
		dec := json.NewDecoder(inR)
		for {
			var m struct {
				ID     json.RawMessage `json:"id"`
				Method string          `json:"method"`
			}
			if dec.Decode(&m) != nil {
				return
			}
			r, ok := replies[m.Method]
			if !ok || len(m.ID) == 0 {
				continue
			}
			_, _ = io.WriteString(outW, `{"jsonrpc": "2.0", "id": `+string(m.ID)+`, `+r+"}\n")
		}
	}()
	_, err := ListStdio(ctx, inW, outR, Options{DiscoverWait: time.Second})
	_ = inW.Close()
	return err
}

func TestAServerWithNoVersionInCommonIsRefused(t *testing.T) {
	for name, replies := range map[string]map[string]string{
		"modern, other versions": {"server/discover": `"result": {"supportedVersions": ["2027-01-01"], "capabilities": {}}`},
		"unsupported version":    {"server/discover": `"error": {"code": -32022, "message": "no", "data": {"supported": ["2027-01-01"]}}`},
		"legacy, unknown version": {
			"server/discover": `"error": {"code": -32601, "message": "no such method"}`,
			"initialize":      `"result": {"protocolVersion": "1999-01-01", "capabilities": {}}`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := scripted(t, replies); !errors.Is(err, ErrUnsupported) {
				t.Errorf("err = %v, want ErrUnsupported", err)
			}
		})
	}
}

func TestTheOldSSETransportSendsTheConfiguredHeaders(t *testing.T) {
	srv, url := serve(t, fakemcp.Script{Era: fakemcp.EraLegacy, Tools: tools(1), Bad: fakemcp.Bad{LegacySSE: true, RequireBearer: "tok_right"}})

	l, err := listHTTP(t, url+"/sse", http.Header{"Authorization": {"Bearer tok_right"}})

	if err != nil || len(l.Tools) != 1 {
		t.Fatalf("listing = %+v, %v; want the tool with the token sent on the stream too", l, err)
	}
	onlyListed(t, srv)
}

func TestListSSEGoesStraightToTheStream(t *testing.T) {
	srv, url := serve(t, fakemcp.Script{Era: fakemcp.EraLegacy, Tools: tools(1), Bad: fakemcp.Bad{LegacySSE: true}})
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	l, err := ListSSE(ctx, netguard.New(), url+"/sse", nil, Options{})

	if err != nil || len(l.Tools) != 1 || l.Transport != TransportSSE {
		t.Fatalf("listing = %+v, %v; want the tool over HTTP+SSE", l, err)
	}
	if got := srv.Received(); len(got) == 0 || got[0] != "initialize" {
		t.Errorf("received %q, want initialize first, with no modern POST before it", got)
	}
}
