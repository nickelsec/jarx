package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"github.com/nickelsec/jarx/internal/netguard"
)

const (
	contentJSON = "application/json"
	contentSSE  = "text/event-stream"
	errBodyCap  = 64 << 10 // how much of an error body is read
	// headerSinceVersion is the first legacy revision with the
	// Mcp-Protocol-Version header.
	headerSinceVersion = "2025-06-18"
)

// ListHTTP lists a remote server at rawURL through the netguard client c.
// header is what the agent would send, like a configured Authorization. It
// tries the modern protocol, then legacy streamable HTTP, then the old
// HTTP+SSE transport, each only when the one before says it isn't there.
func ListHTTP(ctx context.Context, c *netguard.Client, rawURL string, header http.Header, opts Options) (Listing, error) {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return Listing{}, fmt.Errorf("%w: not an http or https URL", ErrProtocol)
	}
	l := Listing{Transport: TransportHTTP}
	t := &httpTransport{c: c, url: u, header: header, noise: &l.Noise, modern: true}
	s := &session{t: t, opts: opts, l: &l}
	caps, err := discoverHTTP(ctx, s, t)
	if errors.Is(err, errNotHere) {
		t.modern, t.version = false, ""
		caps, err = s.initialize(ctx)
		if errors.Is(err, errNotHere) {
			return listSSE(ctx, c, u, header, opts)
		}
	}
	if err != nil {
		return l, err
	}
	t.setVersion(s.version)
	return l, s.listAll(ctx, caps)
}

// errNotHere is a 4xx with no JSON-RPC body: the server doesn't speak what
// was tried, so the next transport is worth a try.
var errNotHere = errors.New("mcp: not this transport")

// discoverHTTP sends server/discover. A modern error body means a modern
// server; a 4xx without one means legacy.
func discoverHTTP(ctx context.Context, s *session, t *httpTransport) (map[string]any, error) {
	s.era = EraModern
	t.version = modernVersion
	raw, err := s.call(ctx, methodDiscover, s.params(nil))
	var rerr *RPCError
	switch {
	case err == nil:
		return s.discovered(raw)
	case errors.As(err, &rerr) && rerr.Code == codeUnsupportedVersion:
		return nil, fmt.Errorf("%w: %s", ErrUnsupported, rerr.Data)
	}
	return nil, err
}

type httpTransport struct {
	c       *netguard.Client
	url     *url.URL
	header  http.Header
	noise   *Noise
	modern  bool
	version string // for the Mcp-Protocol-Version header, "" for none
	session string // Mcp-Session-Id from a legacy server
}

// setVersion sets the version header once the era is known: always for
// modern, and for legacy only from the revision that added it.
func (t *httpTransport) setVersion(v string) {
	t.version = ""
	if t.modern || v >= headerSinceVersion {
		t.version = v
	}
}

func (t *httpTransport) post(ctx context.Context, method string, body []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.url.String(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("mcp: request: %w", err)
	}
	maps.Copy(req.Header, t.header)
	req.Header.Set("Content-Type", contentJSON)
	req.Header.Set("Accept", contentJSON+", "+contentSSE)
	if t.version != "" {
		req.Header.Set("Mcp-Protocol-Version", t.version)
	}
	if t.modern {
		req.Header.Set("Mcp-Method", method)
	}
	if t.session != "" {
		req.Header.Set("Mcp-Session-Id", t.session)
	}
	resp, err := t.c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("mcp: %w", err)
	}
	return resp, nil
}

func (t *httpTransport) notify(ctx context.Context, method string, body []byte) error {
	resp, err := t.post(ctx, method, body)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode >= http.StatusBadRequest {
		return &StatusError{Code: resp.StatusCode}
	}
	return nil
}

func (t *httpTransport) request(ctx context.Context, method string, id int, body []byte) (message, error) {
	resp, err := t.post(ctx, method, body)
	if err != nil {
		return message{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" && !t.modern {
		t.session = sid
	}
	switch {
	case resp.StatusCode == http.StatusUnauthorized, resp.StatusCode == http.StatusForbidden:
		return message{}, &StatusError{Code: resp.StatusCode}
	case resp.StatusCode >= http.StatusBadRequest:
		return t.failed(resp)
	}
	ct, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if ct == contentSSE {
		return t.fromStream(ctx, resp.Body, id)
	}
	var m message
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.noise.NotJSON++
		return message{}, fmt.Errorf("%w: %s answer isn't JSON-RPC", ErrProtocol, method)
	}
	if !t.noise.sort(m, id) {
		return message{}, fmt.Errorf("%w: %s answer isn't the reply", ErrProtocol, method)
	}
	return m, nil
}

// failed reads an error status. A JSON-RPC error body is the server's
// answer; a 400, 404 or 405 without one means this transport isn't there.
func (t *httpTransport) failed(resp *http.Response) (message, error) {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, errBodyCap))
	if m, ok := rpcErrorBody(b); ok {
		return m, nil // the server's own error, which the caller reads
	}
	switch resp.StatusCode {
	case http.StatusBadRequest, http.StatusNotFound, http.StatusMethodNotAllowed:
		return message{}, errNotHere
	}
	return message{}, &StatusError{Code: resp.StatusCode}
}

// fromStream reads an SSE answer until the reply to id, counting the rest.
func (t *httpTransport) fromStream(ctx context.Context, body io.Reader, id int) (message, error) {
	events := readEvents(body)
	for {
		select {
		case <-ctx.Done():
			return message{}, ctx.Err() //nolint:wrapcheck // the caller's own deadline
		case ev, ok := <-events:
			if !ok {
				return message{}, fmt.Errorf("%w: the stream ended before the reply", ErrProtocol)
			}
			if ev.err != nil {
				return message{}, ev.err
			}
			if m, ok := t.decode(ev); ok && t.noise.sort(m, id) {
				return m, nil
			}
		}
	}
}

func (t *httpTransport) decode(ev sseEvent) (message, bool) {
	if ev.kind != "" && ev.kind != "message" {
		return message{}, false
	}
	var m message
	if json.Unmarshal([]byte(ev.data), &m) != nil {
		t.noise.NotJSON++
		return message{}, false
	}
	return m, true
}

// sseEvent is one server-sent event, or the error that ended the stream.
type sseEvent struct {
	kind, data string
	err        error
}

// readEvents parses an SSE stream: "event:" and "data:" lines, ended by a
// blank line. An event over MaxMessage ends the stream with ErrTooLarge.
func readEvents(r io.Reader) <-chan sseEvent {
	out := make(chan sseEvent, 1)
	go func() {
		defer close(out)
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 0, firstRead), MaxMessage)
		var ev sseEvent
		data := make([]string, 0, 1)
		for sc.Scan() {
			l := sc.Text()
			switch {
			case l == "":
				if len(data) > 0 {
					ev.data = strings.Join(data, "\n")
					out <- ev
				}
				ev, data = sseEvent{}, data[:0]
			case strings.HasPrefix(l, "event:"):
				ev.kind = strings.TrimSpace(strings.TrimPrefix(l, "event:"))
			case strings.HasPrefix(l, "data:"):
				data = append(data, strings.TrimPrefix(strings.TrimPrefix(l, "data:"), " "))
			}
		}
		if errors.Is(sc.Err(), bufio.ErrTooLong) {
			out <- sseEvent{err: ErrTooLarge}
		}
	}()
	return out
}

// rpcErrorBody reads a body that holds a JSON-RPC error.
func rpcErrorBody(b []byte) (message, bool) {
	var m message
	if err := json.Unmarshal(b, &m); err != nil || m.Error == nil {
		return message{}, false
	}
	return m, true
}
