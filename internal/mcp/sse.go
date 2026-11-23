package mcp

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"maps"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"github.com/nickelsec/jarx/internal/netguard"
)

// listSSE lists a server over the 2024-11-05 HTTP+SSE transport: a GET
// opens a stream whose first event names the endpoint to POST to, and
// replies come back on the stream. The endpoint has to be on the same
// origin as the URL, so a server can't send the configured headers
// somewhere else.
func listSSE(ctx context.Context, c *netguard.Client, u *url.URL, header http.Header, opts Options) (Listing, error) {
	l := Listing{Transport: TransportSSE}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return l, fmt.Errorf("mcp: request: %w", err)
	}
	maps.Copy(req.Header, header)
	req.Header.Set("Accept", contentSSE)
	resp, err := c.Do(req)
	if err != nil {
		return l, fmt.Errorf("mcp: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return l, &StatusError{Code: resp.StatusCode}
	}
	if ct, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type")); ct != contentSSE {
		return l, fmt.Errorf("%w: the SSE URL answered with %q", ErrProtocol, ct)
	}
	events := readEvents(resp.Body)
	endpoint, err := firstEndpoint(ctx, events, u)
	if err != nil {
		return l, err
	}
	t := &sseTransport{c: c, endpoint: endpoint, header: header, events: events, noise: &l.Noise}
	s := &session{t: t, opts: opts, l: &l}
	caps, err := s.initialize(ctx)
	if err != nil {
		return l, err
	}
	return l, s.listAll(ctx, caps)
}

// firstEndpoint waits for the endpoint event and resolves it against base.
func firstEndpoint(ctx context.Context, events <-chan sseEvent, base *url.URL) (*url.URL, error) {
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err() //nolint:wrapcheck // the caller's own deadline
		case ev, ok := <-events:
			if !ok {
				return nil, fmt.Errorf("%w: the stream ended before the endpoint event", ErrProtocol)
			}
			if ev.err != nil {
				return nil, ev.err
			}
			if ev.kind != "endpoint" {
				continue
			}
			ref, err := url.Parse(strings.TrimSpace(ev.data))
			if err != nil {
				return nil, fmt.Errorf("%w: the endpoint isn't a URL", ErrProtocol)
			}
			ep := base.ResolveReference(ref)
			if !strings.EqualFold(ep.Scheme, base.Scheme) || !strings.EqualFold(ep.Host, base.Host) {
				return nil, ErrOtherOrigin
			}
			return ep, nil
		}
	}
}

type sseTransport struct {
	c        *netguard.Client
	endpoint *url.URL
	header   http.Header
	events   <-chan sseEvent
	noise    *Noise
}

func (t *sseTransport) notify(ctx context.Context, _ string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("mcp: request: %w", err)
	}
	maps.Copy(req.Header, t.header)
	req.Header.Set("Content-Type", contentJSON)
	resp, err := t.c.Do(req)
	if err != nil {
		return fmt.Errorf("mcp: %w", err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, errBodyCap))
	_ = resp.Body.Close()
	if resp.StatusCode >= http.StatusBadRequest {
		return &StatusError{Code: resp.StatusCode}
	}
	return nil
}

// request posts the message and waits for its reply on the stream.
func (t *sseTransport) request(ctx context.Context, method string, id int, body []byte) (message, error) {
	if err := t.notify(ctx, method, body); err != nil {
		return message{}, err
	}
	h := &httpTransport{noise: t.noise}
	for {
		select {
		case <-ctx.Done():
			return message{}, ctx.Err() //nolint:wrapcheck // the caller's own deadline
		case ev, ok := <-t.events:
			if !ok {
				return message{}, fmt.Errorf("%w: the stream ended before the reply", ErrProtocol)
			}
			if ev.err != nil {
				return message{}, ev.err
			}
			if m, ok := h.decode(ev); ok && t.noise.sort(m, id) {
				return m, nil
			}
		}
	}
}
