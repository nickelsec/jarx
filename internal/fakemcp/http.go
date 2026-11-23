package fakemcp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

const (
	maxBody       = 16 << 20 // the largest request body it reads
	sessionBuffer = 64       // replies a legacy stream holds before a sender waits
	versionHeader = "Mcp-Protocol-Version"
)

// Handler serves the script over HTTP: streamable HTTP on any path, or with
// Bad.LegacySSE the 2024-11-05 transport, a GET /sse stream plus POSTs to
// the endpoint it announces.
func (s *Server) Handler() http.Handler {
	return &handler{s: s, sessions: map[string]*session{}}
}

type handler struct {
	s        *Server
	mu       sync.Mutex
	next     int
	sessions map[string]*session
}

// session is one legacy SSE stream: where replies go, and the stream's
// context, which lives as long as the client listens.
type session struct {
	out chan json.RawMessage
	ctx context.Context //nolint:containedctx // the stream's lifetime, used by replies sent after their POST returns
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.gate(w, r) {
		return
	}
	legacy := h.s.sc.Bad.LegacySSE
	switch {
	case legacy && r.Method == http.MethodGet && r.URL.Path == "/sse":
		h.stream(w, r)
	case legacy && r.Method == http.MethodPost && r.URL.Path == "/messages":
		h.legacyPost(w, r)
	case legacy, r.Method != http.MethodPost:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	default:
		h.post(w, r)
	}
}

// gate answers a request the script redirects or that lacks the bearer token
// it wants. It says whether it answered.
func (h *handler) gate(w http.ResponseWriter, r *http.Request) bool {
	bad := h.s.sc.Bad
	switch {
	case bad.Redirect != "":
		http.Redirect(w, r, bad.Redirect, http.StatusTemporaryRedirect)
	case bad.RequireBearer != "" && r.Header.Get("Authorization") != "Bearer "+bad.RequireBearer:
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	default:
		return false
	}
	return true
}

// peek reads the method and the _meta version of a body without acting on
// it.
func peek(body []byte) (string, string) {
	var m struct {
		Method string `json:"method"`
		Params struct {
			Meta map[string]any `json:"_meta"` //nolint:tagliatelle // the name the MCP spec gives it
		} `json:"params"`
	}
	_ = json.Unmarshal(body, &m)
	v, _ := m.Params.Meta[metaVersion].(string)
	return m.Method, v
}

// post serves one streamable HTTP request.
func (h *handler) post(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
	if err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	if h.reject(w, r, body) {
		return
	}
	o := h.s.handle(body)
	switch {
	case !o.isReq:
		w.WriteHeader(http.StatusAccepted)
	case o.hang:
		<-r.Context().Done()
	case !h.s.wait(r.Context()):
	case h.s.sc.Bad.Garbage:
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, "this is not json")
	case h.s.sc.Bad.SSE:
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(o.status)
		for _, l := range h.s.replyLines(o) {
			event(w, "message", string(l))
		}
	default:
		writeJSON(w, o.status, *o.reply)
	}
}

// reject answers a request before the server looks at it: a status the
// script sets for the method, a modern request to a legacy server (a 400
// without a modern error body, so the client falls back), and a version
// header that doesn't match _meta. It says whether it answered.
func (h *handler) reject(w http.ResponseWriter, r *http.Request, body []byte) bool {
	method, version := peek(body)
	header := r.Header.Get(versionHeader)
	code, scripted := h.s.sc.Bad.Status[method]
	switch {
	case scripted:
		h.s.record(method)
		http.Error(w, "status from the script", code)
	case h.s.sc.Era == EraLegacy && (version != "" || header == modernVersion):
		h.s.record(method)
		http.Error(w, "not a modern MCP server", http.StatusBadRequest)
	case version != "" && header != version:
		h.s.record(method)
		writeJSON(w, http.StatusBadRequest, message{JSONRPC: jsonRPC, Error: &rpcError{Code: codeHeaderMismatch,
			Message: versionHeader + " doesn't match the request's _meta"}})
	default:
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, m message) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(mustJSON(m))
}

// event writes one SSE event and flushes it.
func event(w http.ResponseWriter, kind, data string) {
	_, _ = io.WriteString(w, "event: "+kind+"\ndata: "+strings.ReplaceAll(data, "\n", "")+"\n\n")
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

// stream is a legacy SSE stream: it announces the endpoint to POST to, then
// sends each reply as a message event until the client goes away.
func (h *handler) stream(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	h.next++
	id := strconv.Itoa(h.next)
	sess := &session{out: make(chan json.RawMessage, sessionBuffer), ctx: r.Context()}
	h.sessions[id] = sess
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.sessions, id)
		h.mu.Unlock()
	}()
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	event(w, "endpoint", "/messages?session="+id)
	for {
		select {
		case <-r.Context().Done():
			return
		case l := <-sess.out:
			event(w, "message", string(l))
		}
	}
}

// legacyPost takes a message for a legacy session; the reply goes out on
// the session's stream, after this POST has returned.
func (h *handler) legacyPost(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	sess, ok := h.sessions[r.URL.Query().Get("session")]
	h.mu.Unlock()
	if !ok {
		http.Error(w, "no such session", http.StatusNotFound)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
	if err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	o := h.s.handle(body)
	w.WriteHeader(http.StatusAccepted)
	if o.hang || !o.isReq {
		return
	}
	go func() {
		if !h.s.wait(sess.ctx) {
			return
		}
		for _, l := range h.s.replyLines(o) {
			select {
			case sess.out <- l:
			case <-sess.ctx.Done():
				return
			}
		}
	}()
}
