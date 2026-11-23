// Package mcp is jarx's list-only MCP client. It discovers a server and lists
// its tools, prompts and resources, and nothing else: it has no way to call
// a tool, read a resource or get a prompt, and it never answers anything the
// server asks. A test reads this package's source and fails on any other
// method string.
//
// It speaks both protocol eras (see "MCP client speaks both protocol eras"
// in docs/design.md): the modern one (2026-07-28, server/discover and the
// version in each request's _meta) and the legacy one (initialize), over
// stdio, streamable HTTP and the old HTTP+SSE transport. Remote servers are
// reached only through netguard.
//
// What comes back is raw: probe scrubs it before it goes into the model.
package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"time"
)

// The only methods the client can send.
const (
	methodDiscover      = "server/discover"
	methodInitialize    = "initialize"
	methodInitialized   = "notifications/initialized"
	methodToolsList     = "tools/list"
	methodPromptsList   = "prompts/list"
	methodResourcesList = "resources/list"
)

// allowed is the same list, for the check every request goes through.
//
//nolint:gochecknoglobals // fixed list, read only
var allowed = []string{methodDiscover, methodInitialize, methodInitialized, methodToolsList, methodPromptsList, methodResourcesList}

// Protocol versions.
const (
	modernVersion = "2026-07-28"
	legacyVersion = "2025-11-25" // the newest legacy revision, offered in initialize
	metaPrefix    = "io.modelcontextprotocol/"
	jsonRPC       = "2.0"

	codeUnsupportedVersion = -32022
	codeMethodNotFound     = -32601
)

// knownLegacy are the legacy revisions a server may answer initialize with.
//
//nolint:gochecknoglobals // fixed list, read only
var knownLegacy = []string{"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}

// Limits.
const (
	MaxMessage      = 10 << 20 // the largest single message read
	maxKept         = 32 << 20 // the most list data kept from one server
	defaultMaxPages = 50
	defaultWait     = 5 * time.Second // how long stdio waits for server/discover before trying initialize
	firstRead       = 64 << 10        // a reader's starting buffer
	mib             = 1 << 20
)

// Errors a caller can match with errors.Is.
var (
	ErrForbiddenMethod = errors.New("mcp: not a discovery or list method")
	ErrTooLarge        = errors.New("mcp: message too large")
	ErrUnsupported     = errors.New("mcp: no protocol version in common")
	ErrProtocol        = errors.New("mcp: the server broke the protocol")
	ErrOtherOrigin     = errors.New("mcp: the SSE endpoint is on another origin")
)

// Era is which protocol generation a server speaks.
type Era string

// Eras.
const (
	EraModern Era = "modern"
	EraLegacy Era = "legacy"
)

// Transport is how the server was reached.
type Transport string

// Transports.
const (
	TransportStdio Transport = "stdio"
	TransportHTTP  Transport = "streamable http"
	TransportSSE   Transport = "http+sse"
)

// Options tune a listing. The zero value is what jarx uses.
type Options struct {
	ClientVersion string
	MaxPages      int           // pages per list; 0 means 50
	DiscoverWait  time.Duration // stdio only; 0 means 5s
}

// Listing is what a server offered, as it sent it.
type Listing struct {
	Era          Era
	Version      string
	Transport    Transport
	ServerName   string
	Instructions string
	Tools        []json.RawMessage
	Prompts      []json.RawMessage
	Resources    []json.RawMessage
	// Notes say what didn't go as asked, like a list cut at the page cap.
	Notes []string
	Noise Noise
}

// Noise counts what the server sent that the client skipped.
type Noise struct {
	ServerRequests int // requests to the client, never answered
	Notifications  int
	WrongIDs       int // replies to an id the client didn't send
	NotJSON        int // lines or bodies that weren't JSON-RPC
}

// RPCError is a JSON-RPC error from the server.
type RPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (e *RPCError) Error() string {
	return "mcp: server error " + strconv.Itoa(e.Code) + ": " + e.Message
}

// StatusError is an HTTP status that stopped the listing, like a 401.
type StatusError struct{ Code int }

func (e *StatusError) Error() string { return "mcp: HTTP " + strconv.Itoa(e.Code) }

// message is one JSON-RPC message either way.
type message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

// encode builds one request or notification (id 0). It refuses any method
// that isn't discovery or a list, so nothing else can ever be sent.
func encode(id int, method string, params map[string]any) ([]byte, error) {
	if !slices.Contains(allowed, method) {
		return nil, fmt.Errorf("%w: %q", ErrForbiddenMethod, method)
	}
	m := map[string]any{"jsonrpc": jsonRPC, "method": method}
	if id != 0 {
		m["id"] = id
	}
	if params != nil {
		m["params"] = params
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("mcp: encode: %w", err)
	}
	return b, nil
}

// transport sends one message and, for a request, waits for its reply.
type transport interface {
	request(ctx context.Context, method string, id int, body []byte) (message, error)
	notify(ctx context.Context, method string, body []byte) error
}

// session is one conversation with a server.
type session struct {
	t       transport
	opts    Options
	era     Era
	version string
	next    int
	l       *Listing
}

func (s *session) params(extra map[string]any) map[string]any {
	p := map[string]any{}
	maps.Copy(p, extra)
	if s.era == EraModern {
		p["_meta"] = map[string]any{
			metaPrefix + "protocolVersion":    modernVersion,
			metaPrefix + "clientInfo":         s.clientInfo(),
			metaPrefix + "clientCapabilities": map[string]any{},
		}
	}
	return p
}

func (s *session) clientInfo() map[string]any {
	v := s.opts.ClientVersion
	if v == "" {
		v = "dev"
	}
	return map[string]any{"name": "jarx", "version": v}
}

// call sends one request and returns its result, or the server's error.
func (s *session) call(ctx context.Context, method string, params map[string]any) (json.RawMessage, error) {
	s.next++
	body, err := encode(s.next, method, params)
	if err != nil {
		return nil, err
	}
	reply, err := s.t.request(ctx, method, s.next, body)
	if err != nil {
		return nil, err
	}
	if reply.Error != nil {
		return nil, reply.Error
	}
	return reply.Result, nil
}

// discovered reads a DiscoverResult. A server that doesn't list the modern
// version is one the client can't talk to.
func (s *session) discovered(raw json.RawMessage) (map[string]any, error) {
	var r struct {
		SupportedVersions []string       `json:"supportedVersions"`
		Capabilities      map[string]any `json:"capabilities"`
		ServerInfo        struct {
			Name string `json:"name"`
		} `json:"serverInfo"`
		Instructions string `json:"instructions"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("%w: discover result isn't an object", ErrProtocol)
	}
	if !slices.Contains(r.SupportedVersions, modernVersion) {
		return nil, fmt.Errorf("%w: the server supports %q", ErrUnsupported, r.SupportedVersions)
	}
	s.era, s.version = EraModern, modernVersion
	s.l.ServerName, s.l.Instructions = r.ServerInfo.Name, r.Instructions
	return r.Capabilities, nil
}

// initialize does the legacy handshake.
func (s *session) initialize(ctx context.Context) (map[string]any, error) {
	s.era = EraLegacy
	raw, err := s.call(ctx, methodInitialize, map[string]any{
		"protocolVersion": legacyVersion, "capabilities": map[string]any{}, "clientInfo": s.clientInfo(),
	})
	if err != nil {
		return nil, err
	}
	var r struct {
		ProtocolVersion string         `json:"protocolVersion"`
		Capabilities    map[string]any `json:"capabilities"`
		ServerInfo      struct {
			Name string `json:"name"`
		} `json:"serverInfo"`
		Instructions string `json:"instructions"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("%w: initialize result isn't an object", ErrProtocol)
	}
	if !slices.Contains(knownLegacy, r.ProtocolVersion) {
		return nil, fmt.Errorf("%w: the server answered with %q", ErrUnsupported, r.ProtocolVersion)
	}
	s.version = r.ProtocolVersion
	s.l.ServerName, s.l.Instructions = r.ServerInfo.Name, r.Instructions
	body, err := encode(0, methodInitialized, nil)
	if err != nil {
		return nil, err
	}
	if err := s.t.notify(ctx, methodInitialized, body); err != nil {
		return nil, err
	}
	return r.Capabilities, nil
}

// listAll lists each kind the server says it has. With no capabilities at
// all, it asks for each anyway.
func (s *session) listAll(ctx context.Context, caps map[string]any) error {
	s.l.Era, s.l.Version = s.era, s.version
	kept := 0
	for _, k := range []struct {
		method, key, capability string
		into                    *[]json.RawMessage
	}{
		{methodToolsList, "tools", "tools", &s.l.Tools},
		{methodPromptsList, "prompts", "prompts", &s.l.Prompts},
		{methodResourcesList, "resources", "resources", &s.l.Resources},
	} {
		if _, ok := caps[k.capability]; !ok && caps != nil {
			continue
		}
		if err := s.list(ctx, k.method, k.key, k.into, &kept); err != nil {
			return err
		}
	}
	return nil
}

// list follows one list's pages. It stops at the page cap, when a cursor
// comes back that it already sent, or when it's kept too much.
func (s *session) list(ctx context.Context, method, key string, into *[]json.RawMessage, kept *int) error {
	maxPages := s.opts.MaxPages
	if maxPages <= 0 {
		maxPages = defaultMaxPages
	}
	var seen []string
	cursor := ""
	for page := range maxPages {
		items, next, stop, err := s.page(ctx, method, key, cursor)
		if err != nil || stop {
			return err
		}
		for _, it := range items {
			if *kept += len(it); *kept > maxKept {
				s.note("stopped keeping list items after " + strconv.Itoa(maxKept/mib) + " MiB")
				return nil
			}
			*into = append(*into, it)
		}
		switch {
		case next == "":
			return nil
		case slices.Contains(seen, next):
			s.note(method + " sent a cursor it had sent before, so paging stopped")
			return nil
		case page == maxPages-1:
			s.note(method + " stopped at " + strconv.Itoa(maxPages) + " pages")
			return nil
		}
		seen = append(seen, next)
		cursor = next
	}
	return nil
}

// page gets one page of a list: its items and the next cursor. stop means
// the list ends here with a note, not an error: the method isn't there, or
// the server asked for input instead of answering.
func (s *session) page(ctx context.Context, method, key, cursor string) ([]json.RawMessage, string, bool, error) {
	extra := map[string]any{}
	if cursor != "" {
		extra["cursor"] = cursor
	}
	raw, err := s.call(ctx, method, s.params(extra))
	var rerr *RPCError
	if errors.As(err, &rerr) && rerr.Code == codeMethodNotFound {
		s.note(method + " isn't there: the server says the method doesn't exist")
		return nil, "", true, nil
	}
	if err != nil {
		return nil, "", false, err
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return nil, "", false, fmt.Errorf("%w: %s result isn't an object", ErrProtocol, method)
	}
	var resultType, next string
	_ = json.Unmarshal(m["resultType"], &resultType)
	_ = json.Unmarshal(m["nextCursor"], &next)
	if resultType == "input_required" {
		s.note(method + " asked for input (sampling or elicitation) instead of answering; nothing was answered and no items were kept")
		return nil, "", true, nil
	}
	var items []json.RawMessage
	if json.Unmarshal(m[key], &items) != nil {
		return nil, "", false, fmt.Errorf("%w: %s has no %s list", ErrProtocol, method, key)
	}
	return items, next, false, nil
}

func (s *session) note(n string) { s.l.Notes = append(s.l.Notes, n) }

// sort reads one incoming message: the reply to id, or noise it counts.
func (n *Noise) sort(m message, id int) bool {
	switch {
	case m.Method != "" && len(m.ID) > 0:
		n.ServerRequests++
	case m.Method != "":
		n.Notifications++
	case string(m.ID) == strconv.Itoa(id):
		return true
	default:
		n.WrongIDs++
	}
	return false
}
