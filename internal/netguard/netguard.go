// Package netguard is the only package that may make network connections.
// Lint bans http.Client, http.Transport, net.Dial*, tls.Dial*, DNS lookups,
// net/smtp and net/rpc everywhere else.
//
// Every connection is checked in the dialer's Control hook, which runs after
// DNS and right before connect, on the exact IP the socket is about to reach.
// That covers every reconnect and retry, so DNS rebinding can't get past it.
// The two dial paths are split by scheme:
//
//   - https dials through the metadata block (checkAddr), then does TLS on
//     that same connection
//   - plain http dials through the metadata block and must reach a loopback
//     address (checkPlain)
//
// Also: no proxy ever, no redirects, and caps on headers, body size and
// total time, so a hostile server can't stall jarx or fill its memory.
package netguard

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"
)

// Errors a caller can match with errors.Is.
var (
	ErrBlocked  = errors.New("blocked address")
	ErrInsecure = errors.New("insecure transport")
	ErrRedirect = errors.New("redirect not followed")
	ErrTooLarge = errors.New("response too large")
)

// Limits.
const (
	MaxBodySize     = 10 << 20 // bytes read from one response body
	maxHeaderBytes  = 64 << 10
	dialTimeout     = 10 * time.Second
	headerTimeout   = 10 * time.Second
	defaultDeadline = 20 * time.Second // hard ceiling; the probe's own limit is 15s
	// llmDeadline is for the LLM review, whose answer only starts once the
	// model is done, so headers come late too.
	llmDeadline  = 120 * time.Second
	maxIdleConns = 4
	idleTimeout  = 30 * time.Second
)

// errTestEscape is only used by tests (see withTestSafety).
var errTestEscape = errors.New("test safety: refusing a non-loopback connection")

type config struct {
	resolver   *net.Resolver
	roots      *x509.CertPool
	timeout    time.Duration
	headers    time.Duration // how long to wait for response headers
	testSafety bool
}

// option configures a Client. All options are unexported and only used by
// tests: production always gets the system resolver, system roots and the
// default limits.
type option func(*config)

func withResolver(r *net.Resolver) option { return func(c *config) { c.resolver = r } }
func withRootCAs(p *x509.CertPool) option { return func(c *config) { c.roots = p } }
func withTimeout(d time.Duration) option  { return func(c *config) { c.timeout = d } }

// withTestSafety makes the dialer refuse every non-loopback address after the
// real policy has run, so a broken policy fails its test instead of
// connecting somewhere real.
func withTestSafety() option { return func(c *config) { c.testSafety = true } }

// Client makes HTTP requests through the guard.
type Client struct {
	http      *http.Client
	transport *http.Transport
}

// NewLLM returns a Client for the LLM review: every guard New has, with
// llmDeadline for the whole request and for the headers, since a chat
// completion's headers only come once the model has answered.
func NewLLM() *Client {
	return New(func(c *config) { c.timeout, c.headers = llmDeadline, llmDeadline })
}

// New returns a Client.
func New(opts ...option) *Client {
	cfg := config{timeout: defaultDeadline, headers: headerTimeout}
	for _, o := range opts {
		o(&cfg)
	}
	tlsDialer := &tls.Dialer{
		NetDialer: dialer(cfg, checkAddr),
		Config:    &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: cfg.roots},
	}
	plain := dialer(cfg, checkPlain)
	t := &http.Transport{
		Proxy:                  nil, // never, so the dial check sees the real address
		DialContext:            guardName(plain.DialContext),
		DialTLSContext:         guardName(tlsDialer.DialContext),
		ForceAttemptHTTP2:      false,
		ResponseHeaderTimeout:  cfg.headers,
		MaxResponseHeaderBytes: maxHeaderBytes,
		DisableCompression:     true, // no gzip, so nothing inflates behind the body cap
		MaxIdleConns:           maxIdleConns,
		IdleConnTimeout:        idleTimeout,
	}
	return &Client{
		transport: t,
		http: &http.Client{
			Transport: t,
			Timeout:   cfg.timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return ErrRedirect
			},
		},
	}
}

// Do sends req. Only http and https are allowed. The response body is capped
// at MaxBodySize; reading past it returns ErrTooLarge.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" && req.URL.Scheme != "http" {
		return nil, fmt.Errorf("%w: scheme %q", ErrInsecure, req.URL.Scheme)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	if resp.ContentLength > MaxBodySize {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("%w: declared %d bytes, cap %d", ErrTooLarge, resp.ContentLength, MaxBodySize)
	}
	resp.Body = &cappedBody{rc: resp.Body, left: MaxBodySize}
	return resp, nil
}

func dialer(cfg config, policy func(netip.Addr) error) *net.Dialer {
	return &net.Dialer{
		Timeout:  dialTimeout,
		Resolver: cfg.resolver,
		Control: func(network, address string, _ syscall.RawConn) error {
			if network != "tcp4" && network != "tcp6" {
				return fmt.Errorf("%w: network %s", ErrBlocked, network)
			}
			ap, err := netip.ParseAddrPort(address)
			if err != nil {
				return fmt.Errorf("%w: can't parse %q", ErrBlocked, address)
			}
			if err := policy(ap.Addr()); err != nil {
				return err
			}
			if cfg.testSafety && !ap.Addr().Unmap().IsLoopback() {
				return fmt.Errorf("%w: %s", errTestEscape, ap.Addr())
			}
			return nil
		},
	}
}

type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// guardName checks the host before dialing. It refuses metadata hostnames
// before any DNS lookup. It also checks a literal IP host here, because Go
// rewrites a dial to an empty host, 0.0.0.0 or :: into a dial to the local
// machine before Control ever sees it. Control still checks the real IP.
func guardName(dial dialFunc) dialFunc {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("%w: bad address %q", ErrBlocked, addr)
		}
		if host == "" {
			return nil, fmt.Errorf("%w: empty host", ErrBlocked)
		}
		if blockedName(host) {
			return nil, fmt.Errorf("%w: %s (cloud metadata name)", ErrBlocked, host)
		}
		if ip, err := netip.ParseAddr(host); err == nil {
			if err := checkAddr(ip); err != nil {
				return nil, err
			}
		}
		return dial(ctx, network, addr)
	}
}

// cappedBody returns ErrTooLarge once more than the cap has been read.
type cappedBody struct {
	rc   io.ReadCloser
	left int64
}

func (b *cappedBody) Read(p []byte) (int, error) {
	if b.left < 0 {
		return 0, fmt.Errorf("%w: over %d bytes", ErrTooLarge, MaxBodySize)
	}
	// Read one byte past the cap so a body of exactly the cap ends cleanly.
	if int64(len(p)) > b.left+1 {
		p = p[:b.left+1]
	}
	n, err := b.rc.Read(p)
	b.left -= int64(n)
	if b.left < 0 {
		return n + int(b.left), fmt.Errorf("%w: over %d bytes", ErrTooLarge, MaxBodySize)
	}
	return n, err //nolint:wrapcheck // io.EOF must reach the caller unwrapped
}

func (b *cappedBody) Close() error {
	if err := b.rc.Close(); err != nil {
		return fmt.Errorf("closing body: %w", err)
	}
	return nil
}
