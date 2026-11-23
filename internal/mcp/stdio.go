package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// ListStdio lists a server over its stdin and stdout. The caller started
// the process and kills it afterwards; ctx bounds the whole listing.
func ListStdio(ctx context.Context, stdin io.Writer, stdout io.Reader, opts Options) (Listing, error) {
	l := Listing{Transport: TransportStdio}
	t := &stdioTransport{w: stdin, lines: readLines(stdout), noise: &l.Noise}
	s := &session{t: t, opts: opts, l: &l}
	caps, err := discoverStdio(ctx, s, opts)
	if err != nil {
		return l, err
	}
	return l, s.listAll(ctx, caps)
}

// discoverStdio probes with server/discover, as the stdio binding says. A
// DiscoverResult means modern. The modern "unsupported version" error means
// a modern server the client can't talk to. Any other error, or no answer in
// time, means legacy, so it tries initialize.
func discoverStdio(ctx context.Context, s *session, opts Options) (map[string]any, error) {
	wait := opts.DiscoverWait
	if wait <= 0 {
		wait = defaultWait
	}
	s.era = EraModern
	probe, cancel := context.WithTimeout(ctx, wait)
	raw, err := s.call(probe, methodDiscover, s.params(nil))
	cancel()
	var rerr *RPCError
	switch {
	case err == nil:
		return s.discovered(raw)
	case errors.As(err, &rerr) && rerr.Code == codeUnsupportedVersion:
		return nil, fmt.Errorf("%w: %s", ErrUnsupported, rerr.Data)
	case ctx.Err() != nil:
		return nil, ctx.Err() //nolint:wrapcheck // the caller's own deadline
	case errors.As(err, &rerr), errors.Is(err, context.DeadlineExceeded):
		return s.initialize(ctx)
	}
	return nil, err
}

// line is one line from the server, or the error that ended the stream.
type line struct {
	b   []byte
	err error
}

// readLines reads the server's stdout one line at a time until it ends. A
// line over MaxMessage ends it with ErrTooLarge.
func readLines(r io.Reader) <-chan line {
	out := make(chan line, 1)
	go func() {
		defer close(out)
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 0, firstRead), MaxMessage)
		for sc.Scan() {
			out <- line{b: append([]byte(nil), sc.Bytes()...)}
		}
		err := sc.Err()
		switch {
		case errors.Is(err, bufio.ErrTooLong):
			err = ErrTooLarge
		case err == nil:
			err = fmt.Errorf("%w: the server closed its output", ErrProtocol)
		}
		out <- line{err: err}
	}()
	return out
}

type stdioTransport struct {
	w     io.Writer
	lines <-chan line
	noise *Noise
	err   error // the stream's end, once seen
}

func (t *stdioTransport) notify(_ context.Context, _ string, body []byte) error {
	if _, err := t.w.Write(append(body, '\n')); err != nil {
		return fmt.Errorf("mcp: write: %w", err)
	}
	return nil
}

func (t *stdioTransport) request(ctx context.Context, method string, id int, body []byte) (message, error) {
	if err := t.notify(ctx, method, body); err != nil {
		return message{}, err
	}
	for {
		if t.err != nil {
			return message{}, t.err
		}
		select {
		case <-ctx.Done():
			return message{}, ctx.Err() //nolint:wrapcheck // the caller's own deadline
		case l, ok := <-t.lines:
			if !ok {
				return message{}, t.err
			}
			if l.err != nil {
				t.err = l.err
				continue
			}
			var m message
			if json.Unmarshal(l.b, &m) != nil {
				t.noise.NotJSON++
				continue
			}
			if t.noise.sort(m, id) {
				return m, nil
			}
		}
	}
}
