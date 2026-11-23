package fakemcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
)

const (
	maxLine   = 16 << 20 // the longest line it reads from the client
	firstRead = 64 << 10 // the scanner's starting buffer
)

// ServeStdio serves newline-delimited JSON-RPC from r to w until r ends, the
// script says to exit, or ctx ends. stderr gets the script's Stderr text.
func (s *Server) ServeStdio(ctx context.Context, r io.Reader, w, stderr io.Writer) error {
	if s.start(stderr) {
		return nil
	}
	lines, scanErr := readLines(ctx, r)
	requests := 0
	for {
		select {
		case <-ctx.Done():
			return nil
		case line, ok := <-lines:
			if !ok {
				return <-scanErr
			}
			isReq, err := s.respond(ctx, line, w)
			if isReq {
				requests++
			}
			if err != nil || ctx.Err() != nil || s.done(requests) {
				return err
			}
		}
	}
}

// done says whether the script stops after this many requests.
func (s *Server) done(requests int) bool {
	return s.sc.Bad.ExitAfter > 0 && requests >= s.sc.Bad.ExitAfter
}

// readLines reads lines from r until it ends or ctx does. The error channel
// gets the scanner's error once lines is closed.
func readLines(ctx context.Context, r io.Reader) (<-chan []byte, <-chan error) {
	lines := make(chan []byte)
	scanErr := make(chan error, 1)
	go func() {
		defer close(lines)
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 0, firstRead), maxLine)
		for sc.Scan() {
			select {
			case lines <- append([]byte(nil), sc.Bytes()...):
			case <-ctx.Done():
				scanErr <- nil
				return
			}
		}
		if err := sc.Err(); err != nil {
			scanErr <- fmt.Errorf("fakemcp: read: %w", err)
			return
		}
		scanErr <- nil
	}()
	return lines, scanErr
}

// respond handles one line and writes what goes back. It says whether the
// line was a request.
func (s *Server) respond(ctx context.Context, line []byte, w io.Writer) (bool, error) {
	o := s.handle(line)
	if !o.isReq || o.hang || !s.wait(ctx) {
		return o.isReq, nil
	}
	out := s.replyLines(o)
	if s.sc.Bad.Garbage {
		out = append([]json.RawMessage{json.RawMessage("this is not json")}, out...)
	}
	for _, l := range out {
		if _, err := w.Write(append(l, '\n')); err != nil {
			return true, fmt.Errorf("fakemcp: write: %w", err)
		}
	}
	return true, nil
}

// start writes the script's stderr text and says whether it exits at once.
func (s *Server) start(stderr io.Writer) bool {
	if s.sc.Bad.Stderr != "" {
		_, _ = io.WriteString(stderr, s.sc.Bad.Stderr+"\n")
	}
	return s.sc.Bad.ExitAfter < 0
}
