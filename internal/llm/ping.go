package llm

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/nickelsec/jarx/internal/netguard"
)

// PingText is the whole content of the connection test. It's fixed and
// holds nothing from a scan.
const PingText = "This is a connection test. Reply with the word ok."

// Errors from Ping. None of them quote the reply, the key or the URL.
var (
	ErrKeyRejected = errors.New("the endpoint rejected the key")
	ErrStatus      = errors.New("the endpoint answered with an error")
	ErrBadReply    = errors.New("the reply isn't a chat completion")
	ErrUnreachable = errors.New("couldn't reach the endpoint")
)

// maxReply is how much of a reply Ping reads. A chat completion for the
// ping text is tiny.
const maxReply = 1 << 20

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// Chat roles.
const (
	roleSystem    = "system"
	roleUser      = "user"
	roleAssistant = "assistant"
)

type chatRequest struct {
	Model    string        `json:"model"`
	Messages []chatMessage `json:"messages"`
}

type chatReply struct {
	Choices []struct {
		Message struct {
			Content *string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

// Ping sends one chat request with PingText to base's chat completions
// endpoint and reports how long it took. It checks base with
// netguard.CheckURL first, so nothing is sent to a URL setup would refuse.
func Ping(ctx context.Context, c *netguard.Client, base, model string, key Key) (time.Duration, error) {
	_, took, err := complete(ctx, c, base, model, key, []chatMessage{{Role: roleUser, Content: PingText}})
	return took, err
}

// complete sends one chat completion request and returns the first
// choice's text. It checks base with netguard.CheckURL first. The key only
// goes in the Authorization header, and errors never quote the reply, the
// key or the URL.
func complete(ctx context.Context, c *netguard.Client, base, model string, key Key, msgs []chatMessage) (string, time.Duration, error) {
	if err := netguard.CheckURL(base); err != nil {
		return "", 0, fmt.Errorf("base url: %w", err)
	}
	body, err := json.Marshal(chatRequest{Model: model, Messages: msgs})
	if err != nil {
		return "", 0, fmt.Errorf("encoding the request: %w", err)
	}
	endpoint := strings.TrimRight(base, "/") + "/chat/completions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", 0, fmt.Errorf("%w: can't build the request", ErrUnreachable)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key.value)

	start := time.Now()
	resp, err := c.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("%w: %s", ErrUnreachable, failureKind(err))
	}
	defer func() { _ = resp.Body.Close() }()
	data, readErr := io.ReadAll(io.LimitReader(resp.Body, maxReply))
	text, err := replyText(resp.StatusCode, data, readErr)
	return text, time.Since(start), err
}

// replyText is the first choice's text, or what's wrong with the reply,
// without quoting it.
func replyText(status int, data []byte, readErr error) (string, error) {
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return "", fmt.Errorf("%w (HTTP %d)", ErrKeyRejected, status)
	case status != http.StatusOK:
		return "", fmt.Errorf("%w (HTTP %d)", ErrStatus, status)
	case readErr != nil:
		return "", fmt.Errorf("%w: couldn't read it", ErrBadReply)
	}
	var reply chatReply
	if err := json.Unmarshal(data, &reply); err != nil || len(reply.Choices) == 0 {
		return "", ErrBadReply
	}
	if c := reply.Choices[0].Message.Content; c != nil {
		return *c, nil
	}
	return "", nil
}

// failureKind names why a request failed without quoting the error, since
// Go's errors include the URL, which could hold a secret.
func failureKind(err error) string {
	var netErr net.Error
	var certErr *x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	switch {
	case errors.Is(err, netguard.ErrBlocked):
		return "a blocked address"
	case errors.Is(err, netguard.ErrInsecure):
		return "plain http to an address that isn't loopback"
	case errors.Is(err, netguard.ErrRedirect):
		return "it redirected, and jarx doesn't follow redirects"
	case errors.Is(err, context.DeadlineExceeded) || errors.As(err, &netErr) && netErr.Timeout():
		return "it timed out"
	case errors.As(err, &certErr) || errors.As(err, &hostErr):
		return "its TLS certificate isn't trusted"
	default:
		return "the connection failed"
	}
}
