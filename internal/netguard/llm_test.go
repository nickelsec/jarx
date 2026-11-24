package netguard

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

func TestNewLLMWaitsLongerForAnAnswer(t *testing.T) {
	c := NewLLM()

	if c.http.Timeout != llmDeadline || c.transport.ResponseHeaderTimeout != llmDeadline {
		t.Errorf("NewLLM limits = %v total, %v for headers; want %v for both", c.http.Timeout, c.transport.ResponseHeaderTimeout, llmDeadline)
	}
	if llmDeadline <= defaultDeadline {
		t.Errorf("llmDeadline = %v, want more than the default %v", llmDeadline, defaultDeadline)
	}
}

func TestNewLLMKeepsEveryOtherGuard(t *testing.T) {
	c := NewLLM()

	if c.transport.Proxy != nil || !c.transport.DisableCompression || c.transport.MaxResponseHeaderBytes != maxHeaderBytes {
		t.Error("NewLLM changed a guard other than the time limits")
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://169.254.169.254/v1/chat/completions", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if !errors.Is(err, ErrBlocked) {
		t.Errorf("Do(metadata) = %v, want ErrBlocked", err)
	}
}
