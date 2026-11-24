package llm

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Item is one finding in the model's reply.
type Item struct {
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Quote    string `json:"quote"`
	Why      string `json:"why"`
}

// Limits on a reply.
const (
	maxTitle = 120
	maxField = 2000
	maxItems = 10
)

// errShape is a reply that isn't the fixed shape. Its text goes back to the
// model in the retry, so it's always jarx's own words.
var errShape = errors.New("the reply isn't JSON in the shape asked for")

// parseReply checks a reply against the fixed shape:
// {"findings":[{"severity","title","quote","why"}]}, with nothing else
// around it but whitespace or one code fence.
func parseReply(reply string) ([]Item, error) {
	body := unfence(strings.TrimSpace(reply))
	dec := json.NewDecoder(strings.NewReader(body))
	dec.DisallowUnknownFields()
	var got struct {
		Findings *[]Item `json:"findings"`
	}
	if err := dec.Decode(&got); err != nil {
		if field, ok := unknownField(err); ok {
			return nil, fmt.Errorf("%w: unknown field %q", errShape, field)
		}
		return nil, fmt.Errorf("%w: it isn't JSON", errShape)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: it isn't JSON alone, there's more after it", errShape)
	}
	if got.Findings == nil {
		return nil, fmt.Errorf(`%w: it needs a "findings" list`, errShape)
	}
	items := *got.Findings
	if len(items) > maxItems {
		return nil, fmt.Errorf("%w: at most %d findings", errShape, maxItems)
	}
	for i, it := range items {
		if err := it.check(); err != nil {
			return nil, fmt.Errorf("%w: finding %d %s", errShape, i+1, err.Error())
		}
	}
	return items, nil
}

func (it Item) check() error {
	switch {
	case it.Severity != "high" && it.Severity != "medium":
		return errors.New("severity has to be high or medium")
	case strings.TrimSpace(it.Title) == "":
		return errors.New("needs a title")
	case strings.TrimSpace(it.Quote) == "":
		return errors.New("needs a quote")
	case strings.TrimSpace(it.Why) == "":
		return errors.New("needs a why")
	case len(it.Title) > maxTitle:
		return fmt.Errorf("title is too long, keep it under %d chars", maxTitle)
	case len(it.Quote) > maxField || len(it.Why) > maxField:
		return fmt.Errorf("quote and why have to be under %d chars", maxField)
	}
	return nil
}

// unfence drops one code fence around the reply, like ```json ... ```.
func unfence(s string) string {
	if !strings.HasPrefix(s, "```") || !strings.HasSuffix(s, "```") || len(s) < 6 {
		return s
	}
	inner := strings.TrimSuffix(s, "```")
	_, inner, ok := strings.Cut(inner, "\n") // the first line is the fence and its language
	if !ok {
		return s
	}
	return strings.TrimSpace(inner)
}

// unknownField is the field name in encoding/json's unknown field error.
func unknownField(err error) (string, bool) {
	const prefix = `json: unknown field "`
	msg := err.Error()
	if !strings.HasPrefix(msg, prefix) {
		return "", false
	}
	return strings.TrimSuffix(strings.TrimPrefix(msg, prefix), `"`), true
}

// quoted reports whether quote is in text, ignoring how runs of spaces and
// line breaks were reflowed. A quote too short to point at anything
// doesn't count.
func quoted(text, quote string) bool {
	q := squash(quote)
	return len(q) >= minQuote && strings.Contains(squash(text), q)
}

// minQuote is the shortest quote that counts.
const minQuote = 8

func squash(s string) string {
	var b bytes.Buffer
	for i, f := range strings.Fields(s) {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(f)
	}
	return b.String()
}
