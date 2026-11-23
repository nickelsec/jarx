package probe

import (
	"encoding/json"
	"slices"
	"strconv"
	"strings"

	"github.com/nickelsec/jarx/internal/agent"
	"github.com/nickelsec/jarx/internal/mcp"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/redact"
)

// offers turns a listing into the model's offers, scrubbed. Each keeps its
// whole entry as text too, so the rules see every field.
func offers(c agent.Context, l mcp.Listing) []model.Offer {
	text := func(s string) redact.Text { t, _ := c.Scrub.Scrub(s); return t }
	var out []model.Offer
	for _, kind := range []struct {
		kind  model.OfferKind
		items []json.RawMessage
	}{{model.OfferTool, l.Tools}, {model.OfferPrompt, l.Prompts}, {model.OfferResource, l.Resources}} {
		for _, it := range kind.items {
			var e struct {
				Name        string         `json:"name"`
				URI         string         `json:"uri"`
				Description string         `json:"description"`
				Annotations map[string]any `json:"annotations"`
			}
			_ = json.Unmarshal(it, &e)
			name := e.Name
			if name == "" {
				name = e.URI
			}
			o := model.Offer{Kind: kind.kind, Name: text(name), Description: text(e.Description), Text: text(string(it))}
			for _, h := range hints(e.Annotations) {
				o.Hints = append(o.Hints, text(h))
			}
			out = append(out, o)
		}
	}
	return out
}

// hints are the annotation hints set to true, sorted.
func hints(a map[string]any) []string {
	var out []string
	for k, v := range a {
		if b, ok := v.(bool); ok && b && strings.HasSuffix(k, "Hint") {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out
}

// noiseNote says what else the server sent.
func noiseNote(n mcp.Noise) string {
	var parts []string
	add := func(count int, one, many string) {
		if count == 1 {
			parts = append(parts, "1 "+one)
		} else if count > 1 {
			parts = append(parts, strconv.Itoa(count)+" "+many)
		}
	}
	add(n.ServerRequests, "request to jarx (never answered)", "requests to jarx (never answered)")
	add(n.Notifications, "notification", "notifications")
	add(n.WrongIDs, "reply to an id jarx never sent", "replies to ids jarx never sent")
	add(n.NotJSON, "line that wasn't JSON-RPC", "lines that weren't JSON-RPC")
	return "the server also sent " + strings.Join(parts, ", ")
}
