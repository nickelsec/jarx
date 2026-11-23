package probe

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/nickelsec/jarx/internal/agent"
	"github.com/nickelsec/jarx/internal/mcp"
	"github.com/nickelsec/jarx/internal/model"
	"github.com/nickelsec/jarx/internal/netguard"
)

// probeRemote lists a remote server through netguard, sending the static
// credentials its config holds exactly the way the agent would. Under
// --home it contacts nothing.
func probeRemote(ctx context.Context, c agent.Context, s model.Server, spec model.LaunchSpec, opts Options) result {
	switch {
	case c.Env.Fake():
		return result{status: model.StatusNotStarted, why: "under --home jarx doesn't contact remote servers"}
	case s.Transport != model.TransportHTTP && s.Transport != model.TransportSSE:
		return result{status: model.StatusNotStarted, why: "jarx probes stdio, streamable HTTP and SSE servers, not " + string(s.Transport)}
	case spec.OAuth:
		return result{status: model.StatusRequiresAuth, why: "it's set up for an OAuth sign-in, which jarx doesn't do"}
	case spec.HeadersHelper:
		return result{status: model.StatusRequiresAuth, why: "a headers helper computes its headers, and jarx doesn't run it"}
	case opts.Client == nil:
		return result{status: model.StatusNotStarted, why: "no network client"}
	}
	url, header, missing := remoteLaunch(c, s.Origin.Agent, spec)
	if len(missing) > 0 {
		return missingCredential(missing)
	}
	mo := mcp.Options{ClientVersion: opts.ClientVersion}
	var l mcp.Listing
	var err error
	if s.Transport == model.TransportSSE {
		l, err = mcp.ListSSE(ctx, opts.Client, url, header, mo)
	} else {
		l, err = mcp.ListHTTP(ctx, opts.Client, url, header, mo)
	}
	r := result{listing: l}
	r.status, r.why = remoteStatus(err, len(header) > 0, opts)
	return r
}

// remoteLaunch is the URL and headers after the agent's own expansion, and
// the variables a reference needed but didn't find.
func remoteLaunch(c agent.Context, a model.Agent, spec model.LaunchSpec) (string, http.Header, []string) {
	if a != model.AgentClaude {
		return codexRemote(c, spec)
	}
	header := http.Header{}
	url, missing := expandClaude(spec.URL, c.Env.Lookup, spec, true)
	for _, kv := range spec.Headers {
		v, m := expandClaude(kv[1], c.Env.Lookup, spec, true)
		missing = append(missing, m...)
		header.Set(kv[0], v)
	}
	return url, header, missing
}

// codexRemote builds Codex's headers: http_headers as written, a bearer
// token from bearer_token_env_var, and env_http_headers from the env.
func codexRemote(c agent.Context, spec model.LaunchSpec) (string, http.Header, []string) {
	header := http.Header{}
	var missing []string
	for _, kv := range spec.Headers {
		header.Set(kv[0], kv[1])
	}
	fromEnv := func(name, h, prefix string) {
		if v, ok := c.Env.Lookup(name); ok {
			header.Set(h, prefix+v)
		} else {
			missing = append(missing, name)
		}
	}
	if spec.BearerVar != "" {
		fromEnv(spec.BearerVar, "Authorization", "Bearer ")
	}
	for _, kv := range spec.HeaderVars {
		fromEnv(kv[1], kv[0], "")
	}
	return spec.URL, header, missing
}

// remoteStatus turns how the listing ended into a status and why. The
// reasons never quote the error, since a URL in it can hold a token.
func remoteStatus(err error, sentCreds bool, opts Options) (model.ServerStatus, string) {
	if err == nil {
		return model.StatusListed, ""
	}
	if se, ok := errors.AsType[*mcp.StatusError](err); ok {
		return httpStatus(se.Code, sentCreds)
	}
	switch {
	case errors.Is(err, netguard.ErrRedirect):
		return model.StatusBlocked, "it answered with a redirect, which jarx never follows"
	case errors.Is(err, netguard.ErrBlocked):
		return model.StatusBlocked, "it resolves to a link-local or cloud metadata address"
	case errors.Is(err, mcp.ErrOtherOrigin):
		return model.StatusBlocked, "its SSE endpoint is on another origin"
	case errors.Is(err, netguard.ErrInsecure):
		return model.StatusInsecure, "plain http:// to an address that isn't loopback"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return model.StatusTimedOut, "no full answer within " + opts.Timeout.String()
	case errors.Is(err, mcp.ErrProtocol), errors.Is(err, mcp.ErrUnsupported), errors.Is(err, mcp.ErrTooLarge), errors.Is(err, netguard.ErrTooLarge):
		return model.StatusUnreachable, "it didn't speak MCP: " + mcpReason(err)
	}
	return model.StatusUnreachable, "the connection failed (DNS, connect or TLS)"
}

// httpStatus is the status for an HTTP error. A 401 or 403 is "requires
// auth" when no credentials were configured, "credential rejected" when
// they were sent.
func httpStatus(code int, sentCreds bool) (model.ServerStatus, string) {
	switch {
	case code != http.StatusUnauthorized && code != http.StatusForbidden:
		return model.StatusUnreachable, "HTTP " + strconv.Itoa(code)
	case sentCreds:
		return model.StatusRejected, "HTTP " + strconv.Itoa(code) + " with the configured credentials"
	}
	return model.StatusRequiresAuth, "HTTP " + strconv.Itoa(code) + " with no credentials configured"
}
