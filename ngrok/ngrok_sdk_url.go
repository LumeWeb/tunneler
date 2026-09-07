package ngrok

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	ngrok "golang.ngrok.com/ngrok/v2"
)

// IsStableNgrokDevURL reports whether u is a stable ngrok dev-domain URL — the
// account's persistent, auto-assigned dev domain (host ends in .ngrok-free.dev).
// The ngrok service gives every free account exactly one dev domain and limits
// free public endpoints to it (random URL generation is a paid-only feature),
// so a bare free-tier forward IS deterministic and this URL is safe to persist.
// The rotating-URL caveat applies to paid accounts, whose bare binds are
// assigned ephemeral random hostnames that change every session.
func IsStableNgrokDevURL(u string) bool {
	if u == "" {
		return false
	}
	parsed, err := url.Parse(u)
	if err != nil {
		return false
	}
	h := parsed.Hostname()
	return strings.HasSuffix(h, ".ngrok-free.dev")
}

// ResolveNgrokSDKURL connects a short-lived embedded ngrok agent with the given
// authtoken and returns the assigned public tunnel URL, then tears the temp
// tunnel down. On a free account the assigned URL is the account's single,
// stable *.ngrok-free.dev dev domain (deterministic per authtoken), so it can
// be used as a stable public URL. No API key is required — the authtoken the
// operator already has (config file / env / wizard) is enough.
//
// It is a package variable so tests can substitute a stub without opening a
// real tunnel.
var ResolveNgrokSDKURL = func(ctx context.Context, token string) (string, error) {
	return resolveNgrokSDKURLReal(ctx, token)
}

// resolveNgrokSDKURLReal is the production implementation: open a temp ngrok
// tunnel through the embedded agent and read its assigned URL. The SDK agent
// sends its http/https bind WITHOUT a hostname when no WithURL option is given
// (the empty-URL branch in the SDK's endpoint option handling), so the ngrok
// service chooses the URL; on a free account its only permitted public
// endpoint base is the account's auto-assigned dev domain. Paid accounts are
// instead given ephemeral random URLs per session, so the returned URL must be
// treated as stable only for free-tier authtokens (see IsStableNgrokDevURL).
func resolveNgrokSDKURLReal(ctx context.Context, token string) (string, error) {
	agentOpts := []ngrok.AgentOption{}
	if token != "" {
		agentOpts = append(agentOpts, ngrok.WithAuthtoken(token))
	}
	agent, err := ngrok.NewAgent(agentOpts...)
	if err != nil {
		return "", fmt.Errorf("construct ngrok agent: %w", err)
	}

	// A local listener that accepts nothing: ngrok only needs an upstream target
	// to establish the tunnel and assign the public dev-domain URL. The tunnel
	// is closed immediately after we read the URL, so no traffic is served.
	upstream := ngrok.WithUpstream("http://127.0.0.1:1")

	// Bounded so a stuck connect cannot hang the install.
	connectCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	fwd, err := agent.Forward(connectCtx, upstream)
	if err != nil {
		_ = agent.Disconnect()
		return "", fmt.Errorf("open temp ngrok tunnel: %w", err)
	}
	if fwd == nil {
		_ = agent.Disconnect()
		return "", errors.New("ngrok forwarder returned nil")
	}
	url := fwd.URL().String()

	// Best-effort bounded teardown. The forwarder close and the agent session
	// disconnect are each deadline-bound so a stuck ngrok service cannot hang
	// the synchronous install — the URL is already captured and must win. The
	// teardown deadline is derived from context.Background() (not the caller's
	// ctx) so it always gets its full 5s budget even if connect already burned
	// up to 30s of the parent deadline.
	tearCtx, tearCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer tearCancel()
	_ = fwd.CloseWithContext(tearCtx)
	// Forward() connects the agent session on the ngrok cloud service;
	// Disconnect releases that session connection so a one-shot resolver that
	// may run more than once does not leak agent/session state.
	_ = agent.Disconnect()
	return url, nil
}
