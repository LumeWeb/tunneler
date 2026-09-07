package ngrok

import (
	"context"
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	ngrokSDK "golang.ngrok.com/ngrok/v2"
)

func TestRequiresToken(t *testing.T) {
	// Explicit token supplied.
	require.False(t, NewNgrokTunnel("", "tok").RequiresToken())

	// NGROK_AUTHTOKEN env set: token source present.
	t.Setenv("NGROK_AUTHTOKEN", "sekret")
	require.False(t, NewNgrokTunnel("", "").RequiresToken())

	// NGROK_CONFIG pointing at an existing config file counts as auth.
	dir := t.TempDir()
	cfg := filepath.Join(dir, "ngrok.yml")
	require.NoError(t, os.WriteFile(cfg, []byte("agent:\n  authtoken: x\n"), 0o600))
	t.Setenv("NGROK_AUTHTOKEN", "")
	t.Setenv("NGROK_CONFIG", cfg)
	require.False(t, NewNgrokTunnel("", "").RequiresToken())

	// No token, no env, no config file: token required.
	t.Setenv("NGROK_CONFIG", filepath.Join(dir, "missing.yml"))
	require.True(t, NewNgrokTunnel("", "").RequiresToken())

	// A config file that exists but declares no usable agent authtoken (empty
	// or broken; authtoken nested under tunnels/endpoints) must NOT satisfy the
	// token requirement, or the embedded agent would start unauthenticated.
	emptyCfg := filepath.Join(dir, "empty.yml")
	require.NoError(t, os.WriteFile(emptyCfg, []byte("version: 2\nagent:\n"), 0o600))
	t.Setenv("NGROK_CONFIG", emptyCfg)
	require.True(t, NewNgrokTunnel("", "").RequiresToken(), "config file with no agent authtoken must still require a token")

	nestedCfg := filepath.Join(dir, "nested.yml")
	require.NoError(t, os.WriteFile(nestedCfg, []byte(
		"version: 2\nlog:\n  level: debug\ntunnels:\n  test:\n    authtoken: not-an-agent-token\n"), 0o600))
	t.Setenv("NGROK_CONFIG", nestedCfg)
	require.True(t, NewNgrokTunnel("", "").RequiresToken(), "authtoken nested under non-agent block must not count")

	// A token persisted to the credential store satisfies the token requirement
	// (no re-prompt / no rejection).
	t.Setenv("NGROK_CONFIG", filepath.Join(dir, "missing.yml"))
	store := newFakeStore("storedtok")
	require.False(t, NewNgrokTunnelWithStore("", "", store).RequiresToken(), "stored token satisfies the requirement")
}

// TestMissingTokenError locks in the error surfaced when RequiresToken() is
// true: a plain error return, no browser opening or onboarding guidance.
func TestMissingTokenError(t *testing.T) {
	// Isolate the config/env sources so a developer's real
	// ~/.config/ngrok/ngrok.yml (or NGROK_AUTHTOKEN) cannot satisfy the token
	// requirement and flip the bare-tunnel assertion.
	t.Setenv("NGROK_AUTHTOKEN", "")
	t.Setenv("NGROK_CONFIG", filepath.Join(t.TempDir(), "ngrok.yml"))
	ng := NewNgrokTunnel("", "")
	require.True(t, ng.RequiresToken(), "bare ngrok tunnel requires a token")
	require.ErrorContains(t, ng.MissingTokenError(), "ngrok tunnel requires an account token")
}

// blockingDialer is a ngrok.Dialer that blocks until its context is done,
// standing in for a ngrok control plane that is reachable at the TCP/TLS
// level but never answers (a genuinely stuck connect). It returns only when
// the bounded connect context aborts, so it exercises the timeout path the
// fix is guarding rather than an immediate dial error.
type blockingDialer struct{}

func (blockingDialer) Dial(string, string) (net.Conn, error) {
	return nil, errors.New("control plane unreachable")
}

func (blockingDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	// Block until the bounded connect context aborts: the only way out is the
	// ctx.Done() branch, which is precisely what must hold for the fix.
	<-ctx.Done()
	return nil, ctx.Err()
}

// TestNgrokStartBoundedConnect guards the bounded-connect fix in Start.
// ngrok's reconnecting session retries the control-plane connection forever
// with no deadline (and ignores cancellation internally), which used to hang
// the server silently when the control plane was unreachable. Start now
// establishes the session with a bounded context, so an unreachable control
// plane must fail fast with an error rather than hang.
//
// A blocking dialer simulates a connect that never completes until the bound's
// context aborts, and a shortened ngrokConnectTimeout keeps the test quick. The
// elapsed-time assertion proves the connect actually waited out the bound
// (300ms window) instead of failing immediately, which is the behavior the fix
// adds. Without the fix, Forward's unbounded reconnect would never abort and
// the test would time out.
func TestNgrokStartBoundedConnect(t *testing.T) {
	oldTimeout := ngrokConnectTimeout
	ngrokConnectTimeout = 300 * time.Millisecond
	t.Cleanup(func() { ngrokConnectTimeout = oldTimeout })

	ng := &ngrokTunnel{
		token:  "test-token",
		dialer: blockingDialer{},
	}

	start := time.Now()
	done := make(chan error, 1)
	go func() { done <- ng.Start(context.Background(), "127.0.0.1:8893") }()

	select {
	case err := <-done:
		require.Error(t, err, "Start must fail when the ngrok control plane never answers")
		require.Contains(t, err.Error(), "connect to ngrok", "error should identify the connect step")
		// It must have waited out the bounded connect window rather than
		// failing immediately. Use ~2/3 of the window as a lower bound so the
		// assertion is robust to scheduling jitter.
		require.GreaterOrEqual(t, time.Since(start), ngrokConnectTimeout*2/3,
			"Start returned too quickly: the bounded connect window was not honored")
	case <-time.After(10 * time.Second):
		// A failure to return here means Start blocked forever in the ngrok
		// reconnecting session instead of honoring the bounded connect.
		t.Fatal("Start hung: bounded ngrok connect did not abort on a stuck control plane")
	}
}

// TestNgrokCheckAccountFailsFast guards the pre-flight login check.
// CheckAccount is called before Start so an invalid/unreachable ngrok account
// fails fast with a clear error instead of hanging inside Start (ngrok's
// session retries a bad authtoken until its connect deadline). A blocking
// dialer stands in for a control plane that never answers, and a shortened
// ngrokLoginProbeTimeout keeps the test quick; the probe (not the larger
// connect window) must be the bound that aborts.
func TestNgrokCheckAccountFailsFast(t *testing.T) {
	oldProbe := ngrokLoginProbeTimeout
	oldConnect := ngrokConnectTimeout
	ngrokLoginProbeTimeout = 300 * time.Millisecond
	ngrokConnectTimeout = 30 * time.Second // probe, not connect, must be the bound
	t.Cleanup(func() {
		ngrokLoginProbeTimeout = oldProbe
		ngrokConnectTimeout = oldConnect
	})

	ng := &ngrokTunnel{
		token:  "test-token",
		dialer: blockingDialer{},
	}

	start := time.Now()
	done := make(chan error, 1)
	go func() { done <- ng.CheckAccount(context.Background()) }()

	select {
	case err := <-done:
		require.Error(t, err, "CheckAccount must fail when the ngrok control plane never answers")
		require.Contains(t, err.Error(), "ngrok login check", "error should identify the login-check step")
		// It must have waited out the probe window rather than failing
		// immediately, and must not reach the much larger connect window.
		require.GreaterOrEqual(t, time.Since(start), ngrokLoginProbeTimeout*2/3,
			"CheckAccount returned too quickly: the login probe window was not honored")
		require.Less(t, time.Since(start), 5*time.Second,
			"CheckAccount took too long: the login probe must fail fast, not wait the connect window")
	case <-time.After(5 * time.Second):
		t.Fatal("CheckAccount hung: login probe did not abort on a stuck control plane")
	}
}

// fakeNgrokForwarder is a minimal ngrok.EndpointForwarder for tests. It embeds
// the interface so every method is satisfied with zero boilerplate, overriding
// only URL (used by Start/setReady), Done (used by waitReady), and
// CloseWithContext (used by Stop, which the waitReady-failure teardown calls).
// Calling any other method would panic, but the production code path exercised
// by these tests only touches those three.
type fakeNgrokForwarder struct {
	ngrokSDK.EndpointForwarder
	u      *url.URL
	done   chan struct{}
	closed int
}

func (f *fakeNgrokForwarder) URL() *url.URL { return f.u }

func (f *fakeNgrokForwarder) CloseWithContext(context.Context) error {
	f.closed++
	return nil
}

func (f *fakeNgrokForwarder) Done() <-chan struct{} {
	if f.done == nil {
		f.done = make(chan struct{})
	}
	return f.done
}

// fakeNgrokAgent is a minimal ngrok.Agent for tests, embedding the interface to
// avoid implementing the full surface. It records the connect context handed to
// it and returns configurable errors/forwarders from Connect and Forward —
// the only Agent methods the tunnel code calls.
type fakeNgrokAgent struct {
	ngrokSDK.Agent
	connectErr error
	forwardErr error
	fwd        ngrokSDK.EndpointForwarder
	connectCtx context.Context
}

func (f *fakeNgrokAgent) Connect(ctx context.Context) error {
	f.connectCtx = ctx
	return f.connectErr
}

func (f *fakeNgrokAgent) Forward(_ context.Context, _ *ngrokSDK.Upstream, _ ...ngrokSDK.EndpointOption) (ngrokSDK.EndpointForwarder, error) {
	// Model the real SDK: an agent binds its session to the context passed to
	// Connect, so once that context is cancelled the session is closed. Forward
	// then fails with "session closed" even though the agent still believes it
	// is connected. This is what let the regression tests below catch premature
	// cancellation of the connect context.
	if f.connectCtx != nil && f.connectCtx.Err() != nil {
		return nil, errors.New("session closed")
	}
	if f.forwardErr != nil {
		return nil, f.forwardErr
	}
	return f.fwd, nil
}

// TestNgrokCheckAccountDoesNotPoisonStartSession is the regression test for
// the "session closed" failure. An ngrok agent's session is bound to the
// context passed to Connect: cancelling that context closes the session. The
// login probe previously ran through connectedAgent, which cached the probe's
// agent; when the short-lived probe context was then cancelled the cached
// session was torn down, so Start reused a dead agent and agent.Forward failed
// with "start ngrok tunnel: failed to start tunnel: session closed".
//
// The fix makes CheckAccount probe with its own throwaway agent (never cached)
// while Start always establishes a fresh, durable session. A factory-injected
// fake agent lets this test assert the exact contract that prevents the bug:
// CheckAccount builds exactly one probe agent, Start builds a second, distinct
// agent to forward through, and never reuses the probe's.
func TestNgrokCheckAccountDoesNotPoisonStartSession(t *testing.T) {
	var agents []*fakeNgrokAgent
	ng := &ngrokTunnel{
		domain: "mcp.example.com",
		token:  "test-token",
		agentFactory: func(...ngrokSDK.AgentOption) (ngrokSDK.Agent, error) {
			a := &fakeNgrokAgent{
				fwd: &fakeNgrokForwarder{u: &url.URL{Scheme: "https", Host: "mcp.example.com"}},
			}
			agents = append(agents, a)
			return a, nil
		},
	}

	// A successful login probe must fail fast with no error and, crucially,
	// must not cache the probed agent for later reuse.
	require.NoError(t, ng.CheckAccount(context.Background()))
	require.Len(t, agents, 1, "CheckAccount must build exactly one throwaway probe agent")
	probe := agents[0]

	// Start must establish its own fresh session and still succeed after the
	// probe. A custom domain is used so Start takes the pre-assigned-URL
	// branch and does not probe public reachability.
	err := ng.Start(context.Background(), "127.0.0.1:8893")
	require.NoError(t, err, "Start must succeed with its own session after a login probe")

	require.Len(t, agents, 2, "Start must build a fresh agent rather than reuse the probe's")
	startAgent := agents[1]
	require.NotSame(t, probe, startAgent, "Start must not reuse the CheckAccount probe agent")

	// The probe's connect ran under a short probe-bound context (its own
	// throwaway session), while Start's connect ran under the caller context —
	// confirming the two sessions are independent.
	require.NotNil(t, probe.connectCtx, "probe agent must have received a connect context")
	require.NotNil(t, startAgent.connectCtx, "start agent must have received a connect context")
	require.NotEqual(t, probe.connectCtx, startAgent.connectCtx, "probe and start sessions must use independent contexts")
}

// TestNgrokForwardFailureClearsCachedAgent is the regression test for the
// retry-after-Forward-failure failure. When agent.Forward failed inside Start,
// the teardown cancelled the session context but left the cached n.agent,
// n.stopSession, and n.stop fields populated — so connectedAgent returned the
// cached, now-dead agent on the next Start, and the retry deterministically
// failed with "session closed" instead of rebuilding a live agent and session.
//
// The fix clears the cached fields while tearing the session down, so a failed
// Start leaves the tunnel cleanly unstarted and a retry builds a fresh agent.
// The factory counts builds; a forwardErr that flips off after the first
// failure lets the test assert both the field reset and that the retry uses a
// newly built agent.
func TestNgrokForwardFailureClearsCachedAgent(t *testing.T) {
	forwardErr := errors.New("transient forward failure")
	fail := true
	builds := 0
	ng := &ngrokTunnel{
		domain: "mcp.example.com",
		token:  "test-token",
		agentFactory: func(...ngrokSDK.AgentOption) (ngrokSDK.Agent, error) {
			builds++
			return &fakeNgrokAgent{forwardErr: func() error {
				if fail {
					return forwardErr
				}
				return nil
			}(), fwd: &fakeNgrokForwarder{u: &url.URL{Scheme: "https", Host: "mcp.example.com"}}}, nil
		},
	}

	// First Start: connect succeeds but Forward fails transiently.
	err := ng.Start(context.Background(), "127.0.0.1:8893")
	require.ErrorIs(t, err, forwardErr, "Start must surface the Forward failure")
	require.Equal(t, 1, builds, "the failed attempt must have built exactly one agent")

	// The failure must reset the cached agent and session teardown hooks: the
	// session context was cancelled, so the cached agent is dead. Pre-fix these
	// fields stayed non-nil and a retry reused the dead agent.
	ng.mu.Lock()
	require.Nil(t, ng.agent, "agent cache must be cleared after a Forward failure")
	require.Nil(t, ng.stopSession, "session teardown hook must be cleared after a Forward failure")
	require.Nil(t, ng.stop, "forward-cancel hook must be cleared after a Forward failure")
	require.False(t, ng.ready, "a failed Start must not mark the tunnel ready")
	ng.mu.Unlock()

	// A retry must rebuild a fresh agent rather than short-circuit on the
	// cached (dead) one, and succeed now that the transient error is gone.
	fail = false
	require.NoError(t, ng.Start(context.Background(), "127.0.0.1:8893"))
	require.Equal(t, 2, builds, "a retry after a Forward failure must build a fresh agent")
	ready, gotURL := ng.getState()
	require.True(t, ready, "the successful retry must mark the tunnel ready")
	require.Equal(t, "https://mcp.example.com", gotURL)
}

// TestNgrokWaitReadyFailureClearsCachedAgent is the regression test for the
// retry-after-readiness-failure failure. When waitReady timed out inside Start
// (free-tier path: the assigned public URL never accepted traffic), the
// teardown called Stop — which cancelled the session context — but left the
// cached n.agent, n.stopSession, and n.stop fields populated, exactly like the
// Forward-failure case. A retry's connectedAgent then short-circuited on the
// cached, now-dead agent and agent.Forward deterministically failed with
// "session closed" instead of rebuilding a live agent and session.
//
// The fix clears the cached fields after the Stop teardown, mirroring the
// Forward-failure branch. The factory counts builds; the fake forwarder's URL
// points at a dead local address so waitReady's public-URL probe (against a
// shrunk ngrokWaitReadyTimeout) times out and drives the failure path.
func TestNgrokWaitReadyFailureClearsCachedAgent(t *testing.T) {
	oldWait := ngrokWaitReadyTimeout
	ngrokWaitReadyTimeout = 50 * time.Millisecond
	t.Cleanup(func() { ngrokWaitReadyTimeout = oldWait })

	builds := 0
	ng := &ngrokTunnel{
		token: "test-token",
		agentFactory: func(...ngrokSDK.AgentOption) (ngrokSDK.Agent, error) {
			builds++
			return &fakeNgrokAgent{
				fwd: &fakeNgrokForwarder{u: &url.URL{Scheme: "http", Host: "127.0.0.1:1"}},
			}, nil
		},
	}

	// No custom domain: Start takes the free-tier branch and waits for the
	// provider-assigned URL to accept traffic. The fake forwarder's URL points
	// at a non-responding local address, so waitReady must time out and Start
	// must surface the failure.
	err := ng.Start(context.Background(), "127.0.0.1:8893")
	require.Error(t, err, "Start must fail when the assigned URL never accepts traffic")
	require.Contains(t, err.Error(), "timed out waiting for ngrok tunnel",
		"the failure must come from the waitReady readiness window")
	require.Equal(t, 1, builds, "the failed attempt must have built exactly one agent")

	// The failure must reset the cached agent and session teardown hooks: Stop
	// cancelled the session context, so the cached agent is dead. Pre-fix
	// (before the waitReady-failure branch cleared them) these fields stayed
	// non-nil and a retry reused the dead agent.
	ng.mu.Lock()
	require.Nil(t, ng.agent, "agent cache must be cleared after a readiness failure")
	require.Nil(t, ng.stopSession, "session teardown hook must be cleared after a readiness failure")
	require.Nil(t, ng.stop, "forward-cancel hook must be cleared after a readiness failure")
	require.False(t, ng.ready, "a failed Start must not mark the tunnel ready")
	ng.mu.Unlock()

	// A retry must rebuild a fresh agent rather than short-circuit on the
	// cached (dead) one. The retry goes through the same dead-URL readiness
	// window and fails again — the assertion here is on the rebuild, proving
	// the retry did not get stuck on the stale agent.
	require.Error(t, ng.Start(context.Background(), "127.0.0.1:8893"))
	require.Equal(t, 2, builds, "a retry after a readiness failure must build a fresh agent")
}

// TestNgrokStartKeepsSessionAliveAfterConnect is the regression test for the
// "start ngrok tunnel: failed to start tunnel: session closed" failure. The
// previous bounded-connect code used context.WithTimeout and cancelled the
// connect context immediately after a successful agent.Connect. Because the
// ngrok SDK binds the session to the Connect context, that cancel closed the
// session; a subsequent Forward then failed with "session closed" despite the
// agent still reporting itself connected.
//
// This test drives Start directly with a fake agent that models the SDK's
// session-close-on-connect-cancel behavior (see fakeNgrokAgent.Forward). With
// the fix, the connect deadline is released on success and never cancels the
// live session, so Forward succeeds and Start returns nil. A custom domain is
// used so Start takes the pre-assigned-URL branch and does not probe public
// reachability.
func TestNgrokStartKeepsSessionAliveAfterConnect(t *testing.T) {
	ng := &ngrokTunnel{
		domain: "mcp.example.com",
		token:  "test-token",
		agentFactory: func(...ngrokSDK.AgentOption) (ngrokSDK.Agent, error) {
			return &fakeNgrokAgent{
				fwd: &fakeNgrokForwarder{u: &url.URL{Scheme: "https", Host: "mcp.example.com"}},
			}, nil
		},
	}

	err := ng.Start(context.Background(), "127.0.0.1:8893")
	require.NoError(t, err, "Start must not tear down the session after a successful connect")

	// Sanity: the session context was never cancelled, so the forwarder is usable.
	a := ng.agent.(*fakeNgrokAgent)
	require.NoError(t, a.connectCtx.Err(), "the live session context must stay uncancelled")
}
