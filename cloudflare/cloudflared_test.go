package cloudflare

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/cloudflare/cloudflared/signal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.lumeweb.com/tunneler"
)

// TestCloudflaredStopAfterExit guards the exit-detection path of the embedded
// tunnel: once the in-process daemon has shut down (done closed), a subsequent
// Stop must return promptly instead of blocking.
func TestCloudflaredStopAfterExit(t *testing.T) {
	done := make(chan struct{})
	close(done) // daemon already exited

	c := &CloudflaredTunnel{done: done}

	// Stop must return promptly instead of blocking on the closed channel.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	started := time.Now()
	assert.NoError(t, c.Stop(ctx))
	assert.Less(t, time.Since(started), 3*time.Second, "Stop blocked after process exit")
}

// TestCloudflaredStopBeforeStart guards the not-started path: Stop on a tunnel
// whose daemon was never launched must be a no-op rather than a panic or hang.
func TestCloudflaredStopBeforeStart(t *testing.T) {
	c := &CloudflaredTunnel{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	assert.NoError(t, c.Stop(ctx))
}

// TestURLNotReadySentinel guards the pre-Start URL contract.
func TestURLNotReadySentinel(t *testing.T) {
	c := &CloudflaredTunnel{}
	_, err := c.URL()
	require.ErrorIs(t, err, tunneler.ErrNotReady)
}

// TestCloudflaredStartMissingState guards the provisioning gate: Start without
// a provisioned tunnel state (beyond a --domain) must report a clear error
// rather than attempt to build a tunnel from empty credentials.
func TestCloudflaredStartMissingState(t *testing.T) {
	c := &CloudflaredTunnel{domain: "mcp.example.com", statePath: filepath.Join(t.TempDir(), "missing.json")}
	err := c.Start(context.Background(), "127.0.0.1:8893")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no provisioned cloudflare tunnel found")
}

// TestMissingTokenError guards the unprovisioned-tunnel error surfaced when
// RequiresToken() is true.
func TestMissingTokenError(t *testing.T) {
	cf := &CloudflaredTunnel{statePath: filepath.Join(t.TempDir(), "missing.json"), name: "t"}
	require.True(t, cf.RequiresToken(), "unprovisioned cloudflared tunnel requires setup")
	require.ErrorContains(t, cf.MissingTokenError(), "cloudflared tunnel is not provisioned")
}

// TestCloudflaredStartReadyOnConnectedSignal locks the readiness contract:
// Start must succeed — and mark the tunnel ready — once the cloudflared
// CONNECTED signal fires (the connector's edge connection is established) AND
// the post-connected deliverability probe confirms a genuine origin response.
// Readiness is a HYBRID: the deterministic connected signal establishes the
// edge connection without racing the connector's startup, then a bounded,
// edge-aware probe of the public URL verifies the hostname actually delivers
// (the probe's classifier excludes Cloudflare WAF/challenge/routing pages, so
// they are never mistaken for an origin response).
func TestCloudflaredStartReadyOnConnectedSignal(t *testing.T) {
	// Provision a synthetic (non-real) tunnel state so Start passes the
	// provisioning gate.
	_ = redirectTunnelStatePath(t)
	require.NoError(t, SaveCloudflareTunnelState(fixtureState()))

	// Shrink the connect timeout: against a regression that never observes the
	// signal, the test fails fast instead of hanging on the production cap.
	origConnect := cloudflaredConnectTimeout
	cloudflaredConnectTimeout = 2 * time.Second
	t.Cleanup(func() { cloudflaredConnectTimeout = origConnect })

	// Stub the probe seam: the edge-aware deliverability probe succeeds (its
	// network behavior is the real network's problem, not this test's).
	origProbe := probeOriginReady
	probeURL := ""
	probeTimeout := time.Duration(0)
	probeOriginReady = func(publicURL string, timeout time.Duration) bool {
		probeURL = publicURL
		probeTimeout = timeout
		return true
	}
	t.Cleanup(func() { probeOriginReady = origProbe })

	// Stub the embedded-daemon seam: on launch, notify the CONNECTED signal
	// (the edge connection is up) and then keep running, like a real daemon.
	origDaemon := startEmbeddedCloudflared
	startEmbeddedCloudflared = func(_ context.Context, _ *CloudflareTunnelState, _ string, connected *signal.Signal) error {
		connected.Notify()
		<-make(chan struct{}) // block forever; simulate a live daemon (goroutine leaks by design)
		return nil
	}
	t.Cleanup(func() { startEmbeddedCloudflared = origDaemon })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c := &CloudflaredTunnel{}
	require.NoError(t, c.Start(ctx, "127.0.0.1:8893"),
		"Start must succeed once the cloudflared CONNECTED signal fires")

	url, err := c.URL()
	require.NoError(t, err, "the tunnel must be marked ready after the CONNECTED signal")
	assert.Equal(t, "https://mcp.example.com", url)

	// The hybrid's second stage must actually have run: the probe received the
	// public URL derived from the provisioned state and the probe budget.
	assert.Equal(t, "https://mcp.example.com", probeURL, "the deliverability probe must target the public URL")
	assert.Equal(t, cloudflaredProbeTimeout, probeTimeout, "the deliverability probe must run with the package budget")
}

// TestCloudflaredStartTimeoutWhenConnectedNeverFires guards BOTH the failure
// gate and the bounded teardown: when the daemon never fires the CONNECTED
// signal (and never exits), Start must return the connect-timeout error —
// proving it no longer hangs on any readiness probe — and its post-failure
// teardown must be bounded by the independent cloudflaredTeardownTimeout (not
// the caller's context), even though the stubbed daemon ignores cancellation.
func TestCloudflaredStartTimeoutWhenConnectedNeverFires(t *testing.T) {
	// Provision a synthetic (non-real) tunnel state so Start passes the
	// provisioning gate.
	_ = redirectTunnelStatePath(t)
	require.NoError(t, SaveCloudflareTunnelState(fixtureState()))

	// Shrink both the connect timeout and the independent teardown cap so the
	// test completes quickly; the cleanups restore the production values for
	// other tests.
	connectTimeout := 300 * time.Millisecond
	origConnect := cloudflaredConnectTimeout
	cloudflaredConnectTimeout = connectTimeout
	t.Cleanup(func() { cloudflaredConnectTimeout = origConnect })

	smallCap := 200 * time.Millisecond
	origTeardown := cloudflaredTeardownTimeout
	cloudflaredTeardownTimeout = smallCap
	t.Cleanup(func() { cloudflaredTeardownTimeout = origTeardown })

	// Stub the embedded-daemon seam with one that NEVER fires the connected
	// signal and NEVER exits: neither the readiness signal nor done can
	// unblock Start, so only the connect timeout can fail the wait and only
	// the independent cap can release the teardown.
	entered := make(chan struct{})
	origDaemon := startEmbeddedCloudflared
	startEmbeddedCloudflared = func(context.Context, *CloudflareTunnelState, string, *signal.Signal) error {
		// The seam var has now been read by the daemon goroutine; signal so the
		// cleanup never restores the package var ahead of that read (race-
		// detector hygiene, the goroutine intentionally leaks).
		close(entered)
		<-make(chan struct{}) // block forever; simulate a stuck daemon
		return nil
	}
	t.Cleanup(func() { startEmbeddedCloudflared = origDaemon })

	// A long-lived caller context: everything must be driven by the connect
	// timeout and the teardown cap, never by ctx.Done().
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	c := &CloudflaredTunnel{}
	started := time.Now()
	type startResult struct{ err error }
	res := make(chan startResult, 1)
	go func() { res <- startResult{c.Start(ctx, "127.0.0.1:8893")} }()

	select {
	case r := <-res:
		// Ensure the daemon goroutine actually dispatched through the stubbed
		// seam before cleanup restores it.
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("daemon goroutine never invoked the stubbed seam")
		}
		// Start must surface the connect timeout, not any other failure.
		require.ErrorContains(t, r.err, "timed out waiting for cloudflared tunnel")
		// The connect timeout must actually have been honored: Start cannot
		// return before it elapses.
		assert.GreaterOrEqual(t, time.Since(started), connectTimeout,
			"readiness must wait for the CONNECTED signal (bounded by cloudflaredConnectTimeout), not return early")
		// Bounded teardown: even though the daemon ignores cancellation, the
		// total wait is capped at connectTimeout + cloudflaredTeardownTimeout
		// (plus scheduling slack) — a daemon that never exits must not block
		// Start beyond the independent cap.
		assert.Less(t, time.Since(started), connectTimeout+smallCap+2*time.Second,
			"post-failure teardown must be bounded by the independent cap even when the daemon never exits")
	case <-time.After(15 * time.Second):
		t.Fatal("Start hung: neither the connect timeout nor the bounded teardown was honored")
	}
}
