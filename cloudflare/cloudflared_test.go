package cloudflare

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.lumeweb.com/tunneler"
)

// TestCloudflaredStopAfterExit guards the exit-detection path of the embedded
// tunnel: once the in-process daemon has shut down (done closed), waitReady
// must observe the exit rather than spinning to its deadline, and a subsequent
// Stop must return promptly instead of blocking.
func TestCloudflaredStopAfterExit(t *testing.T) {
	done := make(chan struct{})
	close(done) // daemon already exited

	c := &CloudflaredTunnel{done: done}

	// waitReady must fail fast with the exit error, not time out.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := c.waitReady(ctx, "https://exited.invalid")
	assert.ErrorContains(t, err, "exited before the tunnel became ready")

	// Stop must return promptly instead of blocking on the closed channel.
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

// TestWaitReadyRequiresSuccessStatus guards the readiness semantics: only a
// 2xx/3xx response over the tunnel counts as ready. Cloudflare fronts an
// unreachable origin with gateway error pages (502/503/530), so waitReady must
// keep polling through those instead of treating the first response (any
// status) as success.
func TestWaitReadyRequiresSuccessStatus(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Answer with 503 gateway error pages for the first three probes; only
		// then does the tunnel "deliver to the origin" (200).
		if atomic.AddInt32(&hits, 1) <= 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := &CloudflaredTunnel{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	require.NoError(t, c.waitReady(ctx, srv.URL), "waitReady must return once the tunnel serves a success response")
	// Against the old StatusCode > 0 logic waitReady returned on the very
	// first probe (single hit); polling through the 503s proves the fix.
	assert.GreaterOrEqual(t, atomic.LoadInt32(&hits), int32(4),
		"waitReady must keep polling through 503 gateway error pages, not return on the first response")
}

// TestCloudflaredStartBoundedTeardownAfterWaitReadyFailure guards the
// bounded post-cancel teardown in Start: when waitReady fails, Start cancels
// the daemon and must NOT block forever on its exit — a daemon that does not
// promptly observe cancellation (mirroring ngrok's bounded-teardown rationale)
// releases Start as soon as the caller's context is done.
func TestCloudflaredStartBoundedTeardownAfterWaitReadyFailure(t *testing.T) {
	// Provision a synthetic (non-real) tunnel state so Start passes the
	// provisioning gate.
	_ = redirectTunnelStatePath(t)
	require.NoError(t, SaveCloudflareTunnelState(fixtureState()))

	// Stub the embedded-daemon seam with one that never observes
	// cancellation: the daemon never exits, so only the bounded select
	// (ctx.Done()) can unblock Start's teardown.
	entered := make(chan struct{})
	origDaemon := startEmbeddedCloudflared
	startEmbeddedCloudflared = func(context.Context, *CloudflareTunnelState, string) error {
		// The seam var has now been read by the daemon goroutine; signal so the
		// test never restores the stack var ahead of that read (race-detector
		// hygiene, the goroutine intentionally leaks).
		close(entered)
		<-make(chan struct{}) // block forever; simulate a stuck daemon
		return nil
	}
	t.Cleanup(func() { startEmbeddedCloudflared = origDaemon })

	// Use a reserved .invalid hostname so the readiness probe fails fast
	// offline (DNS NXDOMAIN), deterministically driving waitReady to fail via
	// the caller's deadline.
	st, err := LoadCloudflareTunnelState()
	require.NoError(t, err)
	st.Hostname = "bounded-teardown.invalid"
	require.NoError(t, SaveCloudflareTunnelState(st))

	c := &CloudflaredTunnel{}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

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
		// Start must surface the waitReady failure; the bounded wait released
		// it via ctx.Done() even though the daemon never exited.
		require.ErrorIs(t, r.err, context.DeadlineExceeded)
	case <-time.After(15 * time.Second):
		t.Fatal("Start blocked in post-cancel teardown: the bounded wait (ctx.Done) was not honored")
	}
}
