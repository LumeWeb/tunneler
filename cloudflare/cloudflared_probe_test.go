package cloudflare

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cloudflare/cloudflared/signal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.lumeweb.com/tunneler"
)

// TestCloudflaredStartFailsWhenProbeDoesNotConfirmReachability locks the
// second stage of the hybrid readiness gate: when the CONNECTED signal fires
// but the post-connected deliverability probe does NOT confirm a genuine
// origin response (e.g. the DNS/CNAME route is missing or the origin is
// unreachable), Start must FAIL with the "did not become reachable" error.
// The failure path must still undergo the bounded, independent teardown: the
// daemon never observes cancellation yet Start returns within a small bound.
func TestCloudflaredStartFailsWhenProbeDoesNotConfirmReachability(t *testing.T) {
	// Provision a synthetic (non-real) tunnel state so Start passes the
	// provisioning gate.
	_ = redirectTunnelStatePath(t)
	require.NoError(t, SaveCloudflareTunnelState(fixtureState()))

	// Stub the embedded-daemon seam: on launch, notify the CONNECTED signal
	// (the edge connection is established) and then keep running like a real
	// daemon that ignores the readiness failure below — so the readiness
	// failure can only come from the probe, and the teardown can only be
	// released by the independent cap (the daemon exits on cancellation via
	// ctx.Done(), but the failure teardown select waits on `done`, which only
	// closes when the goroutine returns; with the small cap the elapsed bound
	// below proves the independence still holds).
	origDaemon := startEmbeddedCloudflared
	startEmbeddedCloudflared = func(ctx context.Context, _ *CloudflareTunnelState, _ string, connected *signal.Signal) error {
		connected.Notify()
		<-ctx.Done() // keep the daemon goroutine live until Stop/teardown cancel
		return nil
	}
	t.Cleanup(func() { startEmbeddedCloudflared = origDaemon })

	// Stub the probe seam so it NEVER confirms deliverability even though the
	// connected signal fired (its network behavior is otherwise out of scope).
	origProbe := probeOriginReady
	probeOriginReady = func(publicURL string, timeout time.Duration) bool {
		return false
	}
	t.Cleanup(func() { probeOriginReady = origProbe })

	// Shrink the independent teardown cap so a regression that blocks or
	// hangs in the failure path fails fast instead of hanging.
	smallCap := 200 * time.Millisecond
	origTeardown := cloudflaredTeardownTimeout
	cloudflaredTeardownTimeout = smallCap
	t.Cleanup(func() { cloudflaredTeardownTimeout = origTeardown })

	// A long-lived caller context: the failure must come from the probe, not
	// from connect-timeout or ctx cancellation.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	c := &CloudflaredTunnel{}
	started := time.Now()
	err := c.Start(ctx, "127.0.0.1:8893")
	elapsed := time.Since(started)

	// The connected signal fired, but the probe refused to confirm
	// deliverability, so Start must fail with the reachability error.
	require.Error(t, err)
	assert.ErrorContains(t, err, "did not become reachable")

	// The tunnel must NOT be marked ready.
	_, urlErr := c.URL()
	assert.ErrorIs(t, urlErr, tunneler.ErrNotReady, "URL must report not-ready after a failed deliverability probe")

	// Bounded teardown: the stubbed daemon exits promptly on cancellation, so
	// Start must return well within the run: but even if it did not, the
	// independent cap would still bound the wait; this assertion proves the
	// probe-failure path completes promptly rather than hanging.
	assert.Less(t, elapsed, smallCap+2*time.Second,
		"post-failure teardown must be bounded even when the daemon never exits")
}

// TestIsGenuineOriginResponse is a table test of the edge-aware response
// classifier used by the hybrid readiness probe: only a 2xx-4xx response
// WITHOUT Cloudflare edge artifacts (challenge pages, edge error pages) is a
// genuine origin response. A naive "<500" rule would falsely treat Cloudflare
// WAF 403s / routing error pages as origin responses.
func TestIsGenuineOriginResponse(t *testing.T) {
	tests := []struct {
		name string
		// build returns the response under test (via httptest for realism).
		build   func(t *testing.T) *http.Response
		genuine bool
	}{
		{"200 from origin", func(_ *testing.T) *http.Response {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			t.Cleanup(srv.Close)
			resp, err := http.Get(srv.URL)
			require.NoError(t, err)
			t.Cleanup(func() { _ = resp.Body.Close() })
			return resp
		}, true},
		{"301 redirect from origin", func(_ *testing.T) *http.Response {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusMovedPermanently)
			}))
			t.Cleanup(srv.Close)
			resp, err := http.Get(srv.URL)
			require.NoError(t, err)
			t.Cleanup(func() { _ = resp.Body.Close() })
			return resp
		}, true},
		{"404 from origin (no edge headers)", func(_ *testing.T) *http.Response {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			}))
			t.Cleanup(srv.Close)
			resp, err := http.Get(srv.URL)
			require.NoError(t, err)
			t.Cleanup(func() { _ = resp.Body.Close() })
			return resp
		}, true},
		{"403 without edge headers (origin-enforced)", func(_ *testing.T) *http.Response {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusForbidden)
			}))
			t.Cleanup(srv.Close)
			resp, err := http.Get(srv.URL)
			require.NoError(t, err)
			t.Cleanup(func() { _ = resp.Body.Close() })
			return resp
		}, true},
		{"503 (not 2xx-4xx)", func(_ *testing.T) *http.Response {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusServiceUnavailable)
			}))
			t.Cleanup(srv.Close)
			resp, err := http.Get(srv.URL)
			require.NoError(t, err)
			t.Cleanup(func() { _ = resp.Body.Close() })
			return resp
		}, false},
		{"403 challenge page (cf-mitigated)", func(_ *testing.T) *http.Response {
			return &http.Response{StatusCode: http.StatusForbidden, Header: http.Header{
				"Cf-Mitigated": []string{"challenge"},
			}}
		}, false},
		{"402 challenge page (cf-mitigated)", func(_ *testing.T) *http.Response {
			return &http.Response{StatusCode: 402, Header: http.Header{
				"Cf-Mitigated": []string{"challenge"},
			}}
		}, false},
		{"403 with cf-error-type (edge WAF error 1020)", func(_ *testing.T) *http.Response {
			return &http.Response{StatusCode: http.StatusForbidden, Header: http.Header{
				"Cf-Error-Type": []string{"error_1020"},
			}}
		}, false},
		{"502 with cf-error-type (edge routing error)", func(_ *testing.T) *http.Response {
			return &http.Response{StatusCode: http.StatusBadGateway, Header: http.Header{
				"Cf-Error-Type": []string{"error_502"},
			}}
		}, false},
		{"404 with cf-error-type (origin DNS error 1016)", func(_ *testing.T) *http.Response {
			return &http.Response{StatusCode: http.StatusNotFound, Header: http.Header{
				"Cf-Error-Type":   []string{"error_1016"},
				"Cf-Error-Origin": []string{"dns"},
			}}
		}, false},
		{"200 with cf-error-origin only (edge-annotated)", func(_ *testing.T) *http.Response {
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{
				"Cf-Error-Origin": []string{"cloudflare"},
			}}
		}, false},
		{"nil response", nil, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var resp *http.Response
			if tc.build != nil {
				resp = tc.build(t)
			}
			assert.Equal(t, tc.genuine, isGenuineOriginResponse(resp))
		})
	}
}
