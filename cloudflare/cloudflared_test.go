package cloudflare

import (
	"context"
	"path/filepath"
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
