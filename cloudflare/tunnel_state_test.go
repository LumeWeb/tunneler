package cloudflare

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.lumeweb.com/tunneler"
)

// redirectTunnelStatePath points TunnelStatePath at a temp dir for the
// duration of the test and returns the file path that load/save will use.
func redirectTunnelStatePath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "tunnel-state.json")
	orig := TunnelStatePath
	TunnelStatePath = func() (string, error) { return path, nil }
	t.Cleanup(func() { TunnelStatePath = orig })
	return path
}

func TestTunnelStateDefaultPath(t *testing.T) {
	// The default path must live under the per-user config dir in a generic
	// (non-application-specific) directory: <UserConfigDir>/tunneler/tunnel-state.json.
	t.Setenv("XDG_CONFIG_HOME", "")
	var want string
	if runtime.GOOS == "windows" {
		dir := t.TempDir()
		t.Setenv("APPDATA", dir)
		want = filepath.Join(dir, "tunneler", "tunnel-state.json")
	} else {
		dir := t.TempDir()
		t.Setenv("HOME", dir)
		if runtime.GOOS == "darwin" {
			want = filepath.Join(dir, "Library", "Application Support", "tunneler", "tunnel-state.json")
		} else {
			t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, ".config"))
			want = filepath.Join(dir, ".config", "tunneler", "tunnel-state.json")
		}
	}
	got, err := TunnelStatePath()
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

// fixtureState returns a CloudflareTunnelState with clearly synthetic (non-real)
// values.
func fixtureState() *CloudflareTunnelState {
	return &CloudflareTunnelState{
		Provider:   tunneler.TunnelProviderCloudflared,
		AccountID:  "acct-0123456789abcdef0123456789abcdef",
		TunnelID:   "01234567-89ab-4def-8123-456789abcdef",
		TunnelName: "tunneler-fixture",
		Secret:     "c2VjcmV0LWZpY3Rpb24tbm90LXJlYWw=", // base64 of a fixture string
		Token:      "tkn-fixture",
		Hostname:   "mcp.example.com",
	}
}

func TestCloudflareTunnelStateRoundTrip(t *testing.T) {
	path := redirectTunnelStatePath(t)

	// Nothing provisioned yet: Load must return os.ErrNotExist.
	_, err := LoadCloudflareTunnelState()
	require.True(t, os.IsNotExist(err), "missing state file must surface os.ErrNotExist")

	// Save then load round-trips the persisted state.
	in := fixtureState()
	require.NoError(t, SaveCloudflareTunnelState(in))

	// The persisted file must be private (first-class secrets).
	fi, err := os.Stat(path)
	require.NoError(t, err)
	assert.Zero(t, fi.Mode().Perm()&0o077, "tunnel state file must not be group/world readable")

	out, err := LoadCloudflareTunnelState()
	require.NoError(t, err)
	assert.Equal(t, in, out)
}

func TestSaveCloudflareTunnelStateNil(t *testing.T) {
	redirectTunnelStatePath(t)
	require.Error(t, SaveCloudflareTunnelState(nil))
}

func TestParseTunnelStateMalformed(t *testing.T) {
	_, err := parseTunnelState([]byte("not json"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse tunnel state")
}

func TestParseTunnelStateMinimal(t *testing.T) {
	// A minimal document decodes with the provider field populated.
	s, err := parseTunnelState([]byte(`{"provider":"cloudflared","tunnel_id":"id"}`))
	require.NoError(t, err)
	assert.Equal(t, tunneler.TunnelProviderCloudflared, s.Provider)
	assert.Equal(t, "id", s.TunnelID)
}
