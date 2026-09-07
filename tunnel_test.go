package tunneler

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSplitHostPort(t *testing.T) {
	cases := []struct {
		in    string
		host  string
		port  string
		valid bool
	}{
		{"8080", "127.0.0.1", "8080", true},
		{"127.0.0.1:8893", "127.0.0.1", "8893", true},
		{"[::1]:8893", "::1", "8893", true},
		{"", "", "", false},
		{"host:notaport", "", "", false},
	}
	for _, c := range cases {
		host, port, err := SplitHostPort(c.in)
		if !c.valid {
			assert.Error(t, err, "expected error for %q", c.in)
			continue
		}
		require.NoError(t, err, "split %q", c.in)
		assert.Equal(t, c.host, host)
		assert.Equal(t, c.port, port)
	}
}

func TestLocalURL(t *testing.T) {
	assert.Equal(t, "http://127.0.0.1:8893", LocalURL("127.0.0.1", "8893"))
	assert.Equal(t, "http://localhost:7000", LocalURL("localhost", "7000"))
	assert.Equal(t, "http://[::1]:8080", LocalURL("::1", "8080"))
}

func TestURLForOrigin(t *testing.T) {
	u, err := UrlForOrigin("127.0.0.1:8893")
	require.NoError(t, err)
	assert.Equal(t, "http://127.0.0.1:8893", u)

	_, err = UrlForOrigin("notaport")
	require.Error(t, err)
}

func TestBareHostname(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"mcp.example.com", "mcp.example.com"},
		{"https://mcp.example.com", "mcp.example.com"},
		{"HTTP://mcp.example.com", "mcp.example.com"},
		{"http://mcp.example.com/", "mcp.example.com"},
		{"https://mcp.example.com/path#frag", "mcp.example.com"},
		{"  https://mcp.example.com  ", "mcp.example.com"},
		{"", ""},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.want, BareHostname(tc.in), "BareHostname(%q)", tc.in)
	}
}

// baseTunnel is a minimal Tunnel built on tunnelBase, used to pin the
// URL-not-ready sentinel and the ready-state bookkeeping without involving a
// real provider.
type baseTunnel struct {
	tunnelBase
}

func (b *baseTunnel) Name() string { return "base" }

func (b *baseTunnel) URL() (string, error) {
	ready, url := b.getState()
	if !ready {
		return "", errUnavailable
	}
	return url, nil
}

func (b *baseTunnel) Start(_ context.Context, _ string) error {
	b.setReady("https://t.example")
	return nil
}

func (b *baseTunnel) Stop(_ context.Context) error               { return nil }
func (b *baseTunnel) SupportsCustomDomain() bool                 { return false }
func (b *baseTunnel) RequiresToken() bool                        { return false }
func (b *baseTunnel) MissingTokenError() error                    { return missingTokenError("base") }
func (b *baseTunnel) OAuthBaseURL(explicit, tunneled string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	return tunneled, nil
}

// TestURLNotReadySentinel pins the contract that URL before a successful Start
// returns the ErrNotReady sentinel (not a bespoke error), so callers can
// errors.Is against it.
func TestURLNotReadySentinel(t *testing.T) {
	var tb baseTunnel

	url, err := tb.URL()
	require.Error(t, err)
	assert.Equal(t, "", url)
	assert.True(t, errors.Is(err, ErrNotReady), "URL before Start must return the ErrNotReady sentinel")

	missing := tb.MissingTokenError()
	require.Error(t, missing)
	assert.Contains(t, missing.Error(), "base tunnel requires an account token")

	// After Start records the public URL, the sentinel goes away.
	require.NoError(t, tb.Start(context.Background(), "127.0.0.1:8893"))
	url, err = tb.URL()
	require.NoError(t, err)
	assert.Equal(t, "https://t.example", url)
	assert.True(t, errors.Is(err, nil) || err == nil)
}
