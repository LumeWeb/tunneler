package tunneler

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"go.uber.org/zap"
)

// log is the package-level zap logger for the tunneler package. It is a
// settable variable so the embedding application's user-configured logger
// replaces the default, keeping tunnel debug output consistent with the rest
// of the application. The default production logger writes to stderr so it
// never corrupts a stdio transport when the library is embedded in an MCP or
// other stdio-driven server.
var log = zap.Must(zap.NewProduction())

// SetLogger installs a user-configured logger as the shared tunneler package
// logger.
func SetLogger(l *zap.Logger) {
	log = l
}

// Tunnel exposes a locally bound HTTP server to the public internet via a
// third-party tunnel provider (currently ngrok and Cloudflare). The embedding
// application runs and manages the tunnel process for the lifetime of its
// local server.
//
// All providers follow the same contract: Start launches the tunnel
// subprocess and blocks until the public URL is live (or returns an error).
// URL returns the public endpoint once Start has succeeded. Stop tears the
// tunnel down and reaps the subprocess.
type Tunnel interface {
	// Name returns the provider name used to select the tunnel (ngrok,
	// cloudflared).
	Name() string
	// URL returns the public endpoint once the tunnel is live. Calling it
	// before Start succeeds is an error.
	URL() (string, error)
	// Start launches the tunnel subprocess and waits until it accepts
	// traffic over the public URL, or returns an error if it cannot.
	Start(ctx context.Context, localAddr string) error
	// Stop terminates the tunnel and waits for the subprocess to exit.
	Stop(ctx context.Context) error
	// SupportsCustomDomain reports whether the provider can bind a custom
	// hostname (as opposed to only a provider-assigned subdomain).
	SupportsCustomDomain() bool
	// RequiresToken reports whether the provider needs an account token
	// (e.g. an ngrok authtoken) before it can start.
	RequiresToken() bool
	// MissingTokenError returns the provider-specific error to surface when
	// RequiresToken() is true. Each provider owns how it guides the operator to
	// obtain or provision the credential; the caller just returns it instead
	// of branching per provider.
	MissingTokenError() error
	// OAuthBaseURL returns the externally reachable base URL for OAuth discovery.
	OAuthBaseURL(explicitURL, tunnelURL string) (string, error)
}

// AccountChecker is implemented by tunnels whose provider account login can be
// verified before the tunnel is started. It lets the runtime fail fast with an
// actionable "not logged in" error instead of hanging inside Start when the
// credential is invalid (ngrok's session retries a bad authtoken until its
// connect deadline). Providers without a distinct pre-flight check simply do
// not implement it.
type AccountChecker interface {
	// CheckAccount verifies the provider account is usable (the credential
	// authenticates) without starting the tunnel. It returns a clear error when
	// the operator is not logged in or the credential is rejected.
	CheckAccount(ctx context.Context) error
}

// tunnelBase holds the shared bookkeeping for all tunnel providers.
type tunnelBase struct {
	mu        sync.Mutex
	publicURL string
	ready     bool
}

// setReady records the live public URL and unblocks Start waiters.
func (b *tunnelBase) setReady(publicURL string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.publicURL = publicURL
	b.ready = true
}

// getState returns the ready flag and the public URL.
func (b *tunnelBase) getState() (bool, string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.ready, b.publicURL
}

// errUnavailable is the sentinel returned by URL when the tunnel is not ready.
// It aliases the exported ErrNotReady so internal URL() implementations and
// external callers agree on a single sentinel.
var errUnavailable = ErrNotReady

// missingTokenError builds the generic "account token required" error for a
// provider, used by MissingTokenError implementations that have no additional
// provisioning step (e.g. ngrok): the operator provides the token via its
// application's flags/env, the provider's config file, or its installer.
func missingTokenError(name string) error {
	return fmt.Errorf("%s tunnel requires an account token: pass --token or set the provider token (see --help)", name)
}

// SplitHostPort splits a "host:port" address into its parts.
func SplitHostPort(addr string) (string, string, error) {
	if addr == "" {
		return "", "", fmt.Errorf("empty address")
	}
	parts := strings.Split(addr, ":")
	switch len(parts) {
	case 1:
		if _, err := strconv.Atoi(parts[0]); err != nil {
			return "", "", fmt.Errorf("invalid port %q: %w", parts[0], err)
		}
		return "127.0.0.1", parts[0], nil
	case 2:
		if _, err := strconv.Atoi(parts[1]); err != nil {
			return "", "", fmt.Errorf("invalid port %q: %w", parts[1], err)
		}
		return parts[0], parts[1], nil
	default:
		// IPv6 literal form [::1]:port
		port := parts[len(parts)-1]
		if _, err := strconv.Atoi(port); err != nil {
			return "", "", fmt.Errorf("invalid port %q: %w", port, err)
		}
		host := strings.TrimPrefix(strings.TrimSuffix(strings.Join(parts[:len(parts)-1], ":"), "]"), "[")
		return host, port, nil
	}
}
