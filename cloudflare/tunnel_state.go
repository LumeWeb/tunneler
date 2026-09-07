// Package cloudflare re-homes the cloudflared tunnel provider: an in-process
// embedded cloudflared named-tunnel runtime, the provisioned tunnel state
// (persisted, tunnel-scoped credentials), and the readiness bookkeeping.
//
// This package imports the cloudflared SDK (github.com/cloudflare/cloudflared)
// and github.com/google/uuid; the core go.lumeweb.com/tunneler package stays
// provider-SDK-free.
package cloudflare

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"go.lumeweb.com/tunneler"
)

// tunnelStateFileName is the JSON file a tunnel installer / service install
// wizard persists a provisioned tunnel to. The embedded cloudflared runtime
// reads it at Start time to build the in-process named tunnel's credentials.
const tunnelStateFileName = "tunnel-state.json"

// CloudflareTunnelState is the persisted, tunnel-scoped credential set for a
// provisioned Cloudflare named tunnel. It is exactly what a cloudflared
// "credentials file" needs (AccountTag/TunnelID/TunnelSecret) plus the public
// hostname and the scoped run token. It is the "scoped api key for the tunnel
// itself": holding it authorizes running exactly this one tunnel.
type CloudflareTunnelState struct {
	Provider   tunneler.TunnelProvider `json:"provider"`
	AccountID  string                  `json:"account_id"` // credentials AccountTag
	TunnelID   string                  `json:"tunnel_id"`
	TunnelName string                  `json:"tunnel_name"`
	// Secret and Token are credentials (the tunnel credentials secret and the
	// scoped run token). They are populated ONLY at runtime from the Cloudflare
	// API response / tunnel provisioning, never from source and never from
	// literals. Code paths that construct a state must not hard-code these
	// values; tests must likewise use fixtures that are clearly not real
	// credentials.
	Secret   string `json:"secret"`
	Token    string `json:"token"`
	Hostname string `json:"hostname"`
	// ZoneID and DNSRecordID capture the proxied DNS route created for the
	// hostname so a later failure (e.g. an env-file write) can roll the route
	// back alongside the tunnel instead of orphaning the CNAME.
	ZoneID      string `json:"zone_id"`
	DNSRecordID string `json:"dns_record_id"`
}

// TunnelStatePath returns the per-user path to the tunnel state file, under
// the per-user config directory. It is a package variable so the embedding
// application can redirect it (e.g. to its own config dir) and tests can point
// it at a temp dir.
var TunnelStatePath = func() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve user config directory: %w", err)
	}
	return filepath.Join(dir, "tunneler", tunnelStateFileName), nil
}

// LoadCloudflareTunnelState loads the provisioned tunnel state, returning
// os.ErrNotExist if none has been provisioned.
func LoadCloudflareTunnelState() (*CloudflareTunnelState, error) {
	path, err := TunnelStatePath()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseTunnelState(b)
}

// parseTunnelState unmarshals a tunnel state document, yielding a clear error
// on malformed input.
func parseTunnelState(b []byte) (*CloudflareTunnelState, error) {
	var s CloudflareTunnelState
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("parse tunnel state: %w", err)
	}
	return &s, nil
}

// SaveCloudflareTunnelState persists the tunnel state as a private (0600)
// file. The secret/token are first-class secrets and must not be world-readable.
func SaveCloudflareTunnelState(s *CloudflareTunnelState) error {
	if s == nil {
		return fmt.Errorf("nil tunnel state")
	}
	path, err := TunnelStatePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create tunneler config dir: %w", err)
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return fmt.Errorf("write tunnel state %q: %w", path, err)
	}
	return nil
}
