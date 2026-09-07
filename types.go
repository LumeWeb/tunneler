package tunneler

// TunnelProvider identifies the tunnel backend used to expose a local server.
type TunnelProvider string

const (
	TunnelProviderNgrok       TunnelProvider = "ngrok"
	TunnelProviderCloudflared TunnelProvider = "cloudflared"
)

// TunnelConfig is the set of tunnel/account parameters shared by every tunnel
// provider. Not every provider uses every field; each provider's constructor
// reads only what it needs. Using one struct (instead of positional
// constructor args) keeps provider constructors DRY and lets installers and
// the runtime share a single configuration shape.
type TunnelConfig struct {
	// Domain is the custom hostname the tunnel exposes (ngrok custom domain,
	// cloudflared hostname). May be empty for provider-assigned subdomains.
	Domain string
	// Token is the provider account credential: an ngrok authtoken, or a
	// Cloudflare per-tunnel JWT. May be empty if authenticating out of band.
	Token string
	// Name is an arbitrary tunnel/connector identifier (cloudflared tunnel
	// resource name, ngrok agent name).
	Name string
	// TunnelID is the provider-side tunnel identifier (Cloudflare tunnel
	// UUID). Not used by all providers.
	TunnelID string
	// StatePath is an optional override for where provider credentials are
	// loaded from at Start time. Empty uses the default per-user path; set in
	// tests to point at a fixture.
	StatePath string
	// Store is the optional last-resort credential store (e.g. the embedding
	// application's config manager) consulted for tunnel credentials
	// (e.g. an ngrok authtoken persisted via SetTunnelCredential). A nil store
	// degrades to no store.
	Store TunnelCredentialStore
}
