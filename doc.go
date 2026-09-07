// Package tunneler exposes a locally bound HTTP endpoint through a public
// tunnel provider (currently ngrok and Cloudflare), with a provider-neutral
// core and per-provider subpackages that own their SDKs.
//
// The core package defines the Tunnel contract and the shared bookkeeping all
// providers rely on:
//
//	t, err := cloudflare.NewCloudflaredTunnel(tunneler.TunnelConfig{...})
//	if err != nil { ... }
//	if err := t.Start(ctx, "127.0.0.1:8893"); err != nil { ... }
//	url, err := t.URL()
//	defer t.Stop(ctx)
//
// Providers live in the ngrok and cloudflare subpackages:
//
//	t := ngrok.NewNgrokTunnel("mcp.example.com", "")
//	t, err := cloudflare.NewCloudflaredTunnel(tunneler.TunnelConfig{
//		StatePath: "/path/to/tunnel-state.json",
//	})
//
// Dependency rule: this core package imports only the standard library and
// go.uber.org/zap. Every provider SDK is owned by its own subpackage
// (ngrok/ngrok, cloudflare/cloudflare), so consumers that need only one
// provider do not link the others.
//
// The package is intentionally agnostic: it does not own configuration
// persistence, CLI flags, terminal output, browser/URL opening, managed OS
// service installation, or MCP server types. Implementations that need a
// persistent last-resort credential store implement TunnelCredentialStore
// (e.g. an application config manager) and hand it to the provider.
package tunneler
