# tunneler

`go.lumeweb.com/tunneler` is a standalone Go library that exposes a locally
bound HTTP endpoint through a public tunnel provider. It is a multi-module
repository (one repo, many Go modules): a provider-neutral core module at the
root, and one self-contained module per tunnel provider.

Each provider module owns its own SDK — importing the core module pulls in
neither the ngrok SDK nor cloudflared.

## Module layout

| Module | Path | Description |
| --- | --- | --- |
| `go.lumeweb.com/tunneler` | `.` | Provider-neutral core |
| `go.lumeweb.com/tunneler/ngrok` | `ngrok/` | ngrok tunnel provider |
| `go.lumeweb.com/tunneler/cloudflare` | `cloudflare/` | Cloudflare (cloudflared) tunnel provider |

## Install

```bash
# core only — no provider SDKs
go get go.lumeweb.com/tunneler

# ngrok provider (adds the ngrok Go SDK)
go get go.lumeweb.com/tunneler/ngrok

# Cloudflare provider (adds cloudflared)
go get go.lumeweb.com/tunneler/cloudflare
```

## Core module

The root `tunneler` package is deliberately minimal (stdlib + zap): it defines
the provider-neutral pieces every consumer and provider shares.

- `Tunnel` — the tunnel contract (`Name`, `URL`, `Start`, `Stop`, ...)
- `AccountChecker` — optional fail-fast account pre-flight
- `TunnelConfig` / `TunnelProvider` — shared configuration shape and provider
  identifiers
- `TunnelCredentialStore` — last-resort credential store interface
- `ResolveCredential` — ordered credential-source resolution
- `SplitHostPort`, `LocalURL`, `UrlForOrigin`, `BareHostname` — address and
  hostname helpers
- `SetLogger` / `ErrNotReady` — logging and the not-ready sentinel

See `doc.go` for the package overview.

## ngrok module

`go.lumeweb.com/tunneler/ngrok` owns the ngrok Go SDK. It runs an in-process
tunnel through the embedded ngrok SDK (free tier dev domains and paid custom
domains), plus ngrok REST account probes and ngrok config-file authtoken
detection. Entry point: `ngrok.NewNgrokTunnel` / `ngrok.NewNgrokTunnelWithStore`.

## cloudflare module

`go.lumeweb.com/tunneler/cloudflare` owns the cloudflared SDK. It runs an
in-process, embedded Cloudflare named tunnel, driven by persisted
tunnel-scoped credentials. Entry point: `cloudflare.NewCloudflaredTunnel`,
with tunnel state managed via `LoadCloudflareTunnelState` /
`SaveCloudflareTunnelState`.

## Development

Because `./...` stops at module boundaries, build and test each module
separately:

```bash
go build ./... && go test -race ./...        # core (root)
cd ngrok && go build ./... && go test -race ./...
cd cloudflare && go build ./... && go test -race ./...
mockery   # regenerate core mocks (pre-installed at $HOME/go/bin/mockery)
```

Cross-module local development uses a gitignored `go.work` workspace: `go
work init . ./ngrok ./cloudflare` from the repo root resolves the core to
your working copy. The `require go.lumeweb.com/tunneler` line in each
provider `go.mod` stays as the declared dependency for external consumers.

## License

MIT — see [LICENSE](LICENSE).
