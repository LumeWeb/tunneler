# AGENTS.md

## Common Commands

Every directory below is its own Go module — `./...` stops at module
boundaries, so build/test in the root module AND in each provider module:

```bash
# core module (root)
go build ./...
go test -v -race -coverprofile=coverage.out -covermode=atomic ./...

# ngrok module
cd ngrok && go build ./... && go test -v -race ./...

# cloudflare module
cd cloudflare && go build ./... && go test -v -race ./...

mockery   # regenerate core mocks; run with no args, never reinstall it
```

## Layout

Three Go modules share one repository (koanf-style multi-module monorepo):

- **`go.lumeweb.com/tunneler`** (root, `/`): the provider-neutral core —
  interfaces (`Tunnel`, `AccountChecker`, `TunnelCredentialStore`), shared
  types (`TunnelConfig`, `TunnelProvider`), and helpers (`ResolveCredential`,
  address helpers); `doc.go` holds the package documentation. Depends on
  stdlib + zap only — no provider SDKs.
- **`go.lumeweb.com/tunneler/ngrok`** (`ngrok/`, own `go.mod`): the ngrok
  provider (embedded SDK tunnel, REST account probes, ngrok config-file
  authtoken detection). Owns the ngrok SDK dependency; the core is declared
  with `require go.lumeweb.com/tunneler` in its `go.mod` (for local dev, the
  gitignored `go.work` workspace resolves the core to your working copy).
- **`go.lumeweb.com/tunneler/cloudflare`** (`cloudflare/`, own `go.mod`): the
  cloudflared provider (in-process embedded cloudflared named-tunnel runtime,
  provisioned tunnel state load/save). Owns the cloudflared SDK dependency;
  the core is declared with `require go.lumeweb.com/tunneler` in its `go.mod`
  (for local dev, the gitignored `go.work` workspace resolves the core to
  your working copy).
