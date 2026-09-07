package tunneler

import "strings"

// TunnelCredentialStore is the last-resort store for tunnel credentials,
// resolved after the cheaper sources (explicit flag/env, provider config
// file) have been exhausted. The method set mirrors common application config
// managers, so such a manager satisfies the interface structurally without an
// adapter.
//
// provider is the backend identifier (see TunnelProvider) and key is a
// logical credential name (e.g. "token" for the ngrok authtoken).
type TunnelCredentialStore interface {
	// TunnelCredential returns the stored credential for the given provider
	// and logical key, or "" when none is stored.
	TunnelCredential(provider, key string) string
	// SetTunnelCredential persists a credential for the given provider and
	// logical key.
	SetTunnelCredential(provider, key, value string) error
}

// ResolveCredential returns the first non-empty value produced by the given
// source providers, applied in order. Each provider is a thunk so a caller can
// model an ordered detection chain (flag -> env -> provider config file ->
// credential store) without evaluating sources that are more costly or more
// privileged than needed. It mirrors the precedence used by the provider SDKs
// and keeps a single definition of "what is the value" across runtime,
// installers, and service install.
//
// A provider returning a non-empty string stops the chain; the value is
// returned already trimmed.
func ResolveCredential(providers ...func() string) string {
	for _, p := range providers {
		if p == nil {
			continue
		}
		if v := strings.TrimSpace(p()); v != "" {
			return v
		}
	}
	return ""
}
