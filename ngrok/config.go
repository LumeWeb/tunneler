package ngrok

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"

	"go.lumeweb.com/tunneler"
)

// HasConfig reports whether the ngrok provider has a config file that the
// provider (or its SDK) reads on startup to authenticate. We only probe for
// the file's existence — the provider performs the actual parsing — so this is
// the existence signal used to decide whether a token prompt is needed.
//
// It honors NGROK_CONFIG when set; otherwise it uses the per-OS default:
//
//	Windows: %LocalAppData%\ngrok\ngrok.yml   (NOT %AppData%\Roaming)
//	macOS:   ~/Library/Application Support/ngrok/ngrok.yml
//	Linux:   ~/.config/ngrok/ngrok.yml
//
// The Windows LOCALAPPDATA (not the os.UserConfigDir Roaming path) is what
// `ngrok config add-authtoken` actually writes, so it must be probed to match.
func HasConfig() bool {
	return ngrokConfigPath() != ""
}

// ngrokConfigPath returns the path to the ngrok config file, or "" when the
// file does not exist. It honors NGROK_CONFIG when set; otherwise it resolves
// the per-OS default path that `ngrok config add-authtoken` writes.
func ngrokConfigPath() string {
	path := os.Getenv("NGROK_CONFIG")
	if path != "" {
		if _, err := os.Stat(path); err != nil {
			return ""
		}
		return path
	}
	switch runtime.GOOS {
	case "windows":
		if base := os.Getenv("LOCALAPPDATA"); base != "" {
			p := filepath.Join(base, "ngrok", "ngrok.yml")
			if _, err := os.Stat(p); err != nil {
				return ""
			}
			return p
		}
		return ""
	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		p := filepath.Join(home, "Library", "Application Support", "ngrok", "ngrok.yml")
		if _, err := os.Stat(p); err != nil {
			return ""
		}
		return p
	default:
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		p := filepath.Join(home, ".config", "ngrok", "ngrok.yml")
		if _, err := os.Stat(p); err != nil {
			return ""
		}
		return p
	}
}

// ngrokAgentConfig mirrors the `agent:` block of the ngrok config file. Only
// the agent-level authtoken is consumed; nested sub-blocks (tunnels/endpoints)
// are opaque maps we never read into, so an `authtoken` under them is naturally
// excluded from being the agent's own credential.
type ngrokAgentConfig struct {
	Authtoken string         `yaml:"authtoken"`
	Tunnels   map[string]any `yaml:"tunnels"`
	Endpoints map[string]any `yaml:"endpoints"`
}

// ngrokConfigFile is the subset of the ngrok agent config file (as written by
// `ngrok config add-authtoken` and read by the ngrok SDK on startup) that
// needs to be understood here.
type ngrokConfigFile struct {
	Version string           `yaml:"version"`
	Region  string           `yaml:"region"`
	Agent   ngrokAgentConfig `yaml:"agent"`
	// Legacy top-level authtoken accepted for older configs.
	Authtoken string `yaml:"authtoken"`
}

// ConfigAuthtoken parses the ngrok config with a real YAML decoder and returns
// the usable agent authtoken value, or "" when none is present. The agent
// credential is `agent.authtoken` (the direct child of `agent`), with a
// top-level `authtoken` scalar accepted for legacy configs. An authtoken nested
// under a sub-block (e.g. agent.tunnels.<name>, agent.endpoints, log) is NOT
// the agent's credential: the yaml struct only reads the direct keys, so those
// are structurally excluded rather than by indentation heuristics. Install
// wizards use the value to pre-populate a service env file from an out-of-band
// `ngrok config add-authtoken`, so a configured ngrok is never re-prompted.
func ConfigAuthtoken() string {
	path := ngrokConfigPath()
	if path == "" {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var cfg ngrokConfigFile
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		// A malformed or partially-written config carries no usable credential.
		return ""
	}
	if v := strings.TrimSpace(cfg.Agent.Authtoken); v != "" {
		return v
	}
	return strings.TrimSpace(cfg.Authtoken)
}

// ConfigHasAuthtoken reports whether the ngrok config file actually declares an
// agent authtoken (the SDK loads it on startup). Unlike HasConfig, which only
// checks file existence, this inspects the file contents: an empty or
// partially-written config file carries no usable credential, so it must not
// suppress the last-resort credential store token and silently start the agent
// unauthenticated.
func ConfigHasAuthtoken() bool {
	return ConfigAuthtoken() != ""
}

// storeCredential returns a ResolveCredential source thunk that reads the
// last-resort tunnel credential for the given provider + logical key from the
// credential store. A nil store (common in tests and when the embedding app's
// config is unwired) degrades to an empty source so the chain continues.
func storeCredential(store tunneler.TunnelCredentialStore, provider, key string) func() string {
	return func() string {
		if store == nil {
			return ""
		}
		return store.TunnelCredential(provider, key)
	}
}

// ResolveNgrokToken resolves the ngrok authtoken for the runtime path with the
// precedence: explicit token argument and NGROK_AUTHTOKEN env, then the ngrok
// config file (~/.config/ngrok/ngrok.yml, as written by `ngrok config
// add-authtoken`), then the last-resort credential store.
//
// The embedded ngrok SDK does NOT read its own config file on startup, so a
// config-file authtoken must be surfaced here and passed to the agent via
// WithAuthtoken; relying on the SDK to load it leaves the session
// unauthenticated (ngrok ERR_NGROK_4018). Putting the config file before the
// credential store means a stale/revoked token persisted by an earlier
// installer run never overrides a valid config-file authtoken, while an
// empty/broken config file still falls back to the store instead of silently
// starting the agent unauthenticated.
func ResolveNgrokToken(token string, store tunneler.TunnelCredentialStore) string {
	explicit := tunneler.ResolveCredential(
		func() string { return token },
		func() string { return os.Getenv("NGROK_AUTHTOKEN") },
	)
	if explicit != "" {
		return explicit
	}
	if cfg := ConfigAuthtoken(); cfg != "" {
		return cfg
	}
	return storeCredential(store, "ngrok", "token")()
}
