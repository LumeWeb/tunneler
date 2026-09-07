package ngrok

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.lumeweb.com/tunneler"
)

// fakeStore is a minimal in-memory tunneler.TunnelCredentialStore standing in
// for the embedding application's config manager.
type fakeStore struct {
	creds map[string]string
	set   map[string]string
}

func newFakeStore(ngrokToken string) *fakeStore {
	s := &fakeStore{creds: map[string]string{}, set: map[string]string{}}
	if ngrokToken != "" {
		s.creds["ngrok/token"] = ngrokToken
	}
	return s
}

func (s *fakeStore) TunnelCredential(provider, key string) string {
	return s.creds[provider+"/"+key]
}

func (s *fakeStore) SetTunnelCredential(provider, key, value string) error {
	if s == nil {
		return errors.New("nil store")
	}
	s.set[provider+"/"+key] = value
	return nil
}

func TestHasConfig(t *testing.T) {
	t.Run("NGROK_CONFIG override", func(t *testing.T) {
		dir := t.TempDir()
		existing := filepath.Join(dir, "ngrok.yml")
		require.NoError(t, os.WriteFile(existing, []byte("agent:\n  authtoken: x\n"), 0o600))
		t.Setenv("NGROK_CONFIG", existing)
		assert.True(t, HasConfig())

		t.Setenv("NGROK_CONFIG", filepath.Join(dir, "missing.yml"))
		assert.False(t, HasConfig())
	})

	t.Run("default per-OS config paths", func(t *testing.T) {
		t.Setenv("NGROK_CONFIG", "")
		var base, cfg string
		if runtime.GOOS == "windows" {
			base = t.TempDir()
			t.Setenv("LOCALAPPDATA", base)
			cfg = filepath.Join(base, "ngrok", "ngrok.yml")
			t.Setenv("APPDATA", filepath.Join(base, "Roaming")) // must NOT be used
		} else {
			base = t.TempDir()
			t.Setenv("HOME", base)
			if runtime.GOOS == "darwin" {
				cfg = filepath.Join(base, "Library", "Application Support", "ngrok", "ngrok.yml")
			} else {
				cfg = filepath.Join(base, ".config", "ngrok", "ngrok.yml")
			}
		}

		// Absent -> false.
		assert.False(t, HasConfig())

		// Present at the default location -> true.
		require.NoError(t, os.MkdirAll(filepath.Dir(cfg), 0o700))
		require.NoError(t, os.WriteFile(cfg, []byte("agent:\n  authtoken: x\n"), 0o600))
		assert.True(t, HasConfig())
	})
}

func TestResolveNgrokToken(t *testing.T) {
	t.Setenv("NGROK_AUTHTOKEN", "")

	t.Run("explicit flag wins over store", func(t *testing.T) {
		t.Setenv("NGROK_CONFIG", filepath.Join(t.TempDir(), "missing.yml"))
		store := newFakeStore("storetok")
		assert.Equal(t, "flagtok", ResolveNgrokToken("flagtok", store))
	})

	t.Run("env wins over store", func(t *testing.T) {
		t.Setenv("NGROK_CONFIG", filepath.Join(t.TempDir(), "missing.yml"))
		t.Setenv("NGROK_AUTHTOKEN", "envtok")
		store := newFakeStore("storetok")
		assert.Equal(t, "envtok", ResolveNgrokToken("", store))
	})

	t.Run("store is last resort when no config file", func(t *testing.T) {
		t.Setenv("NGROK_CONFIG", filepath.Join(t.TempDir(), "missing.yml"))
		store := newFakeStore("storetok")
		assert.Equal(t, "storetok", ResolveNgrokToken("", store))
	})

	t.Run("config file authtoken wins over stale store token", func(t *testing.T) {
		// The embedded ngrok SDK does NOT load its own config file on startup,
		// so ResolveNgrokToken must return the config-file authtoken so the
		// caller can pass it to the agent via WithAuthtoken. It also takes
		// precedence over the last-resort store: a stale/revoked token must
		// never override a valid config-file authtoken.
		dir := t.TempDir()
		cfg := filepath.Join(dir, "ngrok.yml")
		require.NoError(t, os.WriteFile(cfg, []byte("version: 2\nagent:\n  authtoken: 2abcDEF\n"), 0o600))
		t.Setenv("NGROK_CONFIG", cfg)
		store := newFakeStore("staletok")
		assert.Equal(t, "2abcDEF", ResolveNgrokToken("", store))
	})

	t.Run("config file authtoken used without store", func(t *testing.T) {
		// Even with no store wired, a config file authtoken must be surfaced so
		// the runtime authenticates instead of erroring with 4018.
		dir := t.TempDir()
		cfg := filepath.Join(dir, "ngrok.yml")
		require.NoError(t, os.WriteFile(cfg, []byte("version: 2\nagent:\n  authtoken: cfgtok\n"), 0o600))
		t.Setenv("NGROK_CONFIG", cfg)
		assert.Equal(t, "cfgtok", ResolveNgrokToken("", nil))
	})

	t.Run("empty/broken config file does not suppress store token", func(t *testing.T) {
		// A config file that exists but carries no authtoken (empty or partially
		// written) provides no usable credential, so the store token must still
		// be used rather than silently starting unauthenticated.
		dir := t.TempDir()
		cfg := filepath.Join(dir, "ngrok.yml")
		require.NoError(t, os.WriteFile(cfg, []byte("version: 2\nagent:\n"), 0o600))
		t.Setenv("NGROK_CONFIG", cfg)
		store := newFakeStore("storetok")
		assert.Equal(t, "storetok", ResolveNgrokToken("", store))
	})

	t.Run("no credential source returns empty", func(t *testing.T) {
		t.Setenv("NGROK_CONFIG", filepath.Join(t.TempDir(), "missing.yml"))
		assert.Equal(t, "", ResolveNgrokToken("", nil))
	})
}

func TestConfigHasAuthtoken(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.yml")
	t.Setenv("NGROK_CONFIG", missing)
	assert.False(t, ConfigHasAuthtoken(), "missing file -> no authtoken")

	dir := t.TempDir()

	cfg := filepath.Join(dir, "with.yml")
	require.NoError(t, os.WriteFile(cfg, []byte("version: 2\nagent:\n  authtoken: 2abcDEF\n"), 0o600))
	t.Setenv("NGROK_CONFIG", cfg)
	assert.True(t, ConfigHasAuthtoken(), "authtoken under agent block detected")

	cfg = filepath.Join(dir, "empty.yml")
	require.NoError(t, os.WriteFile(cfg, []byte("version: 2\nagent:\n"), 0o600))
	t.Setenv("NGROK_CONFIG", cfg)
	assert.False(t, ConfigHasAuthtoken(), "file without authtoken value -> false")

	cfg = filepath.Join(dir, "blank.yml")
	require.NoError(t, os.WriteFile(cfg, []byte(""), 0o600))
	t.Setenv("NGROK_CONFIG", cfg)
	assert.False(t, ConfigHasAuthtoken(), "empty file -> false")

	// An authtoken nested under a non-agent block (tunnels/endpoints/log) is
	// NOT a usable agent credential and must be ignored.
	cfg = filepath.Join(dir, "nested.yml")
	require.NoError(t, os.WriteFile(cfg, []byte(
		"version: 2\nlog:\n  level: debug\ntunnels:\n  test:\n    authtoken: 3xYz\n"), 0o600))
	t.Setenv("NGROK_CONFIG", cfg)
	assert.False(t, ConfigHasAuthtoken(), "authtoken under non-agent block must not be treated as agent credential")

	// An authtoken nested under a SUB-block of agent (agent.tunnels.<name>,
	// agent.endpoints) is not agent.authtoken and must be ignored, even though
	// it sits inside the agent: block.
	cfg = filepath.Join(dir, "agent-nested.yml")
	require.NoError(t, os.WriteFile(cfg, []byte(
		"version: 2\nagent:\n  tunnels:\n    web:\n      authtoken: 5xYz\n  authtoken: 6aBcD\n"), 0o600))
	t.Setenv("NGROK_CONFIG", cfg)
	assert.True(t, ConfigHasAuthtoken(), "real agent.authtoken after a nested agent sub-block is still detected")

	cfg = filepath.Join(dir, "agent-nested-only.yml")
	require.NoError(t, os.WriteFile(cfg, []byte(
		"version: 2\nagent:\n  tunnels:\n    web:\n      authtoken: 5xYz\n"), 0o600))
	t.Setenv("NGROK_CONFIG", cfg)
	assert.False(t, ConfigHasAuthtoken(), "authtoken nested under agent sub-block must not count as agent credential")

	// A top-level authtoken (no agent: block) is a usable credential.
	cfg = filepath.Join(dir, "top.yml")
	require.NoError(t, os.WriteFile(cfg, []byte("authtoken: 4abc\n"), 0o600))
	t.Setenv("NGROK_CONFIG", cfg)
	assert.True(t, ConfigHasAuthtoken(), "top-level authtoken detected")

	// An explicitly empty authtoken (`authtoken: ""`) carries no credential and
	// must be treated as absent so the store fallback is not dropped.
	cfg = filepath.Join(dir, "emptyval.yml")
	require.NoError(t, os.WriteFile(cfg, []byte("version: 2\nagent:\n  authtoken: \"\"\n"), 0o600))
	t.Setenv("NGROK_CONFIG", cfg)
	assert.False(t, ConfigHasAuthtoken(), "explicitly empty quoted authtoken -> false")
}

func TestConfigAuthtoken(t *testing.T) {
	t.Setenv("NGROK_CONFIG", filepath.Join(t.TempDir(), "missing.yml"))
	assert.Equal(t, "", ConfigAuthtoken(), "missing file -> empty value")

	dir := t.TempDir()
	cfg := filepath.Join(dir, "with.yml")
	require.NoError(t, os.WriteFile(cfg, []byte(
		"version: 2\nagent:\n  authtoken: 2abcDEF_tok\n"), 0o600))
	t.Setenv("NGROK_CONFIG", cfg)
	assert.Equal(t, "2abcDEF_tok", ConfigAuthtoken(), "agent.authtoken value extracted")

	cfg = filepath.Join(dir, "top.yml")
	require.NoError(t, os.WriteFile(cfg, []byte("authtoken: 4abcQuoted\n"), 0o600))
	t.Setenv("NGROK_CONFIG", cfg)
	assert.Equal(t, "4abcQuoted", ConfigAuthtoken(), "top-level authtoken value extracted")

	// A quoted value is stripped to its raw token.
	cfg = filepath.Join(dir, "quoted.yml")
	require.NoError(t, os.WriteFile(cfg, []byte("agent:\n  authtoken: \"5xYz\"\n"), 0o600))
	t.Setenv("NGROK_CONFIG", cfg)
	assert.Equal(t, "5xYz", ConfigAuthtoken(), "quoted authtoken value unquoted")

	// Nested under an agent sub-block (agent.tunnels.<name>) is not an agent
	// credential and yields no value.
	cfg = filepath.Join(dir, "agent-nested-only.yml")
	require.NoError(t, os.WriteFile(cfg, []byte(
		"version: 2\nagent:\n  tunnels:\n    web:\n      authtoken: 5xYz\n"), 0o600))
	t.Setenv("NGROK_CONFIG", cfg)
	assert.Equal(t, "", ConfigAuthtoken(), "authtoken under agent sub-block -> empty value")

	// Real agent.authtoken after a nested sub-block is still extracted.
	cfg = filepath.Join(dir, "agent-nested.yml")
	require.NoError(t, os.WriteFile(cfg, []byte(
		"version: 2\nagent:\n  tunnels:\n    web:\n      authtoken: 5xYz\n  authtoken: 6aBcD\n"), 0o600))
	t.Setenv("NGROK_CONFIG", cfg)
	assert.Equal(t, "6aBcD", ConfigAuthtoken(), "real agent.authtoken value extracted after nested sub-block")

	// An explicitly empty quoted authtoken carries no value.
	cfg = filepath.Join(dir, "emptyval.yml")
	require.NoError(t, os.WriteFile(cfg, []byte("version: 2\nagent:\n  authtoken: \"\"\n"), 0o600))
	t.Setenv("NGROK_CONFIG", cfg)
	assert.Equal(t, "", ConfigAuthtoken(), "explicitly empty quoted authtoken -> empty value")
}

func TestStoreCredential(t *testing.T) {
	store := newFakeStore("storetok")
	assert.Equal(t, "storetok", storeCredential(store, "ngrok", "token")())
	// A nil store (nil interface) degrades to an empty source.
	var nilStore tunneler.TunnelCredentialStore
	assert.Equal(t, "", storeCredential(nilStore, "ngrok", "token")())
}
