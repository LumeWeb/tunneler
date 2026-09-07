package cloudflare

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/cloudflare/cloudflared/ingress"
	"github.com/cloudflare/cloudflared/logger"
	"github.com/cloudflare/cloudflared/orchestration"
	"github.com/cloudflare/cloudflared/tunnelrpc/pogs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.lumeweb.com/tunneler"
)

// fixtureTunnelState returns a CloudflareTunnelState populated with clearly
// fixture (non-real) values so the embedded wiring can be unit-tested without
// any Cloudflare account or network access. All credential strings are
// obviously synthetic.
func fixtureTunnelState() *CloudflareTunnelState {
	return &CloudflareTunnelState{
		Provider:   tunneler.TunnelProviderCloudflared,
		AccountID:  "acct-0123456789abcdef0123456789abcdef",
		TunnelID:   "01234567-89ab-4def-8123-456789abcdef",
		TunnelName: "tunneler-fixture",
		Secret:     "c2VjcmV0LWZpY3Rpb24tbm90LXJlYWw=", // base64 of a fixture string
		Token:      "tkn-fixture",
		Hostname:   "mcp.example.com",
	}
}

func TestBuildCloudflaredTunnelPropertiesNamed(t *testing.T) {
	props, err := buildCloudflaredTunnelProperties(fixtureTunnelState())
	require.NoError(t, err)

	// A named tunnel, not a quick tunnel: QuickTunnelUrl must stay empty and
	// the credential fields must map from the persisted state. state.Secret is
	// stored base64 and must be DECODED to the raw bytes cloudflared uses for
	// the edge-registration HMAC.
	state := fixtureTunnelState()
	rawSecret, _ := base64.StdEncoding.DecodeString(state.Secret)
	assert.Empty(t, props.QuickTunnelUrl)
	assert.Equal(t, state.AccountID, props.Credentials.AccountTag)
	assert.Equal(t, state.TunnelID, props.Credentials.TunnelID.String())
	assert.Equal(t, rawSecret, props.Credentials.TunnelSecret)
	assert.Empty(t, props.Credentials.Endpoint)
}

func TestBuildCloudflaredTunnelPropertiesInvalidTunnelID(t *testing.T) {
	state := fixtureTunnelState()
	state.TunnelID = "not-a-uuid"
	_, err := buildCloudflaredTunnelProperties(state)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a valid UUID")
}

func TestBuildCloudflaredTunnelPropertiesInvalidSecret(t *testing.T) {
	state := fixtureTunnelState()
	state.Secret = "!!!not-base64!!!"
	_, err := buildCloudflaredTunnelProperties(state)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not valid base64")
}

func TestBuildCloudflaredTunnelPropertiesMissingTunnelID(t *testing.T) {
	state := fixtureTunnelState()
	state.TunnelID = ""
	_, err := buildCloudflaredTunnelProperties(state)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing tunnel id")
}

func TestBuildCloudflaredTunnelPropertiesMissingAccountID(t *testing.T) {
	state := fixtureTunnelState()
	state.AccountID = ""
	_, err := buildCloudflaredTunnelProperties(state)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing account id")
}

func TestBuildCloudflaredTunnelPropertiesNilState(t *testing.T) {
	_, err := buildCloudflaredTunnelProperties(nil)
	require.Error(t, err)
}

func TestBuildOrchestrationConfigSetsOriginDialerService(t *testing.T) {
	// Regression: the embedded daemon used to build an orchestration.Config
	// without OriginDialerService. cloudflared's updateIngress — invoked by
	// orchestration.NewOrchestrator itself — calls
	// OriginDialerService.UpdateDefaultDialer, which dereferences the (nil)
	// receiver, so a real Start() of the embedded tunnel panicked before any
	// connection attempt. The real constructor path must produce a non-nil
	// origin dialer service.
	ing, err := buildCloudflaredIngress("mcp.example.com", "http://127.0.0.1:8893")
	require.NoError(t, err)

	log := logger.Create(logger.CreateConfig("", true, false, "", ""))
	cfg := buildOrchestrationConfig(ing, 0, log)
	require.NotNil(t, cfg.OriginDialerService)

	// Exercise the REAL orchestrator construction exactly as the embedded
	// daemon does. Against pre-fix code this panicked inside updateIngress
	// when UpdateDefaultDialer was called on a nil service.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NotPanics(t, func() {
		orchestrator, orcErr := orchestration.NewOrchestrator(ctx, cfg, []pogs.Tag{}, []ingress.Rule{}, log)
		require.NoError(t, orcErr)
		require.NotNil(t, orchestrator)
	})
}

func TestBuildCloudflaredIngress(t *testing.T) {
	// The provisioned hostname must route to the local origin, with a 404
	// catch-all as the terminal rule.
	ing, err := buildCloudflaredIngress("mcp.example.com", "http://127.0.0.1:8893")
	require.NoError(t, err)

	rules := ing.Rules
	require.GreaterOrEqual(t, len(rules), 2)
	assert.Equal(t, "mcp.example.com", rules[0].Hostname)
	assert.Equal(t, "http://127.0.0.1:8893", rules[0].Service.String())

	// The specific hostname rule must match the provisioned hostname.
	assert.True(t, rules[0].Matches("mcp.example.com", ""))

	// The last rule is the terminal catch-all (empty hostname, http_status).
	last := rules[len(rules)-1]
	assert.Empty(t, last.Hostname)
	assert.Equal(t, "http_status:404", last.Service.String())
	assert.True(t, last.Matches("any.other.example", ""))
}
