package subdomain_harvest

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
)

// fakeFeeder records how many requests were fed and to which hosts.
type fakeFeeder struct{ hosts []string }

func (f *fakeFeeder) Feed(rr *httpmsg.HttpRequestResponse) bool {
	if rr != nil && rr.Service() != nil {
		f.hosts = append(f.hosts, rr.Service().Host())
	}
	return true
}

// fakeExpander records the exact hosts added to scope.
type fakeExpander struct{ allowed []string }

func (e *fakeExpander) AllowHost(host string) { e.allowed = append(e.allowed, host) }

func TestFollowSubdomains_FeedsAndExpandsExactHosts(t *testing.T) {
	t.Parallel()
	m := New()
	feeder := &fakeFeeder{}
	expander := &fakeExpander{}
	sc := &modkit.ScanContext{
		RequestFeeder:    feeder,
		ScopeExpander:    expander,
		FollowSubdomains: true,
	}
	ctx := makeHTTPCtx("app.example.com", "/main.js", "application/javascript", appBundle)

	results, err := m.ScanPerRequest(ctx, sc)
	require.NoError(t, err)
	require.Len(t, results, 1)

	found := results[0].ExtractedResults
	// Every discovered subdomain — and ONLY those — is added to scope and fed.
	assert.ElementsMatch(t, found, expander.allowed)
	assert.ElementsMatch(t, found, feeder.hosts)
	// No apex wildcard: each allowed host is a concrete example.com subdomain.
	for _, h := range expander.allowed {
		assert.True(t, strings.HasSuffix(h, ".example.com"), "unexpected allowed host %q", h)
	}
	assert.Contains(t, results[0].Info.Description, "queued for scanning")
}

func TestFollowSubdomains_ReconOnlyByDefault(t *testing.T) {
	t.Parallel()
	m := New()
	feeder := &fakeFeeder{}
	expander := &fakeExpander{}
	// FollowSubdomains defaults to false: emit findings but never feed/expand.
	sc := &modkit.ScanContext{RequestFeeder: feeder, ScopeExpander: expander}
	ctx := makeHTTPCtx("app.example.com", "/main.js", "application/javascript", appBundle)

	results, err := m.ScanPerRequest(ctx, sc)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.NotEmpty(t, results[0].ExtractedResults)
	assert.Empty(t, expander.allowed)
	assert.Empty(t, feeder.hosts)
	assert.NotContains(t, results[0].Info.Description, "queued for scanning")
}

// TestFollowSubdomains_NoExpanderStaysReconOnly verifies the guard: with the
// toggle on but no ScopeExpander wired, the module must not feed (it would add
// hosts to scope that never become scannable).
func TestFollowSubdomains_NoExpanderStaysReconOnly(t *testing.T) {
	t.Parallel()
	m := New()
	feeder := &fakeFeeder{}
	sc := &modkit.ScanContext{RequestFeeder: feeder, FollowSubdomains: true} // no ScopeExpander
	ctx := makeHTTPCtx("app.example.com", "/main.js", "application/javascript", appBundle)

	results, err := m.ScanPerRequest(ctx, sc)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Empty(t, feeder.hosts)
}
