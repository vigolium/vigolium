package discovery

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/deparos/spider"
)

// TestCollectValidatedLinks_SplitsByOrigin proves that links harvested from a
// single page but pointing at different sibling origins are grouped into
// separate batches, each carrying its OWN host as BaseURL. Previously all paths
// were flattened under the first link's host, so a path from admin.example.test
// could be replayed against api.example.test.
func TestCollectValidatedLinks_SplitsByOrigin(t *testing.T) {
	cfg := confirmTestConfig("http://example.test/", false)
	cfg.Target.ScopeMode = "subdomain" // admit sibling subdomains (eTLD+1 = example.test)
	engine, err := testEngineWithConfig(cfg)
	require.NoError(t, err)
	defer engine.Stop()

	batches := engine.collectValidatedLinks([]*spider.DiscoveredLink{
		mkLink(t, "http://api.example.test/users", spider.SourceHTMLAttribute),
		mkLink(t, "http://admin.example.test/panel", spider.SourceHTMLAttribute),
		mkLink(t, "http://api.example.test/orders", spider.SourceHTMLAttribute),
	}, 0)

	// Index batches by their BaseURL for assertion.
	byOrigin := map[string]*SpiderLinkBatch{}
	for _, b := range batches {
		byOrigin[string(b.BaseURL)] = b
	}

	require.Len(t, batches, 2, "one batch per origin")

	api := byOrigin["http://api.example.test"]
	require.NotNil(t, api, "api.example.test batch present")
	assert.ElementsMatch(t, []string{"/users", "/orders"}, bytesToStrings(api.Files),
		"api paths must stay bound to api host")

	admin := byOrigin["http://admin.example.test"]
	require.NotNil(t, admin, "admin.example.test batch present")
	assert.ElementsMatch(t, []string{"/panel"}, bytesToStrings(admin.Files),
		"admin path must stay bound to admin host, never replayed against api")
}

func bytesToStrings(bs [][]byte) []string {
	out := make([]string, len(bs))
	for i, b := range bs {
		out[i] = string(b)
	}
	return out
}
