package runner

import (
	"testing"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/spitolas"
	"github.com/vigolium/vigolium/pkg/types"
)

// SAFE-11: third-party lookups are off by default, on only with
// dynamic_assessment.external_lookups, and never under --offline, which also
// turns OAST off.
func TestExternalFetcherAndOffline(t *testing.T) {
	settings := config.DefaultSettings()
	r := &Runner{options: types.DefaultOptions(), settings: settings}
	if r.externalFetcher() != nil {
		t.Error("external lookups must be off by default")
	}
	settings.DynamicAssessment.ExternalLookups = true
	if r.externalFetcher() == nil {
		t.Error("external_lookups: true must yield a fetcher")
	}
	settings.OAST.Enabled = true
	r.options.Offline = true
	defer spitolas.SetOffline(false)
	r.applyOffline()
	if r.externalFetcher() != nil {
		t.Error("--offline must disable external lookups")
	}
	if settings.OAST.Enabled {
		t.Error("--offline must disable OAST")
	}
	if config.DefaultSettings().OAST.FallbackToDefault {
		t.Error("oast.fallback_to_default must default to false")
	}
}
