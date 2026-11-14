package salesforce_lightning_debug_mode

import (
	"fmt"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	sf "github.com/vigolium/vigolium/pkg/modules/infra/salesforce"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// confirmRounds is the number of additional independent mode observations (on top
// of the first) that must all agree on the same debug mode before reporting.
const confirmRounds = 2

// debugModes are the Aura modes that ship un-minified JS and serve verbose error
// responses containing backend stacktraces / code extracts to the client — the
// exposure this module reports. PROD and STATS are production-safe. This is the
// module's finding policy (which modes matter), kept out of the shared parser.
var debugModes = map[string]struct{}{
	"PRODDEBUG":   {},
	"DEV":         {},
	"JSTESTDEBUG": {},
}

func isDebugMode(mode string) bool {
	_, ok := debugModes[mode]
	return ok
}

type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

func New() *Module {
	m := &Module{
		BaseActiveModule: modkit.NewBaseActiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeHost,
			modkit.AllInsertionPointTypes,
		),
		ds: dedup.LazyDiskSet("salesforce_lightning_debug_mode"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) IncludesBaseCanProcess() bool { return false }

func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	return ctx != nil && ctx.Request() != nil
}

func (m *Module) ScanPerHost(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}
	host := urlx.Host

	if !modkit.BeginHostProbeKey(scanCtx, httpClient, &m.ds, host) {
		return nil, nil
	}

	// Tech gate: a live Aura gateway proves this is a Salesforce Lightning host (a
	// non-Salesforce host answers none of the gateway paths with a framework error).
	// PrepareGateway marks the tech registry on presence, independent of any finding.
	endpoint, ok := sf.PrepareGateway(ctx, httpClient, scanCtx)
	if !ok {
		return nil, nil
	}

	// Read the Aura bootstrap mode across independent, cache-bypassed rounds. Every
	// round must find a mode AND every round must agree on the same debug mode; a
	// PROD/STATS mode, a disagreement, or a round with no mode marker all mean no
	// finding.
	var mode string
	for range confirmRounds + 1 {
		observed, ok := sf.HarvestAuraMode(ctx, httpClient)
		if !ok || !isDebugMode(observed) {
			return nil, nil
		}
		if mode == "" {
			mode = observed
		} else if mode != observed {
			return nil, nil
		}
	}

	matchedURL := urlx.Scheme + "://" + urlx.Host + endpoint
	return []*output.ResultEvent{m.build(host, matchedURL, endpoint, mode)}, nil
}

func (m *Module) build(host, matchedURL, endpoint, mode string) *output.ResultEvent {
	evidence := []string{
		"aura gateway: " + endpoint,
		"aura bootstrap mode: " + mode,
		fmt.Sprintf("mode confirmed across %d independent rounds", confirmRounds+1),
	}

	desc := fmt.Sprintf(
		"The Salesforce Lightning site is served in the Aura %q mode instead of production (PROD). In this mode the Aura framework ships un-minified "+
			"JavaScript and returns verbose error responses containing backend stacktraces and code extracts to unauthenticated clients — an "+
			"information-disclosure misconfiguration that aids reconnaissance of the org (locating guest-reachable Apex, class/method names, code paths). "+
			"The mode was read from the Aura bootstrap and confirmed identical across %d independent, cache-bypassed rounds.",
		mode, confirmRounds+1,
	)

	return &output.ResultEvent{
		ModuleID:         ModuleID,
		Host:             host,
		URL:              matchedURL,
		Matched:          matchedURL,
		MatcherStatus:    true,
		ExtractedResults: evidence,
		Info: output.Info{
			Name:        "Salesforce Lightning Debug Mode Enabled",
			Description: desc,
			Severity:    severity.Medium,
			Confidence:  severity.Firm,
			Tags:        ModuleTags,
			Reference:   moduleReferences,
		},
		Metadata: map[string]any{"platform": "salesforce", "aura_mode": mode},
	}
}
