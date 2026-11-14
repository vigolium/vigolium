package salesforce_aura_record_exposure

import (
	"fmt"
	"sort"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	sf "github.com/vigolium/vigolium/pkg/modules/infra/salesforce"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// confirmRounds is the number of additional independent getItems observations
// (on top of the initial detection) required before an object is reported.
const confirmRounds = 2

const probePageSize = 100

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
		ds: dedup.LazyDiskSet("salesforce_aura_record_exposure"),
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

	// Tech gate: locating a live Aura gateway + context IS the fail-closed presence
	// check (a non-Salesforce host has no gateway).
	endpoint, auraContext, ok := sf.Prepare(ctx, httpClient, scanCtx)
	if !ok {
		return nil, nil
	}

	// Catch-all negative control: getItems for an object that cannot exist must
	// NOT return records. If it does, the endpoint returns data for anything, so
	// any positive would be a false positive — skip the host entirely.
	if page, _, ok := m.readRecords(ctx, httpClient, endpoint, auraContext, bogusObject); ok && page > 0 {
		return nil, nil
	}

	targets := m.enumerationTargets(ctx, httpClient, endpoint, auraContext)

	baseURL := urlx.Scheme + "://" + urlx.Host + endpoint
	var results []*output.ResultEvent
	for _, obj := range targets {
		if res := m.probeObject(ctx, httpClient, endpoint, auraContext, obj, baseURL, host); res != nil {
			results = append(results, res)
		}
	}
	return results, nil
}

// enumerationTargets returns the standard sensitive object set unioned with any
// custom (__c) objects the guest can enumerate via getConfigData, capped at
// maxObjects.
func (m *Module) enumerationTargets(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, endpoint, auraContext string) []string {
	seen := make(map[string]struct{}, len(standardObjects))
	targets := make([]string, 0, len(standardObjects))
	add := func(name string) {
		if name == "" {
			return
		}
		if _, dup := seen[name]; dup {
			return
		}
		seen[name] = struct{}{}
		targets = append(targets, name)
	}
	for _, o := range standardObjects {
		add(o)
	}

	// Harvest custom objects from getConfigData (best-effort; standard set is still
	// probed if this fails).
	resp := sf.InvokeAction(ctx, httpClient, endpoint, sf.BuildGetConfigData(), auraContext)
	if parsed, ok := sf.ParseAuraResponse(resp.Body); ok {
		if rv, ok := parsed.SuccessReturnValue(); ok {
			var custom []string
			for name := range sf.AccessibleObjects(rv) {
				if sf.IsCustomObject(name) {
					custom = append(custom, name)
				}
			}
			sort.Strings(custom) // deterministic ordering for the cap
			for _, c := range custom {
				add(c)
			}
		}
	}

	if len(targets) > maxObjects {
		targets = targets[:maxObjects]
	}
	return targets
}

// probeObject confirms and reports a single object's record exposure.
func (m *Module) probeObject(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	endpoint, auraContext, obj, baseURL, host string,
) *output.ResultEvent {
	page, total, ok := m.readRecords(ctx, httpClient, endpoint, auraContext, obj)
	if !ok || page == 0 {
		return nil
	}
	// Reproduce across independent rounds before reporting.
	for i := 0; i < confirmRounds; i++ {
		p, _, ok := m.readRecords(ctx, httpClient, endpoint, auraContext, obj)
		if !ok || p == 0 {
			return nil
		}
	}
	return m.build(host, baseURL, obj, page, total)
}

// readRecords invokes getItems for one object and returns the page record count
// and total. ok is false when the action did not succeed (ERROR / invalidSession
// / non-record envelope), which is distinct from a SUCCESS with zero records.
func (m *Module) readRecords(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, endpoint, auraContext, obj string) (page int, total *int, ok bool) {
	resp := sf.InvokeAction(ctx, httpClient, endpoint, sf.BuildGetItems(obj, probePageSize, 0), auraContext)
	parsed, pok := sf.ParseAuraResponse(resp.Body)
	if !pok {
		return 0, nil, false
	}
	rv, sok := parsed.SuccessReturnValue()
	if !sok {
		return 0, nil, false
	}
	return sf.RecordCount(rv)
}

func (m *Module) build(host, matchedURL, obj string, page int, total *int) *output.ResultEvent {
	sev := objectSeverity(obj)
	totalStr := "unknown"
	if total != nil {
		totalStr = fmt.Sprintf("%d", *total)
	}
	evidence := []string{
		"object: " + obj,
		fmt.Sprintf("records on first page: %d", page),
		"total records (getCount): " + totalStr,
	}

	desc := fmt.Sprintf(
		"The Salesforce Experience Cloud Guest user can read %q records over the Aura getItems action with a null (guest) token — %d record(s) "+
			"returned on the first page (total: %s). This is a direct data leak of guest-readable SObject data caused by an over-permissive Guest "+
			"User profile. Confirmed across %d independent rounds; a bogus object name returned no records, ruling out a catch-all.",
		obj, page, totalStr, confirmRounds+1,
	)

	return &output.ResultEvent{
		ModuleID:         ModuleID,
		Host:             host,
		URL:              matchedURL,
		Matched:          matchedURL,
		MatcherStatus:    true,
		ExtractedResults: evidence,
		Info: output.Info{
			Name:        "Salesforce Aura Guest Record Exposure: " + obj,
			Description: desc,
			Severity:    sev,
			Confidence:  severity.Certain,
			Tags:        ModuleTags,
			Reference:   moduleReferences,
		},
		Metadata: map[string]any{"platform": "salesforce", "object": obj},
	}
}
