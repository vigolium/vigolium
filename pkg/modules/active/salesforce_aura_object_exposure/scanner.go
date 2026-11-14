package salesforce_aura_object_exposure

import (
	"fmt"
	"sort"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	sf "github.com/vigolium/vigolium/pkg/modules/infra/salesforce"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// confirmRounds is the number of independent getConfigData observations that must
// all return the object map before the finding is reported.
const confirmRounds = 2

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
		ds: dedup.LazyDiskSet("salesforce_aura_object_exposure"),
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

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if !modkit.BeginHostProbe(scanCtx, httpClient, diskSet, host) {
		return nil, nil
	}

	// Tech gate: locating a live Aura gateway + harvesting its context IS the
	// fail-closed presence check (a non-Salesforce host has no gateway).
	endpoint, auraContext, ok := sf.Prepare(ctx, httpClient, scanCtx)
	if !ok {
		return nil, nil
	}

	// Invoke getConfigData across independent rounds; every round must return a
	// SUCCESS envelope carrying apiNamesToKeyPrefixes. The map must be stable
	// (same object set) so a one-off/echoed response can't confirm.
	var objects map[string]string
	for i := 0; i <= confirmRounds; i++ {
		resp := sf.InvokeAction(ctx, httpClient, endpoint, sf.BuildGetConfigData(), auraContext)
		parsed, ok := sf.ParseAuraResponse(resp.Body)
		if !ok {
			return nil, nil
		}
		rv, ok := parsed.SuccessReturnValue()
		if !ok {
			return nil, nil
		}
		round := sf.AccessibleObjects(rv)
		if len(round) == 0 {
			return nil, nil
		}
		if objects == nil {
			objects = round
		} else if !sameKeys(objects, round) {
			return nil, nil
		}
	}

	custom := customObjects(objects)
	// Fire only when custom (__c) objects are guest-enumerable — a crisp,
	// low-false-positive signal of an over-permissive Guest profile. A community
	// with only default standard objects is not reported here (the record-exposure
	// module independently reports any actual standard-object data leak).
	if len(custom) == 0 {
		return nil, nil
	}

	return []*output.ResultEvent{m.build(host, urlx.Scheme+"://"+urlx.Host+endpoint, endpoint, objects, custom)}, nil
}

func (m *Module) build(host, matchedURL, endpoint string, objects map[string]string, custom []string) *output.ResultEvent {
	sort.Strings(custom)
	shownCustom := custom
	if len(shownCustom) > 15 {
		shownCustom = shownCustom[:15]
	}
	evidence := []string{
		"aura gateway: " + endpoint,
		fmt.Sprintf("guest-accessible objects: %d", len(objects)),
		fmt.Sprintf("custom (__c) objects: %d", len(custom)),
		"custom objects (sample): " + strings.Join(shownCustom, ", "),
	}

	desc := fmt.Sprintf(
		"The Salesforce Experience Cloud Guest user can invoke the Aura getConfigData action at %s and enumerate %d accessible SObjects, "+
			"including %d custom (__c) objects. This confirms guest Aura actions execute and the Guest User profile grants broad object access — "+
			"the pivot for extracting records with getItems. Reproduced across %d independent rounds with a null (guest) token.",
		endpoint, len(objects), len(custom), confirmRounds+1,
	)

	return &output.ResultEvent{
		ModuleID:         ModuleID,
		Host:             host,
		URL:              matchedURL,
		Matched:          matchedURL,
		MatcherStatus:    true,
		ExtractedResults: evidence,
		Info: output.Info{
			Name:        "Salesforce Aura Guest Object Enumeration",
			Description: desc,
			Severity:    severity.Medium,
			Confidence:  severity.Firm,
			Tags:        ModuleTags,
			Reference:   moduleReferences,
		},
		Metadata: map[string]any{"platform": "salesforce", "object_count": len(objects), "custom_object_count": len(custom)},
	}
}

// customObjects returns the __c (custom) object API names from the map.
func customObjects(objects map[string]string) []string {
	var out []string
	for name := range objects {
		if sf.IsCustomObject(name) {
			out = append(out, name)
		}
	}
	return out
}

// sameKeys reports whether two object maps expose the identical object set.
func sameKeys(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			return false
		}
	}
	return true
}
