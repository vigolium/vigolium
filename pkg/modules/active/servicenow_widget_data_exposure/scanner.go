package servicenow_widget_data_exposure

import (
	"fmt"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	sn "github.com/vigolium/vigolium/pkg/modules/infra/servicenow"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// confirmRounds is the number of additional independent widget reads required
// before a table is reported exposed.
const confirmRounds = 2

// maxEvidenceValue bounds the leaked sample value shown in a finding.
const maxEvidenceValue = 80

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
		ds: dedup.LazyDiskSet("servicenow_widget_data_exposure"),
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

	// Tech gate: obtaining a guest g_ck session against ServiceNow's Service Portal
	// IS the fail-closed presence check — a non-ServiceNow host yields no token.
	session, ok := sn.AcquireSession(ctx, httpClient)
	if !ok {
		return nil, nil
	}
	sn.MarkServiceNow(scanCtx, host)

	// Pick a working widget endpoint and run the catch-all negative control:
	// the endpoint must respond as the widget, a bogus table must NOT return
	// records, and a missing/invalid token must not have 401'd our session.
	endpoint, ok := m.chooseEndpoint(ctx, httpClient, session)
	if !ok {
		return nil, nil
	}

	baseURL := urlx.Scheme + "://" + urlx.Host
	var results []*output.ResultEvent
	for _, tbl := range seedTables {
		if res := m.probeTable(ctx, httpClient, endpoint, session, tbl, baseURL, host); res != nil {
			results = append(results, res)
		}
	}
	return results, nil
}

// chooseEndpoint probes each candidate widget endpoint with the bogus table and
// returns the first that responds as a widget while NOT leaking records for the
// bogus table. Returns ok=false on a 401 (token failure) or when a bogus table
// does leak (catch-all → any positive would be a false positive).
func (m *Module) chooseEndpoint(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, session sn.Session) (string, bool) {
	for _, ep := range sn.SimpleListEndpoints {
		r := sn.PostSimpleList(ctx, httpClient, ep, bogusTable, "", session)
		if !r.OK {
			continue
		}
		if r.Status == 401 {
			// Our acquired token is not accepted — cannot test this host.
			return "", false
		}
		if r.Data == nil {
			// Endpoint did not answer as the Simple List widget; try the next.
			continue
		}
		if sn.SimpleListExposed(r.Data) {
			// A table that cannot exist returned records → not a discriminating
			// widget; any positive would be a false positive.
			return "", false
		}
		return ep, true
	}
	return "", false
}

// probeTable confirms and reports one table's exposure.
func (m *Module) probeTable(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	endpoint string,
	session sn.Session,
	tbl snTable,
	baseURL, host string,
) *output.ResultEvent {
	r := sn.PostSimpleList(ctx, httpClient, endpoint, tbl.table, tbl.field, session)
	if !r.OK || !sn.SimpleListExposed(r.Data) {
		return nil
	}
	// Reproduce across independent rounds before reporting.
	for i := 0; i < confirmRounds; i++ {
		rr := sn.PostSimpleList(ctx, httpClient, endpoint, tbl.table, tbl.field, session)
		if !rr.OK || !sn.SimpleListExposed(rr.Data) {
			return nil
		}
	}
	return m.build(tbl, r.Data, endpoint, baseURL, host)
}

func (m *Module) build(tbl snTable, d *sn.SimpleListData, endpoint, baseURL, host string) *output.ResultEvent {
	matchedURL := baseURL + endpoint + "?t=" + tbl.table
	sample := sn.FirstDisplayValue(d)
	if len(sample) > maxEvidenceValue {
		sample = sample[:maxEvidenceValue] + "…"
	}
	evidence := []string{
		"table: " + tbl.table,
		"field: " + tbl.field,
		fmt.Sprintf("records on first page: %d", d.Count),
		"sample display_value: " + sample,
	}

	desc := fmt.Sprintf(
		"The ServiceNow %q table is readable by unauthenticated (guest) users through the public Simple List Service Portal widget. "+
			"A widget POST (t=%s) returned isValid:true with %d record(s) and a real display_value (%s) — %s. This indicates an allow-all "+
			"table ACL combined with a public widget. Confirmed across %d independent rounds; a bogus table returned no records and a missing "+
			"token would 401, ruling out false positives.",
		tbl.table, tbl.table, d.Count, sample, tbl.label, confirmRounds+1,
	)

	return &output.ResultEvent{
		ModuleID:         ModuleID,
		Host:             host,
		URL:              matchedURL,
		Matched:          matchedURL,
		MatcherStatus:    true,
		ExtractedResults: evidence,
		Info: output.Info{
			Name:        "ServiceNow Public Widget Data Exposure: " + tbl.table,
			Description: desc,
			Severity:    tbl.sev,
			Confidence:  severity.Certain,
			Tags:        ModuleTags,
			Reference:   moduleReferences,
		},
		Metadata: map[string]any{"platform": "servicenow", "table": tbl.table},
	}
}
