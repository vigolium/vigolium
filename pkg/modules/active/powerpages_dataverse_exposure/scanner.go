package powerpages_dataverse_exposure

import (
	"fmt"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	ppinfra "github.com/vigolium/vigolium/pkg/modules/infra/powerpages"
	"github.com/vigolium/vigolium/pkg/modules/infra/saasprobe"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// confirmRounds is the number of additional independent SUCCESS observations
// required (on top of the initial detection) before a table is reported exposed.
const confirmRounds = 2

// odataHeaders are sent on every Web API probe (anonymous read needs no token).
var odataHeaders = map[string]string{
	"Accept":           "application/json",
	"OData-MaxVersion": "4.0",
	"OData-Version":    "4.0",
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
		ds: dedup.LazyDiskSet("powerpages_dataverse_exposure"),
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

	// Tech gate + catch-all disproof in one probe: the /_api/ router must reject a
	// bogus entity set with a Dataverse 404. This is the fail-closed presence check
	// (a non-portal returns HTML, not a Dataverse error) and rules out a site that
	// 200s everything under /_api/.
	if !ppinfra.DataverseAPIMounted(ctx, httpClient) {
		return nil, nil
	}
	ppinfra.MarkPowerPages(scanCtx, host)

	baseURL := urlx.Scheme + "://" + urlx.Host
	var results []*output.ResultEvent
	for _, tbl := range seedTables {
		if res := m.probeAndConfirm(ctx, httpClient, tbl, baseURL, host); res != nil {
			results = append(results, res)
		}
	}
	return results, nil
}

// probeAndConfirm reads one table, confirms an exposure across independent rounds,
// and builds the finding. Returns nil when the table is not anonymously exposed.
func (m *Module) probeAndConfirm(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	tbl dvTable,
	baseURL, host string,
) *output.ResultEvent {
	res := probeTable(ctx, httpClient, tbl.set, "$top=1&$count=true")
	verdict := ppinfra.ClassifyTableRead(res)

	switch verdict.Kind {
	case ppinfra.VerdictExposed:
		// Reproduce the read across independent rounds (cache bypassed) before
		// reporting, so a one-off / flapping response can't produce a finding.
		for i := 0; i < confirmRounds; i++ {
			rd := ppinfra.ClassifyTableRead(probeTable(ctx, httpClient, tbl.set, "$top=1"))
			if rd.Kind != ppinfra.VerdictExposed {
				return nil
			}
		}
		// Full-enumeration evidence: pull a sample page + the total row count.
		sample := ppinfra.ClassifyTableRead(probeTable(ctx, httpClient, tbl.set, "$top=20&$count=true"))
		if sample.Kind != ppinfra.VerdictExposed {
			sample = verdict
		}
		return m.buildExposed(tbl, sample, baseURL, host)
	case ppinfra.VerdictColumnRestricted:
		// Table is Web-API-enabled and anonymously reachable, but the probed
		// columns are not allow-listed. Report the reachable table at a lower
		// severity — it evidences a misconfigured permission surface.
		return m.buildColumnRestricted(tbl, baseURL, host)
	default:
		return nil
	}
}

func probeTable(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, set, query string) saasprobe.Result {
	path := "/_api/" + set
	if query != "" {
		path += "?" + query
	}
	return saasprobe.Get(ctx, httpClient, path, odataHeaders)
}

func (m *Module) buildExposed(tbl dvTable, v ppinfra.TableVerdict, baseURL, host string) *output.ResultEvent {
	matchedURL := baseURL + "/_api/" + tbl.set

	total := "unknown"
	if v.Total != nil {
		total = fmt.Sprintf("%d", *v.Total)
	}
	evidence := []string{
		"entity set: " + tbl.set,
		fmt.Sprintf("sample records returned: %d", v.Sample),
		"total rows (@odata.count): " + total,
	}
	if v.Evidence != "" {
		evidence = append(evidence, v.Evidence)
	}

	confidence := severity.Certain
	desc := fmt.Sprintf(
		"Anonymous Dataverse Web API read of the %q table. An unauthenticated GET %s returned %d record(s) (total: %s) with an @odata.context — %s. "+
			"This indicates a Table Permission granting the Anonymous Users web role read access with an over-broad column allow-list. "+
			"Confirmed across %d independent rounds; a bogus entity set returned a Dataverse 404, ruling out a catch-all.",
		tbl.set, matchedURL, v.Sample, total, tbl.label, confirmRounds+1,
	)

	return &output.ResultEvent{
		ModuleID:         ModuleID,
		Host:             host,
		URL:              matchedURL,
		Matched:          matchedURL,
		MatcherStatus:    true,
		ExtractedResults: evidence,
		Info: output.Info{
			Name:        "Power Pages Anonymous Dataverse Exposure: " + tbl.set,
			Description: desc,
			Severity:    tbl.sev,
			Confidence:  confidence,
			Tags:        ModuleTags,
			Reference:   moduleReferences,
		},
		Metadata: map[string]any{"table": tbl.set, "platform": "power-pages"},
	}
}

func (m *Module) buildColumnRestricted(tbl dvTable, baseURL, host string) *output.ResultEvent {
	matchedURL := baseURL + "/_api/" + tbl.set
	// Cap severity: the table is reachable but no record data was returned, so this
	// is a weaker signal than a full data leak.
	sev := modkit.CapSeverity(tbl.sev, severity.Medium)

	desc := fmt.Sprintf(
		"The %q Dataverse table is exposed to the Web API and anonymously reachable, but the probed columns are not on the Web API allow-list "+
			"(HTTP 403, AttributePermissionIsMissing / code 90040101). No record data was returned, yet the reachable table indicates a permissive "+
			"Anonymous Users table permission that should be reviewed — a wider column allow-list would leak data.",
		tbl.set,
	)

	return &output.ResultEvent{
		ModuleID:         ModuleID,
		Host:             host,
		URL:              matchedURL,
		Matched:          matchedURL,
		MatcherStatus:    true,
		ExtractedResults: []string{"entity set: " + tbl.set, "status: 403 AttributePermissionIsMissing (table enabled, column restricted)"},
		Info: output.Info{
			Name:        "Power Pages Anonymously-Reachable Dataverse Table (column-restricted): " + tbl.set,
			Description: desc,
			Severity:    sev,
			Confidence:  severity.Firm,
			Tags:        ModuleTags,
			Reference:   moduleReferences,
		},
		Metadata: map[string]any{"table": tbl.set, "platform": "power-pages", "column_restricted": true},
	}
}
