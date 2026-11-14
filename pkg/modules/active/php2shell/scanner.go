package php2shell

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	php2shellinfra "github.com/vigolium/vigolium/pkg/modules/infra/php2shell"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

// phpTechTag is the tech tag this module is hard-gated on. It is published by
// php_generic_fingerprint and the PHP framework/CMS fingerprints (laravel,
// symfony, wordpress, drupal, joomla).
const phpTechTag = "php"

const (
	defaultPath    = "/index.php"
	phpMyAdminPath = "/show_config_errors.php"
	phpMyAdminMark = "phpMyAdmin"
)

// rejectedStatuses are refusals sent before PHP parsed the body (a size or
// shape limit at the server, proxy or WAF). They make a probe inconclusive.
var rejectedStatuses = map[int]bool{
	400: true, 403: true, 411: true, 413: true, 414: true,
	417: true, 422: true, 429: true, 431: true,
}

// probeSlots bounds how many origins send the multi-MiB probes at once. Each
// in-flight probe holds a few copies of its body (up to 20 MiB), so an
// unbounded fan-out over many PHP hosts could take gigabytes.
var probeSlots = make(chan struct{}, 2)

// Module implements the php2shell multipart-parser crash probe.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new php2shell module.
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
			modkit.ScanScopeRequest,
			modkit.AllInsertionPointTypes,
		),
		ds: dedup.LazyDiskSet("php2shell"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// RequiredTechs implements modules.TechAware. The executor's gate fails OPEN on
// a host with no detected stack (and is off at --intensity deep), so
// ScanPerRequest re-checks and fails CLOSED.
func (m *Module) RequiredTechs() []string { return []string{phpTechTag} }

// IncludesBaseCanProcess returns false because this module uses a custom CanProcess.
func (m *Module) IncludesBaseCanProcess() bool { return false }

// CanProcess accepts any record with a request; the target path is rebuilt.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	return ctx != nil && ctx.Request() != nil && ctx.Service() != nil
}

// ScanPerRequest probes the record's origin once, on the first record seen
// after a PHP fingerprint marked the host.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	u, err := ctx.URL()
	if err != nil {
		return nil, nil
	}
	// HARD tech gate (fail CLOSED), checked before the origin is claimed: a
	// record seen before the fingerprint fired must not use up the origin.
	if !scanCtx.HasTech(modkit.RegistryHostKey(ctx), phpTechTag) {
		return nil, nil
	}
	// The record's own response already names a patched PHP: nothing to probe.
	if ctx.HasResponse() && php2shellinfra.VerdictFor(poweredBy(ctx.Response().Header("X-Powered-By"))) == php2shellinfra.Fixed {
		return nil, nil
	}
	origin := u.Scheme + "://" + u.Host
	if !modkit.BeginHostProbeKey(scanCtx, httpClient, &m.ds, origin) {
		return nil, nil
	}

	path := defaultPath
	if strings.HasSuffix(strings.ToLower(u.Path), ".php") {
		path = u.Path
	}

	probeSlots <- struct{}{}
	defer func() { <-probeSlots }()

	r := check(ctx, httpClient, u.Host, origin, path)
	if r == nil {
		return nil, nil
	}
	return []*output.ResultEvent{r}, nil
}

// check runs the control request and up to three probes against origin+path,
// following the Assetnote scanner's verdict rules. It returns nil unless a
// probe produced a crash signal.
func check(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, host, origin, path string) *output.ResultEvent {
	control, ok := send(ctx, httpClient, path, controlBoundary, []byte(controlBody))
	if !ok || control.status >= 500 {
		return nil
	}
	if strings.Contains(control.body, phpMyAdminMark) {
		path = phpMyAdminPath
		control, ok = send(ctx, httpClient, path, controlBoundary, []byte(controlBody))
		if !ok || control.status >= 500 {
			return nil
		}
	}
	powered := control.poweredBy
	if php2shellinfra.VerdictFor(powered) == php2shellinfra.Fixed {
		return nil
	}

	for i, p := range probes {
		probe, ok := send(ctx, httpClient, path, probeBoundary, buildProbeBody(p.sizeMiB, p.parts))
		if !ok || rejectedStatuses[probe.status] {
			// A transport failure or a refusal before PHP parsed the body is
			// inconclusive; a larger probe will not fare better.
			return nil
		}
		if probe.poweredBy != "" {
			powered = probe.poweredBy
		}
		if sapi, signal := crashSignal(control, probe); signal != "" {
			return buildResult(host, origin, path, i+1, p, sapi, signal, powered, control, probe)
		}
		if php2shellinfra.VerdictFor(powered) == php2shellinfra.Fixed {
			return nil
		}
	}
	return nil
}

// exchange is one sent request's outcome, with the probe body elided.
type exchange struct {
	status    int
	body      string
	poweredBy string
	request   string
	response  string
}

// send POSTs body as multipart/form-data with the given boundary to path on the
// record's origin. Redirects are not followed and the response cache is
// bypassed (each probe must reach PHP).
func send(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, path, boundary string, body []byte) (exchange, bool) {
	raw, err := buildRequest(ctx.Request().Raw(), path, boundary, body)
	if err != nil {
		return exchange{}, false
	}
	req := httpmsg.NewRequestResponseRaw(raw, ctx.Service())
	resp, _, err := httpClient.Execute(req, http.Options{NoRedirects: true, NoClustering: true, PreserveConnection: true})
	if err != nil {
		return exchange{}, false
	}
	defer resp.Close()
	if resp.Response() == nil {
		return exchange{}, false
	}
	return exchange{
		status:    resp.Response().StatusCode,
		body:      resp.Body().String(),
		poweredBy: poweredBy(resp.Response().Header.Get("X-Powered-By")),
		request:   modkit.ElideRequestBody(raw, len(body), maxEvidenceBytes),
		response:  modkit.Truncate(resp.FullResponseString(), maxEvidenceBytes),
	}, true
}

// buildRequest rewrites the record's request into a multipart POST to path.
// The record's headers (cookies, auth) are kept; framing headers are replaced.
func buildRequest(raw []byte, path, boundary string, body []byte) ([]byte, error) {
	raw, err := httpmsg.SetMethod(raw, "POST")
	if err != nil {
		return nil, err
	}
	if raw, err = httpmsg.SetPath(raw, path); err != nil {
		return nil, err
	}
	if raw, err = httpmsg.RemoveHeader(raw, "Transfer-Encoding"); err != nil {
		return nil, err
	}
	if raw, err = httpmsg.AddOrReplaceHeader(raw, "Content-Type", "multipart/form-data; boundary="+boundary); err != nil {
		return nil, err
	}
	if raw, err = httpmsg.AddOrReplaceHeader(raw, "Connection", "close"); err != nil {
		return nil, err
	}
	return httpmsg.SetBody(raw, body)
}

// crashSignal returns the SAPI the signal implicates and a description of it,
// or "" when the probe response is not a crash. A non-empty 500 without the
// PHP fatal-error text is an application error, not a signal.
func crashSignal(control, probe exchange) (sapi, signal string) {
	if strings.Contains(probe.body, "Allowed memory size of ") &&
		strings.Contains(probe.body, " bytes exhausted") &&
		strings.Contains(probe.body, "Unknown") {
		return "mod_php/PHP-FPM", "in-band PHP fatal error (memory exhausted in Unknown) raised while parsing the multipart body"
	}
	controlHadBody := control.body != ""
	if probe.status == 500 && controlHadBody && probe.body == "" {
		return "mod_php/PHP-FPM", "HTTP 500 with an empty body although the control request produced output"
	}
	switch probe.status {
	case 502, 503, 504:
		return "PHP-FPM", fmt.Sprintf("HTTP %d from the web server fronting PHP-FPM (worker died mid-request)", probe.status)
	}
	if probe.status == 200 && controlHadBody && probe.body == "" {
		return "PHP-FPM", "HTTP 200 with an empty body although the control request produced output (worker died mid-request)"
	}
	return "", ""
}

func buildResult(host, origin, path string, index int, p probeSpec, sapi, signal, powered string, control, probe exchange) *output.ResultEvent {
	target := origin + path
	extracted := []string{
		fmt.Sprintf("Signal: probe %d (%d MiB, %d parts, %d nested keys): %s", index, p.sizeMiB, p.parts, nestedKeys, signal),
		"SAPI: " + sapi,
		fmt.Sprintf("Control: HTTP %d, %d-byte body", control.status, len(control.body)),
		fmt.Sprintf("Probe: HTTP %d, %d-byte body", probe.status, len(probe.body)),
	}
	if powered != "" {
		extracted = append(extracted, "X-Powered-By: "+powered)
		if php2shellinfra.VerdictFor(powered) == php2shellinfra.Vulnerable {
			extracted = append(extracted, "Advertised PHP predates the fix ("+php2shellinfra.FixedRelease(powered)+")")
		}
	} else {
		extracted = append(extracted, "No PHP version advertised: a patched PHP with a low memory_limit can produce the same signal")
	}
	return &output.ResultEvent{
		ModuleID:           ModuleID,
		Host:               host,
		URL:                target,
		Matched:            target,
		Request:            probe.request,
		Response:           probe.response,
		ExtractedResults:   extracted,
		AdditionalEvidence: []string{"Control request:\n" + control.request + "\n\nControl response:\n" + control.response},
		Info: output.Info{
			Name:        "php2shell: PHP multipart parser crash (" + php2shellinfra.CVEs + ")",
			Description: fmt.Sprintf("Probe %d made the PHP handler at %s fail: %s.", index, path, signal),
			Severity:    ModuleSeverity,
			Confidence:  ModuleConfidence,
			Tags:        []string{"php", "php2shell", "cve-2026-109618", "cve-2026-109619"},
			Reference:   php2shellinfra.References,
		},
		Metadata: map[string]any{
			"sapi":       sapi,
			"probe":      index,
			"size_mib":   p.sizeMiB,
			"parts":      p.parts,
			"powered_by": powered,
		},
	}
}

// poweredBy keeps a header value only when it names PHP.
func poweredBy(v string) string {
	if strings.Contains(strings.ToLower(v), "php") {
		return v
	}
	return ""
}
