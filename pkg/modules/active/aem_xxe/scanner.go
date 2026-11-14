package aem_xxe

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	aem "github.com/vigolium/vigolium/pkg/modules/infra/aem"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

const confirmRounds = 2

// guideContainerPaths are Adaptive Forms guideContainer internalsubmit endpoints.
// The sample geometrixx forms exist on demo/default installs; the /libs form is
// the generic component. No node is created — these target existing forms only.
var guideContainerPaths = []string{
	"/content/forms/af/geometrixx-gov/immatriculationvehicule/jcr:content/guideContainer.af.internalsubmit.json",
	"/content/forms/af/geometrixx-gov/health-care-service-form/jcr:content/guideContainer.af.internalsubmit.json",
	"/libs/fd/af/components/guideContainer.af.internalsubmit.json",
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
		ds: dedup.LazyDiskSet("aem_xxe"),
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

	if !aem.ConfirmAEM(ctx, httpClient, scanCtx) {
		return nil, nil
	}

	baseURL := urlx.Scheme + "://" + urlx.Host
	for _, path := range guideContainerPaths {
		if res := m.probe(ctx, httpClient, path, baseURL); res != nil {
			return []*output.ResultEvent{res}, nil
		}
	}
	return nil, nil
}

// probe sends the internal-entity expansion payload with a fresh marker each
// round and confirms the parser EXPANDS it (marker appears, the literal entity
// reference &xxe; does not) rather than merely echoing the payload back.
func (m *Module) probe(ctx *httpmsg.HttpRequestResponse, client *http.Requester, path, baseURL string) *output.ResultEvent {
	expanded, err := modkit.ConfirmReflectionWithValue(confirmRounds, modkit.FreshCanary, func(marker string) (bool, error) {
		res := aem.Post(ctx, client, path, xxeBody(marker), map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
			"Referer":      baseURL + "/",
		})
		if !res.OK || res.Status != 200 {
			return false, nil
		}
		// Expansion proof: the benign marker appears in a data position AND the
		// distinctive entity name is gone. An endpoint that merely echoes our
		// payload back would still carry "vigent" (in the <!ENTITY vigent …>
		// declaration or the &vigent; reference); a parser that expands the entity
		// strips both and leaves only the expanded marker. Keying on the entity
		// NAME (not &vigent;) is robust to a JSON reflector unicode-escaping '&'.
		if strings.Contains(res.Body, "vigent") {
			return false, nil
		}
		return strings.Contains(res.Body, marker), nil
	})
	if err != nil || !expanded {
		return nil
	}
	return m.build(path, baseURL)
}

// xxeBody builds the guideState form body carrying an internal-entity XML that
// expands to marker. Detection-only: the entity is internal (no SYSTEM/file/URL),
// so nothing is read or fetched — only that the parser expands entities.
func xxeBody(marker string) string {
	xml := `<!DOCTYPE afData [<!ENTITY vigent "` + marker + `">]><afData>&vigent;</afData>`
	guideState := `{"guideState":{"guideDom":{},"guideContext":{"xsdRef":"","guidePrefillXml":` + strconv.Quote(xml) + `}}}`
	return "guideState=" + url.QueryEscape(guideState)
}

func (m *Module) build(path, baseURL string) *output.ResultEvent {
	matchedURL := baseURL + path
	return &output.ResultEvent{
		ModuleID:      ModuleID,
		Host:          aem.HostFromBase(baseURL),
		URL:           matchedURL,
		Matched:       matchedURL,
		MatcherStatus: true,
		ExtractedResults: []string{
			"endpoint: " + path,
			"proof: internal XML entity expanded (detection-only; no file read or OOB performed)",
		},
		Info: output.Info{
			Name: "AEM Adaptive Forms XXE - Entity Processing Enabled (CVE-2019-8086)",
			Description: fmt.Sprintf(
				"The AEM Adaptive Forms guideContainer at %s expands internal XML entities in guidePrefillXml, confirming DTD/entity processing across %d rounds. A parser that expands entities is exposed to full XXE (file disclosure / SSRF); this check proved processing without exfiltrating any data.",
				path, confirmRounds,
			),
			Severity:   severity.High,
			Confidence: severity.Firm,
			Tags:       []string{"aem", "adobe", "xxe", "cve", "cve2019"},
			Reference: []string{
				"https://helpx.adobe.com/security/products/experience-manager/apsb19-48.html",
				"https://github.com/0ang3el/aem-hacker",
			},
		},
	}
}
