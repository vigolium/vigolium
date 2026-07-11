package spring_h2_console_exposure

import (
	"crypto/sha256"
	"fmt"
	"math"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

type notFoundFingerprint struct {
	bodyHash string
	bodyLen  int
}

type probe struct {
	path        string
	name        string
	markers     [][]string
	antiMarkers []string
	sev         severity.Severity
	desc        string
	bypass      bool // if true, also probe reverse-proxy path-normalization bypasses
}

var probes = []probe{
	{
		path:        "/h2-console",
		name:        "H2 Console",
		markers:     [][]string{{"H2 Console", "h2-console"}, {"JDBC URL", "Driver Class", "org.h2"}},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.Medium,
		desc:        "The H2 console connection interface is reachable without credentials. This is a dangerous development surface, but database authentication, SQL execution, and code execution were not demonstrated.",
		bypass:      true,
	},
	{
		path:        "/h2-console/",
		name:        "H2 Console (trailing slash)",
		markers:     [][]string{{"H2 Console", "h2-console"}, {"JDBC URL", "Driver Class", "org.h2"}},
		antiMarkers: []string{"404", "Not Found"},
		sev:         severity.Medium,
		desc:        "The H2 console connection interface is reachable without credentials at the trailing-slash path; database access was not demonstrated.",
		bypass:      true,
	},
	{
		path:        "/console",
		name:        "H2 Console (alternate path)",
		markers:     [][]string{{"H2 Console", "h2-console"}, {"JDBC URL", "org.h2", "Driver Class"}},
		antiMarkers: []string{"404", "Not Found", "WebLogic", "WildFly", "JBoss"},
		sev:         severity.Medium,
		desc:        "The H2 console connection interface is reachable without credentials at an alternate path; database access was not demonstrated.",
		bypass:      true,
	},
}

// Module implements the Spring H2 Console Exposure active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Spring H2 Console Exposure module.
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
		ds: dedup.LazyDiskSet("spring_h2_console_exposure"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) IncludesBaseCanProcess() bool { return false }

func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Request() == nil {
		return false
	}
	return ctx.Response() != nil
}

// ScanPerRequest probes the host for exposed H2 database web consoles.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	service := ctx.Service()
	if service == nil {
		return nil, nil
	}

	host := service.Host()

	cleanRaw, err := modkit.StripCredentialHeaders(ctx.Request().Raw())
	if err != nil {
		return nil, nil
	}
	anonymousClient, err := httpClient.CloneWithoutCredentials()
	if err != nil {
		return nil, nil
	}
	anonymousCtx := httpmsg.NewHttpRequestResponse(
		httpmsg.NewHttpRequestWithService(service, cleanRaw),
		ctx.Response(),
	)

	urlx, err := anonymousCtx.URL()
	if err != nil {
		return nil, nil
	}

	// Walk the web root plus any context-path prefixes of the observed URL, so a
	// console mounted under server.servlet.context-path (e.g. /api/h2-console) is
	// reached, not just /h2-console. Claim each (host, base) pair up front so a
	// fully-deduped request issues no traffic at all — including the soft-404
	// fingerprint below.
	var diskSet *dedup.DiskSet
	if scanCtx != nil {
		diskSet = m.ds.Get(scanCtx.DedupMgr())
	}
	bases := modkit.UnclaimedBasePaths(diskSet, host, modkit.CandidateBasePaths(urlx.Path))
	if len(bases) == 0 {
		return nil, nil
	}

	fp := m.fingerprint404(anonymousCtx, anonymousClient)

	// Walk the bases and, once per host, fall back to the reverse-proxy path-
	// normalization bypass for any bypass-eligible endpoint the direct root probe
	// found blocked. The shared driver owns the status/hit bookkeeping and the
	// once-per-host + blocked-status gating.
	results := modkit.DriveProbesWithBypass(bases, probes, urlx.Path,
		func(p probe) string { return p.name },
		func(p probe) string { return p.path },
		func(p probe) bool { return p.bypass },
		func(p probe, probePath string) (*output.ResultEvent, int) {
			return m.probeEndpoint(anonymousCtx, anonymousClient, p, probePath, fp)
		})

	return results, nil
}

func (m *Module) fingerprint404(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
) *notFoundFingerprint {
	randomPath := "/vigolium-h2-404-" + utils.RandomString(8)

	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, randomPath)
	if err != nil {
		return nil
	}

	// SetPath produces well-formed raw, so wrap directly instead of
	// re-parsing on this hot path.
	fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true, NoClustering: true})
	if err != nil {
		return nil
	}
	defer resp.Close()
	if resp.Response() == nil || infra.IsBlockedResponse(resp) {
		return nil
	}

	body := resp.Body().String()
	return &notFoundFingerprint{
		bodyHash: fmt.Sprintf("%x", sha256.Sum256([]byte(body))),
		bodyLen:  len(body),
	}
}

func (m *Module) probeEndpoint(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	p probe,
	probePath string,
	fp *notFoundFingerprint,
) (*output.ResultEvent, int) {
	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil, 0
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, probePath)
	if err != nil {
		return nil, 0
	}

	// SetPath produces well-formed raw, so wrap directly instead of
	// re-parsing on this hot path.
	fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true, NoClustering: true})
	if err != nil {
		return nil, 0
	}
	defer resp.Close()

	if resp.Response() == nil {
		return nil, 0
	}

	status := resp.Response().StatusCode
	if infra.GetBlockDetectionValidator().Validate(resp) != nil {
		return nil, status
	}
	if status == 404 || status == 500 || status == 502 || status == 503 || status == 403 || status == 401 {
		return nil, status
	}

	if status == 301 || status == 302 {
		location := resp.Response().Header.Get("Location")
		if strings.Contains(strings.ToLower(location), "login") || strings.Contains(strings.ToLower(location), "user") {
			return nil, status
		}
	}

	body := resp.Body().String()

	if fp != nil {
		bodyHash := fmt.Sprintf("%x", sha256.Sum256([]byte(body)))
		if bodyHash == fp.bodyHash {
			return nil, status
		}
		if fp.bodyLen > 0 {
			ratio := math.Abs(float64(len(body)-fp.bodyLen)) / float64(fp.bodyLen)
			if ratio < 0.05 {
				return nil, status
			}
		}
	}

	for _, anti := range p.antiMarkers {
		if strings.Contains(body, anti) {
			return nil, status
		}
	}

	if status != 200 {
		return nil, status
	}

	// Confirm the marker groups, then drop the finding if a sub-directory
	// catch-all serves the same markers for a nonexistent sibling (a handler that
	// 200s every child path). Root-level probes are covered by the random-path 404
	// fingerprint above, so the sibling probe is a no-op for them.
	matchedMarkers, ok := modkit.MatchAndConfirmSibling(ctx, httpClient, probePath, body, p.markers)
	if !ok {
		return nil, status
	}

	urlx, _ := ctx.URL()
	targetURL := urlx.Scheme + "://" + urlx.Host + probePath

	return &output.ResultEvent{
		ModuleID:         ModuleID,
		RecordKind:       output.RecordKindCandidate,
		EvidenceGrade:    output.EvidenceGradeCandidate,
		URL:              targetURL,
		Matched:          targetURL,
		Request:          string(modifiedRaw),
		Response:         resp.FullResponseString(),
		ExtractedResults: matchedMarkers,
		Info: output.Info{
			Name:        fmt.Sprintf("H2 Console Exposure Candidate: %s", p.name),
			Description: p.desc,
			Severity:    p.sev,
			Confidence:  severity.Firm,
			Tags:        []string{"spring", "java", "h2", "database", "misconfiguration"},
			Reference:   []string{"https://www.h2database.com/html/tutorial.html"},
		},
		Metadata: map[string]any{
			"credential_free":        true,
			"database_access_tested": false,
			"sql_execution_tested":   false,
			"code_execution_tested":  false,
		},
	}, status
}
