package aspnet_sensitive_files

import (
	"crypto/sha256"
	"fmt"
	"math"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

// decoyRounds is how many same-directory/same-extension negative-control probes
// the catch-all disproof issues per candidate. A host that answers every
// /<dir>/<anything>.<ext> with the same 200 body (a reflecting/echo server, a
// SPA fallback, a blanket rewrite) trips at least one round and the candidate is
// dropped. Two rounds tolerate a single WAF/CDN flake without over-probing.
const decoyRounds = 2

type notFoundFingerprint struct {
	bodyHash string
	bodyLen  int
}

// accepts reports whether body satisfies this file's confirmation: its marker
// requirement (requireAll co-occurrence when set, otherwise any single marker)
// AND, when present, a confirmAny signal. matched carries the evidence
// substrings. Centralized so the primary match and the catch-all decoy disproof
// apply the exact same predicate.
func (sf sensitiveFile) accepts(body string) (matched []string, ok bool) {
	if len(sf.requireAll) > 0 {
		matched, ok = modkit.MatchAllGroups(body, sf.requireAll)
		if !ok {
			return nil, false
		}
	} else {
		for _, marker := range sf.markers {
			if strings.Contains(body, marker) {
				matched = append(matched, marker)
			}
		}
		if len(matched) == 0 {
			return nil, false
		}
	}
	if len(sf.confirmAny) > 0 {
		confirmed := false
		for _, sig := range sf.confirmAny {
			if strings.Contains(body, sig) {
				matched = append(matched, sig)
				confirmed = true
				break
			}
		}
		if !confirmed {
			return nil, false
		}
	}
	return matched, true
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
			modkit.ScanScopeRequest,
			modkit.AllInsertionPointTypes,
		),
		ds: dedup.LazyDiskSet("aspnet_sensitive_files"),
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

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if !modkit.BeginHostProbe(scanCtx, httpClient, diskSet, host) {
		return nil, nil
	}

	fp := m.fingerprint404(ctx, httpClient)

	var results []*output.ResultEvent
	for _, sf := range sensitiveFiles {
		if result := m.probeFile(ctx, httpClient, sf, fp); result != nil {
			results = append(results, result)
		}
	}
	return results, nil
}

func (m *Module) fingerprint404(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
) *notFoundFingerprint {
	randomPath := "/vigolium-aspnet-files-404-" + utils.RandomString(8)

	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, randomPath)
	if err != nil {
		return nil
	}

	// SetMethod/SetPath produce well-formed raw, so wrap directly instead
	// of re-parsing on this hot path.
	fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil
	}
	defer resp.Close()

	body := resp.Body().String()
	return &notFoundFingerprint{
		bodyHash: fmt.Sprintf("%x", sha256.Sum256([]byte(body))),
		bodyLen:  len(body),
	}
}

func (m *Module) probeFile(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	sf sensitiveFile,
	fp *notFoundFingerprint,
) *output.ResultEvent {
	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, sf.path)
	if err != nil {
		return nil
	}

	// SetMethod/SetPath produce well-formed raw, so wrap directly instead
	// of re-parsing on this hot path.
	fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil
	}
	defer resp.Close()

	if resp.Response() == nil {
		return nil
	}

	status := resp.Response().StatusCode
	if status == 404 || status == 500 || status == 502 || status == 503 || status == 403 || status == 401 {
		return nil
	}

	if status == 301 || status == 302 {
		location := resp.Response().Header.Get("Location")
		if strings.Contains(strings.ToLower(location), "login") {
			return nil
		}
	}

	body := resp.Body().String()

	if fp != nil {
		bodyHash := fmt.Sprintf("%x", sha256.Sum256([]byte(body)))
		if bodyHash == fp.bodyHash {
			return nil
		}
		if fp.bodyLen > 0 {
			ratio := math.Abs(float64(len(body)-fp.bodyLen)) / float64(fp.bodyLen)
			if ratio < 0.05 {
				return nil
			}
		}
	}

	// Catch-all / SPA shell guard: a themed app that returns the same shell for
	// any path is a false positive even when a weak marker appears in that shell.
	if modkit.ResemblesObservedPage(ctx, body) {
		return nil
	}

	for _, anti := range sf.antiMarkers {
		if strings.Contains(body, anti) {
			return nil
		}
	}

	if status != 200 {
		return nil
	}

	// Strip the reflected request from the body before marker matching: a host
	// that echoes the requested path or the request body back into its response
	// (the acme trace.acme.com echo server) would otherwise let an injected
	// value satisfy a marker ("password" from the request's own JSON body). The
	// original body is kept for anti-markers and stored evidence.
	matchBody := modkit.StripReflectedProbePath(body, sf.path)
	if reqBody := ctx.Request().BodyToString(); reqBody != "" {
		matchBody = modkit.StripReflected(matchBody, reqBody)
	}

	matchedMarkers, ok := sf.accepts(matchBody)
	if !ok {
		return nil
	}

	// Multi-round catch-all disproof: probe several guaranteed-nonexistent
	// siblings sharing this file's directory AND extension. If a random same-shape
	// path returns the same status and also satisfies the file's predicate, the
	// host serves this content for any path (a reflecting/echo server, a SPA
	// fallback, an extension-scoped catch-all) and the match proves nothing. A
	// genuinely exposed file has no such sibling (the decoy 404s), so this costs no
	// true positives, and it is robust to the body-truncation quirk because the
	// decoy is run through the same predicate rather than a body-similarity compare.
	if modkit.MultiRoundExtDecoyCatchAll(ctx, httpClient, sf.path, body, status, decoyRounds, func(b string) bool {
		_, sibOK := sf.accepts(b)
		return sibOK
	}) {
		return nil
	}

	urlx, _ := ctx.URL()
	targetURL := urlx.Scheme + "://" + urlx.Host + sf.path

	findingName := sf.title
	if findingName == "" {
		findingName = fmt.Sprintf("ASP.NET Sensitive File: %s", sf.name)
	}

	return &output.ResultEvent{
		URL:              targetURL,
		Matched:          targetURL,
		Request:          string(modifiedRaw),
		Response:         resp.FullResponseString(),
		ExtractedResults: matchedMarkers,
		Info: output.Info{
			Name:        findingName,
			Description: sf.desc,
			Severity:    modkit.CapSeverity(sf.sev, severity.Medium),
			Confidence:  severity.Tentative,
			Tags:        []string{"aspnet", "sensitive-file", "information-disclosure", "misconfiguration"},
			Reference:   []string{"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information"},
		},
	}
}
