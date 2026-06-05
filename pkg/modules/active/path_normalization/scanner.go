package path_normalization

import (
	"fmt"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	syncutils "github.com/projectdiscovery/utils/sync"
	"github.com/vigolium/vigolium/pkg/anomaly"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"go.uber.org/zap"
)

// Note: sync is still needed for the goroutine mutex

// PathPayload defines a structure for path normalization payloads
type PathPayload struct {
	Payload          string // The actual traversal/normalization payload string
	DisableAutoSlash bool   // If true, don't automatically add a trailing slash to the base path before appending the payload
}

var (
	// Common path normalization/traversal payloads with auto-slash control
	pathNormalizationPayloads = []PathPayload{
		{Payload: "..;/", DisableAutoSlash: true}, // /js..;/xxx.jsp
		{Payload: "../", DisableAutoSlash: true},  // /js../
		{Payload: "..%2f", DisableAutoSlash: true},
		{Payload: "..%252f", DisableAutoSlash: true},
		{Payload: "%2e%2e%2f", DisableAutoSlash: true},
		{Payload: "%252e%252e%252f", DisableAutoSlash: true},
		{Payload: "..//", DisableAutoSlash: true},
		{Payload: "...//", DisableAutoSlash: true},
		{Payload: ".../", DisableAutoSlash: true},
		{Payload: "..\\", DisableAutoSlash: true},
		{Payload: "...\\", DisableAutoSlash: true},
		{Payload: "..%5c", DisableAutoSlash: true},
		{Payload: "..%255c", DisableAutoSlash: true},
		{Payload: "..%255c\\", DisableAutoSlash: true},
		{Payload: "%2e%2e%5c", DisableAutoSlash: true},
		{Payload: "%252e%252e%255c", DisableAutoSlash: true},
		{Payload: "..\\/", DisableAutoSlash: true},
		{Payload: "../\\", DisableAutoSlash: true},
		{Payload: "..;a=a/", DisableAutoSlash: true},
		{Payload: "..%01/", DisableAutoSlash: true},
		{Payload: "..%0a/", DisableAutoSlash: true},
		{Payload: "..%0b/;.css", DisableAutoSlash: true},
		{Payload: "./", DisableAutoSlash: true},
	}
	// Number of times to repeat the payload prefix, relative to original path depth
	payloadRepetitionDepth = 5

	// Status codes based on pathbuster description.
	//
	// pubStatus: the over-traversed ("public"/proxy) path is rejected as a
	// malformed request.
	pubStatus = map[int]bool{
		400: true,
	}

	// Define the fingerprint types to use for comparison
	fingerprintTypes = []anomaly.Type{
		anomaly.STATUS_CODE,
		anomaly.CONTENT_TYPE,
		anomaly.LINE_COUNT,
		anomaly.WORD_COUNT,
		anomaly.LIMITED_BODY_CONTENT,
		anomaly.SERVER_HEADER,
		anomaly.PAGE_TITLE,
		anomaly.FIRST_HEADER_TAG,
	}
)

type Module struct {
	modkit.BaseActiveModule
	rhm dedup.Lazy[dedup.RequestHashManager]
	// ds gates the static-root traversal branch to once per (host, mount-segment).
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
		rhm: dedup.LazyRHM("path_normalization", dedup.Option{
			Host: true,
			Path: true,
		}),
		ds: dedup.LazyDiskSet("path_normalization_static"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest scans the request for path normalization vulnerabilities.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	var results []*output.ResultEvent
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	// Static-root traversal oracle (matrix-parameter + encoded-slash bypass of
	// static file handlers — express.static / send and similar). It has its own
	// per-(host, mount-segment) dedup and a file-content/listing oracle, distinct
	// from the normalization status oracle below, and deliberately runs on
	// static-asset URLs. A confirmed file read is the higher-signal finding, so
	// return it immediately.
	if staticRes, fatal := m.scanStaticRootTraversal(ctx, httpClient, scanCtx, urlx); len(staticRes) > 0 {
		return staticRes, nil
	} else if fatal {
		return results, nil
	}

	rhm := m.rhm.Get(scanCtx.DedupMgr())
	if rhm != nil && !rhm.ShouldCheck3(urlx, "GET", "", "path", urlx.EscapedPath(), "inURL") {
		return results, nil
	}

	var findingReported atomic.Bool
	findingReported.Store(false)

	wg, err := syncutils.New(syncutils.WithSize(1))
	if err != nil {
		return nil, err
	}
	var mutex sync.Mutex

	rawRequest := ctx.Request().Raw()
	httpService := ctx.Service()

	originalURL, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}
	originalPath := originalURL.Path
	if originalPath == "" {
		originalPath = "/"
	}

	// Fetch baseline fingerprint
	baselineFingerprint := m.fetchFingerprint(rawRequest, originalPath, httpService, httpClient)

	// Fetch root path fingerprint
	var rootFingerprint *anomaly.Fingerprint
	if originalPath != "/" {
		rootFingerprint = m.fetchFingerprint(rawRequest, "/", httpService, httpClient)
	} else {
		rootFingerprint = baselineFingerprint
	}

	// Fetch non-existent path fingerprint
	nonExistentPath := strings.TrimSuffix(originalPath, "/") + "/nonexistentpathcheck12345abcde"
	nonExistentFingerprint := m.fetchFingerprint(rawRequest, nonExistentPath, httpService, httpClient)

	pathDepth := strings.Count(strings.Trim(originalPath, "/"), "/")
	repeatCount := pathDepth + payloadRepetitionDepth

	for _, pld := range pathNormalizationPayloads {
		wg.Add()
		go func(payloadInfo PathPayload) {
			defer wg.Done()

			payload := payloadInfo.Payload
			disableAutoSlash := payloadInfo.DisableAutoSlash

			var basePathForPayload string
			if disableAutoSlash {
				basePathForPayload = strings.TrimSuffix(originalPath, "/")
			} else {
				if !strings.HasSuffix(originalPath, "/") {
					basePathForPayload = originalPath + "/"
				} else {
					basePathForPayload = originalPath
				}
			}

			for i := 1; i <= repeatCount; i++ {
				if findingReported.Load() {
					return
				}

				fuzzedPathSegment := strings.Repeat(payload, i)
				fuzzedPath := basePathForPayload + fuzzedPathSegment

				// Step 1: Request with Fuzzed Path
				fuzzedRaw1, err1 := httpmsg.SetPath(rawRequest, fuzzedPath)
				if err1 != nil {
					continue
				}
				fuzzedRaw1, _ = httpmsg.ClearQueryString(fuzzedRaw1)

				fuzzedReq1, parseErr1 := httpmsg.ParseRawRequest(string(fuzzedRaw1))
				if parseErr1 != nil {
					continue
				}
				fuzzedReq1.WithService(httpService)

				resp1, _, err1 := httpClient.Execute(fuzzedReq1, http.Options{})
				if err1 != nil {
					continue
				}

				s1 := resp1.Response().StatusCode
				resp1.Close()

				if _, ok := pubStatus[s1]; !ok {
					continue
				}

				// Step 2: Request with Backed-off Path
				backedOffPathSegment := ""
				if i > 1 {
					backedOffPathSegment = strings.Repeat(payload, i-1)
				}
				backedOffPath := basePathForPayload + backedOffPathSegment

				backedOffRaw, err2 := httpmsg.SetPath(rawRequest, backedOffPath)
				if err2 != nil {
					continue
				}
				backedOffRaw, _ = httpmsg.ClearQueryString(backedOffRaw)

				backedOffReq, parseErr2 := httpmsg.ParseRawRequest(string(backedOffRaw))
				if parseErr2 != nil {
					continue
				}
				backedOffReq.WithService(httpService)

				resp2, _, err2 := httpClient.Execute(backedOffReq, http.Options{})
				if err2 != nil {
					continue
				}

				s2 := resp2.Response().StatusCode
				// Require the backed-off path to actually REACH A RESOURCE (a 2xx
				// success). The earlier oracle also accepted 403/404/500, but on
				// hardened hosts (WAF / CIAM / identity gateways) those are
				// default-deny / not-found responses emitted for almost any
				// malformed or disallowed path, so a 400 (over-traversal) -> 403
				// (backed-off) transition was reported as a normalization bypass
				// when it was just the host's normal error handling — the reported
				// false positive. Demanding a real resource reach preserves the
				// canonical Orange-Tsai signal (normalize through the proxy to
				// fetch an internal resource you cannot reach directly) while
				// removing the error-status FP class.
				if !isResourceReached(s2) {
					resp2.Close()
					continue
				}

				// Fingerprint comparison
				req2Fingerprint := anomaly.NewFingerprint4(resp2.Response(), fingerprintTypes)
				resp2.Close()

				if req2Fingerprint == nil {
					continue
				}

				isDifferentFromBaseline := baselineFingerprint == nil || !baselineFingerprint.IsSimilar(req2Fingerprint)
				isDifferentFromNonExistent := nonExistentFingerprint == nil || !nonExistentFingerprint.IsSimilar(req2Fingerprint)
				isDifferentFromRoot := rootFingerprint == nil || !rootFingerprint.IsSimilar(req2Fingerprint)

				if !isDifferentFromBaseline || !isDifferentFromNonExistent || !isDifferentFromRoot {
					continue
				}

				// Reproducibility gate: re-fetch the backed-off path and require
				// the same resource-reached status with a matching fingerprint.
				// A genuine normalization bypass is deterministic; a one-off 2xx
				// from a dynamic/error page (rotating tokens, load-balanced error
				// pages) will not reproduce identically and is dropped.
				confirmStatus, confirmFingerprint := m.fetchStatusFingerprint(rawRequest, backedOffPath, httpService, httpClient)
				if !isResourceReached(confirmStatus) || confirmFingerprint == nil || !req2Fingerprint.IsSimilar(confirmFingerprint) {
					continue
				}

				// Check if backed-off path is same as original
				vulnURL := &url.URL{
					Scheme: originalURL.Scheme,
					Host:   originalURL.Host,
					Path:   backedOffPath,
				}
				vulnURLString := vulnURL.String()

				originalURLStrForCompare := originalURL.String()
				if !strings.HasSuffix(originalPath, "/") && !disableAutoSlash {
					originalURLStrForCompare += "/"
				} else if strings.HasSuffix(originalPath, "/") && disableAutoSlash {
					originalURLStrForCompare = strings.TrimSuffix(originalURLStrForCompare, "/")
				}

				if vulnURLString == originalURLStrForCompare {
					continue
				}

				// Report vulnerability
				desc := fmt.Sprintf(
					"Path normalization vulnerability detected. Payload '%s' repetition led to path '%s' (rejected with status %d), while the backed-off path '%s' reproducibly reached a resource (status %d) whose response differs from the baseline, root, and non-existent reference pages.",
					payload, fuzzedPath, s1, vulnURLString, s2,
				)

				resultEvent := &output.ResultEvent{
					ModuleID: m.ID(),
					Info: output.Info{
						Name:        m.Name(),
						Description: desc,
						Severity:    m.Severity(),
					},
					URL:       vulnURLString,
					Host:      originalURL.Host,
					Request:   string(backedOffRaw),
					Timestamp: time.Now(),
				}

				mutex.Lock()
				results = append(results, resultEvent)
				mutex.Unlock()

				findingReported.Store(true)

				zap.L().Info("Path Normalization Vulnerability Found",
					zap.String("moduleID", m.ID()),
					zap.String("url", vulnURLString),
					zap.String("payload", payload),
				)

				break
			}
		}(pld)
	}

	wg.Wait()
	return results, nil
}

// isResourceReached reports whether a backed-off path response represents
// actually reaching a resource — a 2xx success — rather than a default-deny
// (403), not-found (404) or server-error (500) response. Those error statuses
// are emitted indiscriminately by hardened hosts for malformed/disallowed
// paths, so treating them as "internal resource reached" produced the reported
// path-normalization false positives.
func isResourceReached(status int) bool {
	return status >= 200 && status < 300
}

// fetchFingerprint fetches the response fingerprint for a given path.
func (m *Module) fetchFingerprint(
	rawRequest []byte,
	path string,
	httpService *httpmsg.Service,
	httpClient *http.Requester,
) *anomaly.Fingerprint {
	_, fp := m.fetchStatusFingerprint(rawRequest, path, httpService, httpClient)
	return fp
}

// fetchStatusFingerprint fetches both the status code and response fingerprint
// for a given path. Returns (0, nil) on any request/parse error.
func (m *Module) fetchStatusFingerprint(
	rawRequest []byte,
	path string,
	httpService *httpmsg.Service,
	httpClient *http.Requester,
) (int, *anomaly.Fingerprint) {
	modifiedRaw, err := httpmsg.SetPath(rawRequest, path)
	if err != nil {
		return 0, nil
	}
	modifiedRaw, _ = httpmsg.ClearQueryString(modifiedRaw)

	req, err := httpmsg.ParseRawRequest(string(modifiedRaw))
	if err != nil {
		return 0, nil
	}
	req.WithService(httpService)

	resp, _, err := httpClient.Execute(req, http.Options{})
	if err != nil {
		return 0, nil
	}
	defer resp.Close()

	return resp.Response().StatusCode, anomaly.NewFingerprint4(resp.Response(), fingerprintTypes)
}
