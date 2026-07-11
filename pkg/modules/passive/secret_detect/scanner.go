package secret_detect

import (
	"bytes"
	"sync"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/secretscan"
)

// Module detects leaked secrets in HTTP response bodies using the native
// in-process secret detector (pkg/secretscan). Detection runs inline per
// response — no external binary, no temp files, no end-of-scan batch.
type Module struct {
	modkit.BasePassiveModule

	detectorOnce sync.Once
	detector     *secretscan.Detector
	detectorErr  error

	// ds collapses the same secret re-detected on the same URL across scan passes
	// (discovery, spidering, re-spider, and the dynamic-assessment baseline all
	// fetch the same page), keyed by a hash of SecretDedupKey. It resolves to the
	// per-runner dedup Manager on the ScanContext, so — unlike a module-level map
	// on this registry singleton — it is bounded (LRU-evicted), isolated per scan,
	// and never carries a finding (or suppression) from one scan or project into
	// the next in the long-lived server. Its check-and-set is atomic, so two
	// worker-pool goroutines can't both emit the same secret.
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new secret detection passive module.
func New() *Module {
	m := &Module{
		BasePassiveModule: modkit.NewBasePassiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.PassiveScanScopeResponse,
		),
		ds: dedup.LazyDiskSet("secret_detect"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// CanProcess filters out responses that are not worth scanning:
// nil/empty responses, media content, non-text MIME types, and oversized bodies.
// The eligibility decision itself is the shared ShouldScanBody policy.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Response() == nil {
		return false
	}

	body := ctx.Response().Body()
	mimeType := ctx.Response().Header("Content-Type")
	urlPath := ""
	if u, err := ctx.URL(); err == nil {
		urlPath = u.Path
	}

	return ShouldScanBody(mimeType, urlPath, len(body))
}

// ScanPerRequest scans the response body for leaked secrets and returns the
// findings immediately. Matches are graded and false-positive-filtered exactly
// as the previous batch path did; only the detection engine changed.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	det, err := m.getDetector()
	if err != nil {
		return nil, nil
	}

	resp := ctx.Response()
	// A WAF/CDN edge block is the edge talking, not the application — skip it so a
	// challenge/error page's random tokens are never scanned as app secrets.
	if modkit.IsEdgeBlockedResponse(resp) {
		return nil, nil
	}

	body := resp.Body()
	matches := det.Detect(body)
	if len(matches) == 0 {
		return nil, nil
	}

	ev := EvidenceContext{
		Body:         body,
		RespHead:     string(resp.Head()),
		StatusCode:   resp.StatusCode(),
		ContentType:  resp.Header("Content-Type"),
		HeaderValues: JoinHeaderValues(resp.Headers()),
	}
	if u, err := ctx.URL(); err == nil {
		ev.URL = u.String()
		ev.Host = u.Host
	}
	if req := ctx.Request(); req != nil {
		ev.Request = string(req.Raw())
	}

	// Resolve the scan-scoped dedup set once for this response (nil when no dedup
	// Manager is wired, e.g. unit tests — then every match is emitted and the
	// storage layer collapses any duplicates).
	ds := m.ds.Get(scanCtx.DedupMgr())

	var results []*output.ResultEvent
	for _, mt := range matches {
		if event := m.buildFinding(mt, ev, ds); event != nil {
			results = append(results, event)
		}
	}
	return results, nil
}

// buildFinding deduplicates then grades one match via the shared GradeMatch
// helper, returning the finding or nil (duplicate or structural false positive).
func (m *Module) buildFinding(mt secretscan.Match, ev EvidenceContext, ds *dedup.DiskSet) *output.ResultEvent {
	// Hash the dedup identity so plaintext credentials are never written into the
	// on-disk dedup set. FNV is sufficient: a collision only risks dropping one
	// finding, and the (host,url,rule,value) tuple makes that astronomically rare.
	dedupKey := dedup.FNVHash(SecretDedupKey(ev.Host, ev.URL, mt.RuleID, mt.Secret))

	// Cheap early-out for the common duplicate — the same page is re-fetched across
	// discovery/spider/re-spider/assessment passes — so grading work is skipped.
	if ds != nil && ds.Contains(dedupKey) {
		return nil
	}

	event, ok := GradeMatch(mt, ev)
	if !ok {
		return nil
	}
	event.ModuleID = ModuleID

	// Commit atomically, and only now that the match survived GradeMatch's
	// body-dependent guards: a value dropped as a blob/JS-escape artifact in one
	// body may be a genuine leak in another, so an early mark could suppress the
	// real one. IsSeen marks-and-reports in one locked step, so if a concurrent
	// worker committed this identity between the Contains check and here, the
	// second caller collapses to nil — no duplicate emission.
	if ds != nil && ds.IsSeen(dedupKey) {
		return nil
	}

	return event
}

// MatchLine returns the 1-indexed line number of the byte at offset, used as a
// fallback anchor when the snippet can't be located verbatim in the body. Shared
// by the passive module and the known-issue-scan secret pass.
func MatchLine(body []byte, offset int) int {
	if offset < 0 || offset > len(body) {
		return 1
	}
	return 1 + bytes.Count(body[:offset], []byte("\n"))
}

// getDetector returns the process-wide native secret detector, built once.
func (m *Module) getDetector() (*secretscan.Detector, error) {
	m.detectorOnce.Do(func() {
		m.detector, m.detectorErr = secretscan.Default()
	})
	return m.detector, m.detectorErr
}
