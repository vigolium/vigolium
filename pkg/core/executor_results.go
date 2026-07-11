package core

import (
	"bytes"
	"context"
	"fmt"
	goruntime "runtime"
	"strings"

	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"go.uber.org/zap"
)

func (e *Executor) processResults(ctx context.Context, results []*output.ResultEvent, m modules.Module, item *httpmsg.HttpRequestResponse) {
	moduleType := database.ModuleTypeActive
	if _, ok := m.(modules.PassiveModule); ok {
		moduleType = database.ModuleTypePassive
	}
	for _, result := range results {
		result.ModuleType = moduleType
		result.FindingSource = database.FindingSourceDynamicAssessment
		e.assignModuleInfo(result, m)

		// Backfill request/response from original item when the module
		// did not populate them so the finding always carries raw data
		// and can be linked to an http_record.
		//
		// When we backfill the request, result.Request IS the unchanged baseline
		// request — pass that request to emitResult so it reuses the baseline's
		// memoized hash for the record-link lookup instead of allocating a temp
		// request and re-hashing the raw bytes per finding. For DB-sourced items
		// the baseline's hash is pre-registered in requestUUIDs (at item
		// ingestion), so the lookup hits and links to the existing record rather
		// than saving a duplicate. A module that sets its own (mutated) request
		// leaves baselineReq nil and takes the unchanged parse/save path.
		var baselineReq *httpmsg.HttpRequest
		if item != nil {
			// Whether the module supplied its own request. Captured BEFORE the
			// request backfill below so we can tell a module-mutated request
			// apart from the baseline one when deciding on the response.
			moduleSuppliedRequest := result.Request != ""
			if result.Request == "" && item.Request() != nil {
				result.Request = string(item.Request().Raw())
				baselineReq = item.Request()
			}
			// Backfill the baseline response ONLY when it actually corresponds to
			// result.Request. That holds when the module supplied no request (the
			// finding adopts the whole baseline exchange) or its own request is
			// byte-identical to the baseline. If the module supplied a *mutated*
			// request, the baseline response never came from it — pairing them
			// would fabricate a (request, response) exchange that never happened
			// on the wire. In that case leave Response empty; a module with a real
			// proving response is expected to set it itself.
			if result.Response == "" && item.HasResponse() {
				if !moduleSuppliedRequest ||
					(item.Request() != nil && result.Request == string(item.Request().Raw())) {
					result.Response = string(item.Response().Raw())
				}
			}
		}

		// Body-differential safety net: for modules that opt in, re-confirm the
		// payload-vs-baseline difference before reporting. Drops the finding when
		// no real, reproducible differential exists (status flip, dynamic noise,
		// or no effect) — the most common false-positive causes.
		if !e.reconfirmBodyDifferential(ctx, m, result, item) {
			continue
		}

		emitted := e.emitResult(ctx, result, baselineReq)

		// Cross-module finding dedup: mark (URL, param, vuln_class) as found
		// so that lower-priority modules with the same vuln class can skip.
		if emitted.outcome == emissionFinding && emitted.event != nil {
			if vc, ok := m.(modules.VulnClassifier); ok && e.scanCtx != nil && e.scanCtx.ParamFindings != nil {
				param := emitted.event.FuzzingParameter
				if param != "" {
					e.scanCtx.ParamFindings.MarkFound(paramFindingLocationKeyFromResult(emitted.event), param, vc.VulnClass())
				}
			}
		}
	}
}

// reconfirmBodyDifferential re-confirms a candidate finding by replaying its
// payload-applied request and comparing it against a clean (no-payload)
// baseline, for modules that opt in via modules.BodyDifferentialConfirmable.
// Returns true to keep (emit) the finding, false to drop it.
//
// It fails OPEN on anything inconclusive — a module that didn't opt in, missing
// request data, an identical payload/baseline (nothing to differentiate), or a
// network/parse error during re-confirmation — so a transient failure never
// silently discards a true positive. It fails CLOSED (drops, and counts the
// drop) only on a definitive negative: the payload produced no real,
// reproducible, in-band difference against a stable baseline.
func (e *Executor) reconfirmBodyDifferential(
	ctx context.Context,
	m modules.Module,
	result *output.ResultEvent,
	item *httpmsg.HttpRequestResponse,
) bool {
	confirmable, ok := m.(modules.BodyDifferentialConfirmable)
	if !ok || !confirmable.ConfirmsByBodyDifferential() {
		return true // module did not opt in
	}
	if item == nil || item.Request() == nil || result.Request == "" || e.httpClient == nil {
		return true // not enough context to re-confirm
	}

	payloadRaw := []byte(result.Request)
	baselineRaw := item.Request().Raw()
	if bytes.Equal(payloadRaw, baselineRaw) {
		return true // no payload differential to verify
	}

	cachedBody := ""
	cachedStatus := 0
	if item.HasResponse() && item.Response() != nil {
		cachedBody = string(item.Response().Raw())
		cachedStatus = item.Response().StatusCode()
	}

	res := modkit.ConfirmBodyDifferential(
		e.httpClient.WithContext(ctx),
		item.Service(),
		payloadRaw, baselineRaw,
		cachedBody, cachedStatus,
		modkit.ReconfirmConfig{NoRedirects: true},
	)

	if !res.Ran {
		zap.L().Debug("body-differential re-confirmation inconclusive; keeping finding",
			zap.String("module", m.ID()),
			zap.String("url", result.URL),
			zap.String("reason", res.Reason))
		return true
	}
	if res.Confirmed {
		return true
	}

	e.suppressedFindings.Add(1)
	zap.L().Debug("dropped finding: payload-vs-baseline differential not re-confirmed",
		zap.String("module", m.ID()),
		zap.String("url", result.URL),
		zap.String("param", result.FuzzingParameter),
		zap.String("reason", res.Reason))
	return false
}

// moduleFindingAllowed returns true if the module has not exceeded its finding cap.
func (e *Executor) moduleFindingAllowed(moduleID string) bool {
	cap := e.cfg.MaxFindingsPerModule
	if cap <= 0 {
		return true
	}
	// Load-first to avoid the eager &moduleFindingTracker{} alloc on the common
	// (already-present) path.
	val, ok := e.caches.moduleFindingCount.Load(moduleID)
	if !ok {
		val, _ = e.caches.moduleFindingCount.LoadOrStore(moduleID, &moduleFindingTracker{})
	}
	tracker := val.(*moduleFindingTracker)
	n := tracker.count.Add(1)
	if n > int64(cap) {
		tracker.warned.Do(func() {
			zap.L().Warn("Module finding cap reached, suppressing further findings",
				zap.String("module", moduleID),
				zap.Int("cap", cap))
		})
		return false
	}
	return true
}

// admitFinding makes the finding-cap decision once for a final, post-hook
// root-cause identity. first is true only for the goroutine that owns an
// admitted identity; duplicates wait until that owner's decision is visible.
func (e *Executor) admitFinding(id, moduleID string) (first, allowed bool) {
	pending := &findingAdmission{ready: make(chan struct{})}
	actual, loaded := e.caches.emittedFindingIDs.LoadOrStore(id, pending)
	admission := actual.(*findingAdmission)
	if loaded {
		<-admission.ready
		return false, admission.allowed
	}

	admission.allowed = e.moduleFindingAllowed(moduleID)
	close(admission.ready)
	if !admission.allowed {
		// Do not retain an unbounded set of capped identities. A later retry may
		// make another (still rejected) cap decision, but can never race past it.
		e.caches.emittedFindingIDs.Delete(id)
	}
	return true, admission.allowed
}

// emitResult persists and dispatches a finding. baselineReq is an optional hint
// set when result.Request is the unchanged baseline request: it supplies a
// memoized request hash so the record-link cache lookup avoids allocating a temp
// request and re-hashing the raw bytes. It is nil for findings carrying a
// module-supplied (mutated) request.
type emissionOutcome uint8

const (
	emissionDropped emissionOutcome = iota
	emissionFinding
	emissionMerged
	emissionCandidate
	emissionObservation
)

type emissionResult struct {
	outcome emissionOutcome
	event   *output.ResultEvent
}

func (e *Executor) emitResult(ctx context.Context, result *output.ResultEvent, baselineReq *httpmsg.HttpRequest) emissionResult {
	// Run post-hooks (may modify or drop result)
	if e.hooks != nil {
		hooked, err := e.hooks.RunPostHooks(result)
		if err != nil {
			zap.L().Debug("Post-hook error", zap.Error(err))
		}
		if hooked == nil {
			return emissionResult{outcome: emissionDropped} // Post-hook dropped this result
		}
		result = hooked
	}

	result.RecordKind = result.EffectiveRecordKind()
	duplicateFinding := false
	if result.IsFinding() {
		first, allowed := e.admitFinding(result.ID(), result.ModuleID)
		duplicateFinding = !first
		// Only reportable vulnerabilities consume the finding cap. Retained
		// observations/candidates have their own module-level dedup and must not
		// crowd a later confirmed result out of the report.
		if !allowed {
			return emissionResult{outcome: emissionDropped}
		}
		if !duplicateFinding {
			e.results.Store(true)
			if e.statsTracker != nil {
				e.statsTracker.IncrementFindings()
			}
		}
	}

	// Store finding in database (if enabled) and import HTTP evidence into http_records
	if e.repo != nil {
		var recordUUIDs []string

		if result.Request != "" {
			// Resolve the request hash. Reuse the baseline request's memoized
			// ID() when the finding is the unchanged baseline (no temp-request
			// alloc, no re-hash); otherwise hash the raw bytes of the (mutated)
			// finding request.
			var reqHash string
			if baselineReq != nil {
				reqHash = baselineReq.ID()
			} else {
				reqHash = httpmsg.NewHttpRequest([]byte(result.Request)).ID()
			}

			// Look up the database record UUID
			recordUUID, exists := e.caches.requestUUIDs.Load(reqHash)

			if !exists {
				// Parse raw request to extract service info (host/port/protocol) from Host header
				var findingRR *httpmsg.HttpRequestResponse
				var parseErr error
				if result.URL != "" {
					findingRR, parseErr = httpmsg.ParseRawRequestWithURL(result.Request, result.URL)
				} else {
					findingRR, parseErr = httpmsg.ParseRawRequest(result.Request)
				}
				if parseErr != nil {
					zap.L().Debug("Failed to parse finding request, skipping http_record save", zap.Error(parseErr))
				} else {
					findingRR = findingRR.WithResponse(httpmsg.NewHttpResponse([]byte(result.Response)))
					var err error
					if e.recordWriter != nil {
						recordUUID, err = e.recordWriter.Write(ctx, findingRR, string(result.RecordKind), e.projectUUID)
					} else {
						recordUUID, err = e.repo.SaveRecord(ctx, findingRR, string(result.RecordKind), e.projectUUID)
					}
					if err != nil {
						zap.L().Warn("Failed to save finding http_record", zap.Error(err))
					} else {
						e.caches.requestUUIDs.Store(reqHash, recordUUID)
						exists = true
					}
				}
			}

			if exists {
				recordUUIDs = []string{recordUUID}
			}
		}

		// Persist via the batched finding writer when available so the worker
		// isn't blocked on a synchronous database round-trip; fall back to a
		// direct write otherwise. The record this finding links to was already
		// persisted synchronously above, so async finding persistence never
		// races ahead of its http_record.
		var saveErr error
		if e.findingWriter != nil {
			saveErr = e.findingWriter.Save(ctx, result, recordUUIDs, e.scanUUID, e.projectUUID)
		} else {
			saveErr = e.repo.SaveFinding(ctx, result, recordUUIDs, e.scanUUID, e.projectUUID)
		}
		if saveErr != nil {
			// A dropped finding is a data-loss event for the operator, not a debug
			// detail — surface it at Warn with enough context to locate the result.
			zap.L().Warn("failed to persist finding to database; finding will be missing from stored results",
				zap.String("module", result.ModuleID),
				zap.String("url", result.URL),
				zap.Error(saveErr))
		}
	}

	switch result.RecordKind {
	case output.RecordKindObservation:
		if e.cfg.OnObservation != nil {
			e.cfg.OnObservation(result)
		}
		return emissionResult{outcome: emissionObservation, event: result}
	case output.RecordKindCandidate:
		if e.cfg.OnCandidate != nil {
			e.cfg.OnCandidate(result)
		}
		return emissionResult{outcome: emissionCandidate, event: result}
	default:
		if duplicateFinding {
			return emissionResult{outcome: emissionMerged, event: result}
		}
		if e.cfg.OnResult != nil {
			e.cfg.OnResult(result)
		}
		if e.cfg.Services != nil && e.cfg.Services.Notifier != nil && !result.DisableNotify {
			if err := e.cfg.Services.Notifier.Send(result); err != nil {
				zap.L().Debug("notifier send failed for finding",
					zap.String("module", result.ModuleID), zap.Error(err))
			}
		}
		return emissionResult{outcome: emissionFinding, event: result}
	}
}

func (e *Executor) assignModuleInfo(result *output.ResultEvent, m modules.Module) {
	result.ModuleID = m.ID()

	if result.ModuleShort == "" {
		result.ModuleShort = m.ShortDescription()
	}

	if result.Info.Name == "" {
		result.Info.Name = m.Name()
	}
	// Compose the finding description: keep the module's per-finding context line
	// (the specific header/param/endpoint it set inline) as a lead, then append the
	// module's static "what it means / how it's exploited / fix" explanation block.
	// Modules that emit no inline description fall back to the block alone.
	if block := m.Description(); block != "" {
		if result.Info.Description == "" {
			result.Info.Description = block
		} else if !strings.Contains(result.Info.Description, block) {
			result.Info.Description = result.Info.Description + "\n\n" + block
		}
	}
	// Propagate the module's classification tags onto the finding. Before this,
	// native-module findings carried no tags at all (only known-issue-scan set them).
	// Copy rather than alias: m.Tags() returns the module's own backing slice, shared
	// across every finding it produces and persisted to the DB, so a later in-place
	// edit on one finding's tags must not corrupt the module or its sibling findings.
	if len(result.Info.Tags) == 0 {
		if tags := m.Tags(); len(tags) > 0 {
			result.Info.Tags = append([]string(nil), tags...)
		}
	}
	if result.Info.Severity == severity.Undefined {
		result.Info.Severity = m.Severity()
	}
	if result.Info.Confidence == severity.ConfidenceUndefined {
		result.Info.Confidence = m.Confidence()
	}

	if result.Type == "" {
		result.Type = "http"
	}

	if result.Matched == "" && result.URL != "" {
		result.Matched = result.URL
	}

	if result.URL == "" && result.Request != "" {
		result.URL = httpmsg.GetURLFromRequest("https", []byte(result.Request))
		if result.Matched == "" {
			result.Matched = result.URL
		}
	}

	if result.Host == "" {
		e.fillHostFromResult(result)
	}
}

func (e *Executor) fillHostFromResult(result *output.ResultEvent) {
	if result.URL != "" {
		urlx, err := urlutil.ParseURL(result.URL, true)
		if err == nil {
			result.Host = urlx.Host
			result.Scheme = urlx.Scheme
			return
		}
	}
	if result.Request != "" {
		host, _ := httpmsg.GetHeaderValue([]byte(result.Request), "Host")
		if host != "" {
			result.Host = host
			return
		}
	}
	result.Host = "unknown"
}

func (e *Executor) recoverFromPanic(ctx string) {
	if r := recover(); r != nil {
		stack := make([]byte, 4096)
		length := goruntime.Stack(stack, false)
		stackTrace := string(stack[:length])

		errorMessage := fmt.Sprintf(
			"Recovered from panic in %s: %+v\nStack Trace:\n%s",
			ctx, r, stackTrace,
		)
		zap.L().Error(errorMessage)

		if e.cfg.Services != nil && e.cfg.Services.Notifier != nil {
			_ = e.cfg.Services.Notifier.SendRaw(errorMessage)
		}
	}
}
