package core

import (
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
	"github.com/vigolium/vigolium/pkg/utils/textutil"
	"go.uber.org/zap"
)

// processResults finalizes and emits one module call's results. ip is the
// insertion point the call scanned (nil for host-, request-scope and passive
// modules); it and item supply the replay context `finding verify` reads back.
func (e *Executor) processResults(ctx context.Context, results []*output.ResultEvent, m modules.Module, item *httpmsg.HttpRequestResponse, ip httpmsg.InsertionPoint) {
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
		// The item's live response object, carried alongside baselineReq when the
		// finding adopts the baseline exchange. It differs from
		// NewHttpResponse([]byte(result.Response)) in one way that matters: it
		// carries the MEASURED round-trip duration, which raw bytes cannot. A
		// finding-evidence record dedups onto (or becomes) the item's own record,
		// so rebuilding from bytes here is how response_time_ms got lost on every
		// record a passive module happened to report on.
		var baselineResp *httpmsg.HttpResponse
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
					baselineResp = item.Response()
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

		e.setReplayContext(result, item, ip)

		emitted := e.emitResult(ctx, result, baselineReq, baselineResp)

		// Cross-module finding dedup: mark (URL, param, vuln_class) as found
		// so that lower-priority modules with the same vuln class can skip.
		if emitted.outcome == emissionFinding && emitted.event != nil {
			if vc, ok := m.(modules.VulnClassifier); ok && e.scanCtx.ParamDedupEnabled() {
				param := emitted.event.FuzzingParameter
				if class := vc.VulnClass(); param != "" && class != "" {
					e.scanCtx.ParamFindings.MarkFound(modkit.ParamFindingKeyFromResult(emitted.event), param, class)
				}
			}
		}
	}
}

// reconfirmBodyDifferential re-confirms a candidate finding by replaying its
// payload-applied request and comparing it against a clean (no-payload)
// baseline, for modules that opt in via modules.BodyDifferentialConfirmable or,
// per result, modules.ResultDifferentialConfirmable. Returns true to keep (emit)
// the finding, false to drop it. The comparison itself is
// modkit.ReconfirmFinding, the same call module tests use to predict this
// decision.
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
	if !modules.ConfirmsByBodyDifferential(m, result) {
		return true // module (or this result) did not opt in
	}
	if e.httpClient == nil {
		return true // not enough context to re-confirm
	}

	res := modkit.ReconfirmFinding(e.httpClient.WithContext(ctx), item, result.Request)
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

// maxStoredPayload bounds ResultEvent.Payload as derived by the executor: the
// payload is a replay hint, and the full request is already on the finding.
const maxStoredPayload = 4096

// setReplayContext records what `finding verify` needs to re-run the module:
// the stored record of the scanned item, the insertion point and the value
// injected there. Values a module (or extension) set itself are kept.
func (e *Executor) setReplayContext(result *output.ResultEvent, item *httpmsg.HttpRequestResponse, ip httpmsg.InsertionPoint) {
	if item == nil || item.Request() == nil {
		return
	}
	// The unmutated item's URL is the finding's v2 identity location
	// (output.ResultEvent.IdentityKey) and the scheme for a URL rebuilt from
	// the request.
	if result.BaseURL == "" {
		if u, err := item.URL(); err == nil && u != nil {
			result.BaseURL = u.String()
		}
	}
	if result.OriginRecordUUID == "" && e.caches.requestUUIDs != nil {
		result.OriginRecordUUID = e.ResolveRequestUUID(item.Request().ID())
	}
	if ip == nil {
		return
	}
	if result.FuzzingParameter == "" {
		result.FuzzingParameter = ip.Name()
	}
	if result.FuzzingParameter != ip.Name() {
		return // the module reported another point; don't pair it with this one
	}
	if result.InsertionPointType == "" {
		result.InsertionPointType = ip.Type().String()
	}
	if result.Payload == "" && result.Request != "" && result.Request != string(item.Request().Raw()) {
		result.Payload = injectedValue(result.Request, ip)
	}
}

// injectedValue reads the value at ip's position in the mutated raw request.
// Empty when the request does not parse or no longer carries the point.
func injectedValue(rawRequest string, ip httpmsg.InsertionPoint) string {
	pts, err := httpmsg.CreateAllInsertionPoints([]byte(rawRequest), true)
	if err != nil {
		return ""
	}
	found := httpmsg.FindInsertionPoint(pts, ip.Type().String(), ip.Name())
	if found == nil || found.BaseValue() == ip.BaseValue() {
		return ""
	}
	v := found.BaseValue()
	return v[:textutil.CutIndex(v, maxStoredPayload)]
}

// moduleFindingAllowed returns true if the module has not exceeded its finding
// cap. id is the finding's identity (output.ResultEvent.IdentityKey hashed), so
// the cap and its drop count are per distinct finding, not per emission.
func (e *Executor) moduleFindingAllowed(id, moduleID string) bool {
	cap := e.cfg.MaxFindingsPerModule
	if cap <= 0 {
		return true
	}
	counts := &e.admission().counts
	// Load-first to avoid the eager &moduleFindingTracker{} alloc on the common
	// (already-present) path.
	val, ok := counts.Load(moduleID)
	if !ok {
		val, _ = counts.LoadOrStore(moduleID, &moduleFindingTracker{})
	}
	tracker := val.(*moduleFindingTracker)
	n := tracker.count.Add(1)
	if n > int64(cap) {
		e.admission().noteCapped(id, tracker)
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
	ids := &e.admission().ids
	pending := &findingAdmission{ready: make(chan struct{})}
	actual, loaded := ids.LoadOrStore(id, pending)
	admission := actual.(*findingAdmission)
	if loaded {
		<-admission.ready
		return false, admission.allowed
	}

	admission.allowed = e.moduleFindingAllowed(id, moduleID)
	close(admission.ready)
	if !admission.allowed {
		// Do not retain an unbounded set of capped identities. A later retry may
		// make another (still rejected) cap decision, but can never race past it.
		ids.Delete(id)
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

func (e *Executor) emitResult(ctx context.Context, result *output.ResultEvent, baselineReq *httpmsg.HttpRequest, baselineResp *httpmsg.HttpResponse) emissionResult {
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
	if result.IsFinding() {
		clampTentativeSeverity(result)
	}
	duplicateFinding := false
	insertedNew := false // the direct save wrote a NEW finding row (SAFE-12)
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
					findingRR = findingRR.WithResponse(findingResponse(result.Response, baselineResp))
					// RecordKind, not the executor's own source: this row is the
					// finding's evidence. Normalized by EffectiveRecordKind above,
					// so never empty. Zero lineage — evidence is not part of a
					// chain and names no submitted target of its own.
					//
					// Assigned, not redeclared: recordUUID is the outer variable
					// the finding links through below.
					var err error
					recordUUID, err = e.writeRecord(ctx, findingRR, string(result.RecordKind), database.RecordLineage{})
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
			// New-finding notifications come from the writer once the row is
			// known to be new (SAFE-12); see notifyNewFindings.
			e.notifyNewFindings()
			saveErr = e.findingWriter.Save(ctx, result, recordUUIDs, e.scanUUID, e.projectUUID)
		} else {
			insertedNew, saveErr = e.repo.SaveFindingInserted(ctx, result, recordUUIDs, e.scanUUID, e.projectUUID)
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
		// Notify only on NEW findings (SAFE-12): a re-scan used to re-notify
		// every known and dismissed finding. With a database the decision is
		// the save's: the writer path notifies from its insert callback, the
		// direct path when the row was inserted. Without one, every finding.
		if e.repo == nil || (e.findingWriter == nil && insertedNew) {
			e.sendFindingNotification(result)
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
		result.URL = httpmsg.GetURLFromRequest(resultScheme(result), []byte(result.Request))
		if result.Matched == "" {
			result.Matched = result.URL
		}
	}

	if result.Host == "" {
		e.fillHostFromResult(result)
	}
}

// resultScheme is the scheme for a URL rebuilt from the finding's request: the
// scanned item's (BaseURL), else the event's own, else https.
func resultScheme(result *output.ResultEvent) string {
	if result.Scheme != "" {
		return result.Scheme
	}
	if i := strings.Index(result.BaseURL, "://"); i > 0 {
		return strings.ToLower(result.BaseURL[:i])
	}
	return "https"
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

// reportPanic logs a recovered panic with its stack trace and forwards it to the
// operator notifier. label identifies where it happened (e.g. "processItem" or
// "module <id>"). Shared by recoverFromPanicInto and the per-module guard so the
// stack-capture/formatting/notify logic lives in exactly one place.
func (e *Executor) reportPanic(label string, r any) {
	stack := make([]byte, 4096)
	length := goruntime.Stack(stack, false)
	errorMessage := fmt.Sprintf(
		"Recovered from panic in %s: %+v\nStack Trace:\n%s",
		label, r, string(stack[:length]),
	)
	zap.L().Error(errorMessage)

	if e.cfg.Services != nil && e.cfg.Services.Notifier != nil {
		_ = e.cfg.Services.Notifier.SendRaw(errorMessage)
	}
}

// recoverFromPanicInto recovers a panic, reports it, and records that it
// happened through recovered.
//
// The flag is an out-parameter rather than a return value because this runs as a
// deferred call, where a return value is discarded. Its callers need the
// fact: a work item whose processing panicked must still be acknowledged, or the
// same poison item is re-served on every later run and the durable cursor never
// moves past it.
func (e *Executor) recoverFromPanicInto(label string, recovered *bool) {
	if r := recover(); r != nil {
		e.reportPanic(label, r)
		if recovered != nil {
			*recovered = true
		}
	}
}

// runScanFnGuarded runs a module scan function, converting a panic into an
// error value instead of letting it unwind. The active/passive timeout wrappers
// invoke scanFn from a raw goroutine that neither the worker's nor the active
// task's panic recovery can reach, so an unrecovered panic there crashes the
// whole process. Recovering here keeps a single defective module (or a parser
// panic on adversarial input) from taking down a long-running server, while
// still surfacing the failure through the normal (nil, err) result path so the
// watchdog goroutine completes its channel send and slot release.
func (e *Executor) runScanFnGuarded(
	ctx context.Context,
	moduleID string,
	fn func(context.Context) ([]*output.ResultEvent, error),
) (events []*output.ResultEvent, err error) {
	defer func() {
		if r := recover(); r != nil {
			e.reportPanic("module "+moduleID, r)
			events = nil
			err = &modulePanicError{moduleID: moduleID, value: r}
		}
	}()
	return fn(ctx)
}

// findingResponse returns the HttpResponse to store with a finding's evidence
// record. It prefers the live baseline object when that object IS the finding's
// response, because only the live one carries the measured round-trip duration —
// rebuilding from result.Response yields identical bytes and a zero duration,
// and that record then wins the dedup against the item's own record, erasing
// the timing for the whole exchange.
//
// The byte comparison is the safety check, not an optimization: a module may
// have replaced result.Response after the backfill, and pairing a stale
// baseline response with it would record an exchange that never happened.
func findingResponse(raw string, baseline *httpmsg.HttpResponse) *httpmsg.HttpResponse {
	if baseline != nil && string(baseline.Raw()) == raw {
		return baseline
	}
	return httpmsg.NewHttpResponse([]byte(raw))
}

// clampTentativeSeverity enforces the severity rule at emit time: a Tentative
// finding is an unproven oracle and files at Suspect at most. The module's
// requested severity is kept as Metadata["claimed_severity"]. Modules on
// modules.TentativeSeverityWaivers are exempt (RES-7).
func clampTentativeSeverity(result *output.ResultEvent) {
	if result == nil || result.Info.Confidence != severity.Tentative || result.Info.Severity <= severity.Suspect {
		return
	}
	if modules.TentativeSeverityWaived(result.ModuleID) {
		return
	}
	if result.Metadata == nil {
		result.Metadata = map[string]any{}
	}
	if _, set := result.Metadata["claimed_severity"]; !set {
		result.Metadata["claimed_severity"] = result.Info.Severity.String()
	}
	result.Info.Severity = severity.Suspect
}

// sendFindingNotification forwards a finding to the operator notifier.
func (e *Executor) sendFindingNotification(result *output.ResultEvent) {
	if result == nil || result.DisableNotify || e.cfg.Services == nil || e.cfg.Services.Notifier == nil {
		return
	}
	if err := e.cfg.Services.Notifier.Send(result); err != nil {
		zap.L().Debug("notifier send failed for finding",
			zap.String("module", result.ModuleID), zap.Error(err))
	}
}

// notifyNewFindings points the finding writer's new-row callback at this
// executor's notifier (idempotent; every executor of a phase shares the
// writer and the notifier).
func (e *Executor) notifyNewFindings() {
	if e.findingWriter == nil || e.cfg.Services == nil || e.cfg.Services.Notifier == nil {
		return
	}
	e.notifyOnce.Do(func() {
		e.findingWriter.SetOnInserted(e.sendFindingNotification)
	})
}
