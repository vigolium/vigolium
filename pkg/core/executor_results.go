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
		if !e.moduleFindingAllowed(m.ID()) {
			continue
		}
		result.ModuleType = moduleType
		result.FindingSource = database.FindingSourceDynamicAssessment
		e.assignModuleInfo(result, m)

		// Backfill request/response from original item when the module
		// did not populate them so the finding always carries raw data
		// and can be linked to an http_record.
		if item != nil {
			if result.Request == "" && item.Request() != nil {
				result.Request = string(item.Request().Raw())
			}
			if result.Response == "" && item.HasResponse() {
				result.Response = string(item.Response().Raw())
			}
		}

		// Body-differential safety net: for modules that opt in, re-confirm the
		// payload-vs-baseline difference before reporting. Drops the finding when
		// no real, reproducible differential exists (status flip, dynamic noise,
		// or no effect) — the most common false-positive causes.
		if !e.reconfirmBodyDifferential(ctx, m, result, item) {
			continue
		}

		e.emitResult(ctx, result)

		// Cross-module finding dedup: mark (URL, param, vuln_class) as found
		// so that lower-priority modules with the same vuln class can skip.
		if vc, ok := m.(modules.VulnClassifier); ok && e.scanCtx != nil && e.scanCtx.ParamFindings != nil {
			param := result.FuzzingParameter
			if param != "" {
				e.scanCtx.ParamFindings.MarkFound(paramFindingLocationKeyFromResult(result), param, vc.VulnClass())
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
	val, _ := e.caches.moduleFindingCount.LoadOrStore(moduleID, &moduleFindingTracker{})
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

func (e *Executor) emitResult(ctx context.Context, result *output.ResultEvent) {
	// Run post-hooks (may modify or drop result)
	if e.hooks != nil {
		hooked, err := e.hooks.RunPostHooks(result)
		if err != nil {
			zap.L().Debug("Post-hook error", zap.Error(err))
		}
		if hooked == nil {
			return // Post-hook dropped this result
		}
		result = hooked
	}

	e.results.Store(true)
	if e.statsTracker != nil {
		e.statsTracker.IncrementFindings()
	}

	// Store finding in database (if enabled) and import HTTP evidence into http_records
	if e.repo != nil {
		var recordUUIDs []string

		if result.Request != "" {
			// Create a temporary HttpRequest to get the hash
			tempReq := httpmsg.NewHttpRequest([]byte(result.Request))
			reqHash := tempReq.ID()

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
						recordUUID, err = e.recordWriter.Write(ctx, findingRR, "finding", e.projectUUID)
					} else {
						recordUUID, err = e.repo.SaveRecord(ctx, findingRR, "finding", e.projectUUID)
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

	if e.cfg.OnResult != nil {
		e.cfg.OnResult(result)
	}

	if e.cfg.Services != nil && e.cfg.Services.Notifier != nil && !result.DisableNotify {
		if err := e.cfg.Services.Notifier.Send(result); err != nil {
			zap.L().Debug("notifier send failed for finding",
				zap.String("module", result.ModuleID), zap.Error(err))
		}
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
