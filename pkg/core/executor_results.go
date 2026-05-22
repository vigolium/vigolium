package core

import (
	"context"
	"fmt"
	goruntime "runtime"

	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules"
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

// moduleFindingAllowed returns true if the module has not exceeded its finding cap.
func (e *Executor) moduleFindingAllowed(moduleID string) bool {
	cap := e.cfg.MaxFindingsPerModule
	if cap <= 0 {
		return true
	}
	val, _ := e.moduleFindingCount.LoadOrStore(moduleID, &moduleFindingTracker{})
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
			recordUUID, exists := e.requestUUIDs.Load(reqHash)

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
						e.requestUUIDs.Store(reqHash, recordUUID)
						exists = true
					}
				}
			}

			if exists {
				recordUUIDs = []string{recordUUID}
			}
		}

		if err := e.repo.SaveFinding(ctx, result, recordUUIDs, e.scanUUID, e.projectUUID); err != nil {
			zap.L().Debug("Failed to save finding to database", zap.Error(err))
		}
	}

	if e.cfg.OnResult != nil {
		e.cfg.OnResult(result)
	}

	if e.cfg.Services != nil && e.cfg.Services.Notifier != nil && !result.DisableNotify {
		_ = e.cfg.Services.Notifier.Send(result)
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
	if result.Info.Description == "" {
		result.Info.Description = m.Description()
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
