package core

import (
	"context"
	"sync"

	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"go.uber.org/zap"
)

func (e *Executor) runActivePerHost(ctx context.Context, reqClient *http.Requester, item *httpmsg.HttpRequestResponse, filter *moduleFilter, elig *requestEligibility, t *itemTracker) {
	if len(e.perHostActive) == 0 {
		return
	}

	origin := originKeyFromItem(item)

	for _, module := range e.perHostActive {
		if !filter.allows(module.ID()) {
			continue
		}
		if !e.passesTechFilter(module, item) {
			continue
		}
		e.moduleMetrics.MarkConsidered(module.ID())
		if !activeModuleCanProcess(module, item, elig) {
			continue
		}

		// Claim this (module, origin) pair — skip if another worker already claimed
		// it. ContainsOrAdd is atomic (single lock) so two concurrent workers
		// can't both win the claim; ok==true means the pair was already claimed.
		claimKey := hostClaimKey{moduleID: module.ID(), origin: origin}
		if ok, _ := e.caches.perHostActiveClaimed.ContainsOrAdd(claimKey, struct{}{}); ok {
			continue
		}

		mod := module // capture loop variable
		e.goActiveTask(ctx, t, func(releaseSlot func()) {
			results, completed := e.runActiveWithTimeout(ctx,
				func(runCtx context.Context, client *http.Requester) ([]*output.ResultEvent, error) {
					if contextual, ok := mod.(modules.ContextualActiveModule); ok {
						return contextual.ScanPerHostContext(runCtx, item, client, e.scanCtx)
					}
					return mod.ScanPerHost(item, client, e.scanCtx)
				},
				mod, item, reqClient, releaseSlot, 0)
			if completed && len(results) > 0 {
				e.processResults(ctx, results, mod, item, nil)
			}
		})
	}
}

func (e *Executor) runActivePerRequest(ctx context.Context, reqClient *http.Requester, item *httpmsg.HttpRequestResponse, filter *moduleFilter, elig *requestEligibility, t *itemTracker) {
	if len(e.perRequestActive) == 0 {
		return
	}

	// A ScanPerRequest module loops over every insertion point in one call, so its
	// timeout is scaled by the point count (see runActiveWithTimeout). Compute it
	// once per item — the count is shared across all per-request modules.
	workUnits := e.itemInsertionPointCount(item)

	for _, module := range e.perRequestActive {
		if !filter.allows(module.ID()) {
			continue
		}
		if !e.passesTechFilter(module, item) {
			continue
		}
		e.moduleMetrics.MarkConsidered(module.ID())
		if !activeModuleCanProcess(module, item, elig) {
			continue
		}

		mod := module // capture loop variable
		e.goActiveTask(ctx, t, func(releaseSlot func()) {
			results, completed := e.runActiveWithTimeout(ctx,
				func(runCtx context.Context, client *http.Requester) ([]*output.ResultEvent, error) {
					if contextual, ok := mod.(modules.ContextualActiveModule); ok {
						return contextual.ScanPerRequestContext(runCtx, item, client, e.scanCtx)
					}
					return mod.ScanPerRequest(item, client, e.scanCtx)
				},
				mod, item, reqClient, releaseSlot, workUnits)
			if completed && len(results) > 0 {
				e.processResults(ctx, results, mod, item, nil)
			}
		})
	}
}

// itemInsertionPointCount returns the number of insertion points a whole-request
// module will cover for item, used to scale that module's per-module timeout. It
// goes through the shared insertion-point provider, which hits/populates the same
// ipCache the per-insertion-point stage uses, so the request is parsed at most once.
// Returns 0 when the request is empty or unparseable, leaving the base timeout unscaled.
func (e *Executor) itemInsertionPointCount(item *httpmsg.HttpRequestResponse) int {
	if item == nil || item.Request() == nil || len(item.Request().Raw()) == 0 {
		return 0
	}
	pts, err := e.scanCtx.GetInsertionPoints(item.Request().Raw(), item.Request().ID(), true)
	if err != nil {
		return 0
	}
	return len(pts)
}

func (e *Executor) runActivePerInsertionPoint(ctx context.Context, reqClient *http.Requester, item *httpmsg.HttpRequestResponse, filter *moduleFilter, elig *requestEligibility, t *itemTracker) {
	if len(e.perIPActive) == 0 {
		return
	}

	if item.Request() == nil || len(item.Request().Raw()) == 0 {
		return
	}

	// Cache lookup by request hash (same SHA-256 used by HttpRequest.ID()), through
	// the same accessor the module-facing provider uses so both agree on the key.
	allPoints, err := e.caches.ipCache.GetOrCompute(item.Request().Raw(), item.Request().ID(), true)
	if err != nil {
		zap.L().Debug("Failed to create insertion points", zap.Error(err))
		return
	}

	// Pre-compute the registry location key for cross-module finding dedup
	// (the same key modules use via ScanContext.ParamAlreadyFound).
	paramDedup := e.scanCtx.ParamDedupEnabled()
	itemKey := ""
	if paramDedup {
		itemKey = modkit.ParamFindingKey(item)
	}

	// Module-outer, insertion-point-inner: the module-level gates
	// (filter / tech-filter / MarkConsidered / CanProcess) don't depend on the
	// insertion point, so evaluate them once per module rather than once per
	// (module × insertion-point). Only the type check and the cross-module
	// vuln-class dedup are point-dependent and stay in the inner loop.
	for _, module := range e.perIPActive {
		if !filter.allows(module.ID()) {
			continue
		}
		if !e.passesTechFilter(module, item) {
			continue
		}
		e.moduleMetrics.MarkConsidered(module.ID())
		if !activeModuleCanProcess(module, item, elig) {
			continue
		}

		allowedTypes := module.AllowedInsertionPointTypes()
		vulnClass := ""
		if paramDedup {
			vulnClass = modules.ModuleVulnClass(module)
		}

		for _, ip := range allPoints {
			if !allowedTypes.Contains(ip.Type()) {
				continue
			}
			if ipFilter := e.cfg.InsertionPointFilter; ipFilter != nil && !ipFilter(ip) {
				continue
			}

			// Cross-module dedup: skip if another module already found this vuln
			// class on this param.
			if vulnClass != "" && e.scanCtx.ParamFindings.HasFinding(itemKey, ip.Name(), vulnClass) {
				continue
			}

			mod, pt := module, ip // capture loop variables
			// A point that lives in a header (or one cookie) keeps the module's
			// value over the session's / -H copy (MISS-11).
			ptClient := reqClient.WithPreservedHeaders(httpmsg.OwnedHeaderKeysOf(pt))
			e.goActiveTask(ctx, t, func(releaseSlot func()) {
				// Re-check when the task actually runs: it may have waited on the
				// active-task semaphore while a same-class module confirmed this
				// param, and the dispatch-time check above could not see that.
				if vulnClass != "" && e.scanCtx.ParamFindings.HasFinding(itemKey, pt.Name(), vulnClass) {
					releaseSlot()
					return
				}
				results, completed := e.runActiveWithTimeout(ctx,
					func(runCtx context.Context, client *http.Requester) ([]*output.ResultEvent, error) {
						if contextual, ok := mod.(modules.ContextualActiveModule); ok {
							return contextual.ScanPerInsertionPointContext(runCtx, item, pt, client, e.scanCtx)
						}
						return mod.ScanPerInsertionPoint(item, pt, client, e.scanCtx)
					},
					mod, item, ptClient, releaseSlot, 0)
				if completed && len(results) > 0 {
					e.processResults(ctx, results, mod, item, pt)
				}
			})
		}
	}
}

// goActiveTask runs fn as a detached task of t's item, gated by the global
// active-task semaphore. Semaphore acquisition is context-aware: if ctx is
// cancelled (scan shutdown or max-duration timeout) while every slot is
// occupied, the task is skipped instead of blocking the dispatcher until a slot
// frees up.
//
// The task holds a reference on t for as long as it runs, so the item is
// acknowledged only after its last task returns; nobody waits on it here. The
// scan-level taskWG lets Execute join every task at shutdown.
//
// Slot release is NOT tied to fn returning. fn hands releaseSlot to
// runActiveWithTimeout, which frees the slot only when the module's real work
// finishes — even if that work outlives a per-module timeout the wrapper gave up
// waiting for. Releasing on fn return instead would let the pool admit
// replacement tasks while abandoned scans still hold connections, so the
// concurrency cap would understate true in-flight work. sync.Once keeps the
// release idempotent so a stray double-call can never over-drain the semaphore.
//
// A panic in fn is recovered here (a detached goroutine has no caller to unwind
// to): it is reported, the slot is released if fn had not handed it off yet,
// and the item is marked so it is acknowledged anyway — the poison-item rule.
func (e *Executor) goActiveTask(ctx context.Context, t *itemTracker, fn func(releaseSlot func())) {
	select {
	case e.pool.activeTaskSem <- struct{}{}:
	case <-ctx.Done():
		return
	}
	var once sync.Once
	releaseSlot := func() { once.Do(func() { <-e.pool.activeTaskSem }) }
	t.acquire()
	e.pool.taskWG.Add(1)
	go func() {
		defer e.pool.taskWG.Done()
		defer t.done()
		var panicked bool
		defer func() {
			if panicked {
				t.panicked.Store(true)
				releaseSlot()
			}
		}()
		defer e.recoverFromPanicInto("activeTask", &panicked)
		fn(releaseSlot)
	}()
}

// runActiveStage dispatches every eligible active task for req as a detached
// task of t and returns without waiting for them.
func (e *Executor) runActiveStage(ctx context.Context, t *itemTracker, req *httpmsg.HttpRequestResponse, filter *moduleFilter, elig *requestEligibility) {
	// One context-bound requester clone per item, handed to every active-module
	// task below — they all run under the same PHASE ctx. Binding the context once
	// here keeps that work off the hottest fan-out loop; runActiveWithTimeout still
	// takes a second shallow clone per call to attach that call's abandon flag,
	// which is the minimum needed to carry per-call state into a module that takes
	// a *http.Requester.
	// Bound to the phase context, NOT any per-module timeout, so the shared request
	// clusterer isn't poisoned by one module's timeout (see runActiveWithTimeout).
	var reqClient *http.Requester
	if e.httpClient != nil {
		reqClient = e.httpClient.WithContext(ctx)
	}

	e.runActivePerHost(ctx, reqClient, req, filter, elig, t)
	e.runActivePerRequest(ctx, reqClient, req, filter, elig, t)
	e.runActivePerInsertionPoint(ctx, reqClient, req, filter, elig, t)
}
