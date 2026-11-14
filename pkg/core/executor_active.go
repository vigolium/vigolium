package core

import (
	"context"

	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"go.uber.org/zap"
)

func (e *Executor) runActivePerHost(ctx context.Context, reqClient *http.Requester, item *httpmsg.HttpRequestResponse, filter *moduleFilter, elig *requestEligibility, t *itemTracker, hostKey string) {
	if len(e.perHostActive) == 0 {
		return
	}

	origin := httpmsg.OriginKey(item)

	for _, module := range e.perHostActive {
		if !e.activeEligible(module, item, filter, elig, t) {
			continue
		}
		// Claim this (module, origin) pair — skip if another worker already did.
		claimKey := hostClaimKey{moduleID: module.ID(), origin: origin}
		if !e.caches.hostClaims.claimActive(claimKey) {
			continue
		}

		mod := module // capture loop variable
		e.goModuleTask(ctx, t, hostKey, mod.ID(), func(releaseSlot func()) callOutcome {
			o := e.runActiveWithTimeout(ctx,
				func(runCtx context.Context, client *http.Requester) ([]*output.ResultEvent, error) {
					if contextual, ok := mod.(modules.ContextualActiveModule); ok {
						return contextual.ScanPerHostContext(runCtx, item, client, e.scanCtx)
					}
					return mod.ScanPerHost(item, client, e.scanCtx)
				},
				mod, item, reqClient, releaseSlot, 0)
			if o.failedTransiently() && ctx.Err() == nil {
				e.caches.hostClaims.releaseActive(claimKey)
			}
			e.deliverCall(ctx, o, mod, item, nil)
			return o
		})
	}
}

// activeEligible applies the module-level gates every active stage shares —
// the module filter and the record's stored coverage, the tech filter and
// CanProcess — marking the module considered and counting the skip reason.
func (e *Executor) activeEligible(module modules.ActiveModule, item *httpmsg.HttpRequestResponse, filter *moduleFilter, elig *requestEligibility, t *itemTracker) bool {
	id := module.ID()
	if !filter.allows(id) || e.moduleDone(t.item, id) {
		return false
	}
	if !e.passesTechFilter(module, item) {
		e.noteModuleSkip(id, SkipReasonTechFilter)
		return false
	}
	e.moduleMetrics.MarkConsidered(id)
	if !activeModuleCanProcess(module, item, elig) {
		e.noteModuleSkip(id, SkipReasonCannotProcess)
		return false
	}
	return true
}

func (e *Executor) runActivePerRequest(ctx context.Context, reqClient *http.Requester, item *httpmsg.HttpRequestResponse, filter *moduleFilter, elig *requestEligibility, t *itemTracker, hostKey string) {
	if len(e.perRequestActive) == 0 {
		return
	}

	// A ScanPerRequest module loops over every insertion point in one call, so its
	// timeout is scaled by the point count (see runActiveWithTimeout). Compute it
	// once per item — the count is shared across all per-request modules.
	workUnits := e.itemInsertionPointCount(item)

	for _, module := range e.perRequestActive {
		if !e.activeEligible(module, item, filter, elig, t) {
			continue
		}

		mod := module // capture loop variable
		e.goModuleTask(ctx, t, hostKey, mod.ID(), func(releaseSlot func()) callOutcome {
			o := e.runActiveWithTimeout(ctx,
				func(runCtx context.Context, client *http.Requester) ([]*output.ResultEvent, error) {
					if contextual, ok := mod.(modules.ContextualActiveModule); ok {
						return contextual.ScanPerRequestContext(runCtx, item, client, e.scanCtx)
					}
					return mod.ScanPerRequest(item, client, e.scanCtx)
				},
				mod, item, reqClient, releaseSlot, workUnits)
			e.deliverCall(ctx, o, mod, item, nil)
			return o
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

func (e *Executor) runActivePerInsertionPoint(ctx context.Context, reqClient *http.Requester, item *httpmsg.HttpRequestResponse, filter *moduleFilter, elig *requestEligibility, t *itemTracker, hostKey string) {
	if len(e.perIPActive) == 0 {
		return
	}

	if item.Request() == nil || len(item.Request().Raw()) == 0 {
		return
	}

	// Cache lookup by request hash (same SHA-256 used by HttpRequest.ID()), through
	// the same accessor the module-facing provider uses so both agree on the key.
	// The full set, opt-in name/entire-body points included: each module's
	// allowed types decide (AllInsertionPointTypes excludes them).
	allPoints, err := e.caches.ipCache.GetOrComputeAll(item.Request().Raw(), item.Request().ID(), true)
	if err != nil {
		zap.L().Debug("Failed to create insertion points", zap.Error(err))
		return
	}

	origin := httpmsg.OriginKey(item)

	// Pre-compute the registry location key for cross-module finding dedup
	// (the same key modules use via ScanContext.ParamAlreadyFound).
	paramDedup := e.scanCtx.ParamDedupEnabled()
	itemKey := ""
	if paramDedup {
		itemKey = modkit.ParamFindingKey(item)
	}

	// Per-point state shared by every module: the header class the gate reads
	// (classified once per point, not per module × point) and the requester
	// that keeps a header / cookie point's value over the session's / -H copy
	// (built on first use).
	headerClasses := make([]infra.HeaderClass, len(allPoints))
	for i, ip := range allPoints {
		if ip.Type() == httpmsg.INS_HEADER {
			headerClasses[i] = infra.ClassifyHeader(ip.Name())
		}
	}
	ptClients := make([]*http.Requester, len(allPoints))
	pointClient := func(i int) *http.Requester {
		if ptClients[i] == nil {
			ptClients[i] = reqClient.WithPreservedHeaders(httpmsg.OwnedHeaderKeysOf(allPoints[i]))
		}
		return ptClients[i]
	}

	// Module-outer, insertion-point-inner: the module-level gates don't depend
	// on the insertion point, so evaluate them once per module rather than once
	// per (module × insertion-point). Only the type check, the cross-module
	// vuln-class dedup and the header gate are point-dependent.
	for _, module := range e.perIPActive {
		if !e.activeEligible(module, item, filter, elig, t) {
			continue
		}

		allowedTypes := module.AllowedInsertionPointTypes()
		gateClass := modules.ModuleVulnClass(module)
		vulnClass := ""
		if paramDedup {
			vulnClass = gateClass
		}

		var ipTypeSkips int64
		for i, ip := range allPoints {
			if !allowedTypes.Contains(ip.Type()) {
				if !httpmsg.IsExtraInsertionPointType(ip.Type()) {
					ipTypeSkips++
				}
				continue
			}
			if ipFilter := e.cfg.InsertionPointFilter; ipFilter != nil && !ipFilter(ip) {
				continue
			}

			// Cross-module dedup: skip if another module already found this vuln
			// class on this param.
			if vulnClass != "" && e.scanCtx.ParamFindings.HasFinding(itemKey, ip.Name(), vulnClass) {
				e.noteModuleSkip(module.ID(), SkipReasonParamAlreadyFound)
				continue
			}

			// Header gate: noise headers never, headers outside the module's
			// class interest never, logged/negotiation/routing headers once per
			// (origin, module, header).
			gate := modkit.GateHeaderPoint(e.scanCtx, module, gateClass, origin, ip, headerClasses[i])
			if !gate.Allow {
				e.noteModuleSkip(module.ID(), SkipReasonHeaderGated)
				continue
			}
			claimed := gate.Claimed

			mod, pt, ptClient := module, ip, pointClient(i) // capture loop variables
			e.goModuleTask(ctx, t, hostKey, mod.ID(), func(releaseSlot func()) callOutcome {
				// Re-check when the task actually runs: it may have waited on the
				// scheduler queue while a same-class module confirmed this
				// param, and the dispatch-time check above could not see that.
				if vulnClass != "" && e.scanCtx.ParamFindings.HasFinding(itemKey, pt.Name(), vulnClass) {
					e.noteModuleSkip(mod.ID(), SkipReasonParamAlreadyFound)
					releaseSlot()
					return callOutcome{completed: true}
				}
				// Reflection gate: a module whose oracle needs the value
				// reflected runs only when the point's shared canary probe saw it
				// come back. Fails open on a probe error, a blocked probe or a
				// WAF-fronted host.
				if e.reflectionGateSkips(ctx, mod, item, pt, reqClient) {
					e.noteModuleSkip(mod.ID(), SkipReasonCannotProcess)
					releaseSlot()
					return callOutcome{completed: true}
				}
				o := e.runActiveWithTimeout(ctx,
					func(runCtx context.Context, client *http.Requester) ([]*output.ResultEvent, error) {
						if contextual, ok := mod.(modules.ContextualActiveModule); ok {
							return contextual.ScanPerInsertionPointContext(runCtx, item, pt, client, e.scanCtx)
						}
						return mod.ScanPerInsertionPoint(item, pt, client, e.scanCtx)
					},
					mod, item, ptClient, releaseSlot, 0)
				// A once-per-host header claim taken for a call that did not
				// complete goes back, so the header is tested on a later record.
				if claimed && !o.completed {
					e.scanCtx.ReleaseHeaderClaim(origin, mod.ID(), pt.Name())
				}
				e.deliverCall(ctx, o, mod, item, pt)
				return o
			})
		}
		e.moduleSkips.add(module.ID(), SkipReasonIPType, ipTypeSkips)
	}
}

// goActiveTask queues fn as a detached task of t's item on the per-host
// scheduler (see activeScheduler) and returns without blocking. hostKey is the
// item's host:port; the task is admitted once both the global cap and that
// host's cap have room. A task still queued when ctx is cancelled is dropped
// without running. onAbort, when set, runs if the task is dropped before it
// ran or panicked (its work did not complete).
//
// The task holds a reference on t (and on the scan-level taskWG) from the
// moment it is queued, so the item is acknowledged only after its last task
// returns or is dropped, and Execute can join every task at shutdown.
//
// Slot release is NOT tied to fn returning. fn hands releaseSlot to
// runActiveWithTimeout, which frees the slot only when the module's real work
// finishes — even if that work outlives a per-module timeout the wrapper gave up
// waiting for. Releasing on fn return instead would let the scheduler admit
// replacement tasks while abandoned scans still hold connections, so the
// concurrency caps would understate true in-flight work. The release is
// idempotent so a stray double-call can never over-drain the caps.
//
// A panic in fn is recovered here (a detached goroutine has no caller to unwind
// to): it is reported, the slot is released if fn had not handed it off yet,
// and the item is marked so it is acknowledged anyway — the poison-item rule.
func (e *Executor) goActiveTask(ctx context.Context, t *itemTracker, hostKey string, fn func(releaseSlot func()), onAbort func()) {
	t.acquire()
	e.pool.taskWG.Add(1)
	e.pool.sched.enqueue(&schedTask{
		ctx:  ctx,
		host: hostKey,
		drop: func() {
			if onAbort != nil {
				onAbort()
			}
			e.pool.taskWG.Done()
			t.done()
		},
		run: func(releaseSlot func()) {
			go func() {
				defer e.pool.taskWG.Done()
				defer t.done()
				var panicked bool
				defer func() {
					if panicked {
						t.panicked.Store(true)
						releaseSlot()
						if onAbort != nil {
							onAbort()
						}
					}
				}()
				defer e.recoverFromPanicInto("activeTask", &panicked)
				fn(releaseSlot)
			}()
		},
	})
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
		// The record's unmodified request is the breaker's recovery probe for
		// this item's payload traffic: a host that silently drops payloads is
		// then probed with something it answers.
		reqClient = e.httpClient.WithContext(ctx).WithBaseline(req)
	}

	hostKey := httpmsg.TargetHostPortKey(req)
	if t.prog != nil {
		t.prog.mu.Lock()
		t.prog.dispatched = true
		t.prog.mu.Unlock()
	}
	e.runActivePerHost(ctx, reqClient, req, filter, elig, t, hostKey)
	e.runActivePerRequest(ctx, reqClient, req, filter, elig, t, hostKey)
	e.runActivePerInsertionPoint(ctx, reqClient, req, filter, elig, t, hostKey)
}

// reflectionGateSkips reports whether mod (a modkit.ReflectionAware module)
// should skip point pt because the shared canary probe showed no reflection of
// the kind it needs. Fails open: no requester, a probe error, a
// blocked probe or a host with a detected WAF all run the module.
func (e *Executor) reflectionGateSkips(ctx context.Context, mod modules.ActiveModule, item *httpmsg.HttpRequestResponse, pt httpmsg.InsertionPoint, client *http.Requester) bool {
	ra, ok := mod.(modkit.ReflectionAware)
	if !ok || client == nil || e.scanCtx == nil {
		return false
	}
	need := ra.RequiresReflection()
	if need == 0 {
		return false
	}
	if e.scanCtx.DetectedWAF(modkit.RegistryHostKey(item)) != "" {
		return false
	}
	if oob, ok := mod.(modkit.OutOfBandLeg); ok && oob.HasOutOfBandLeg() {
		if p := e.scanCtx.OASTProv(); p != nil && p.Enabled() {
			return false // its blind leg needs no reflection
		}
	}
	prof, err := e.scanCtx.ReflectionProfile(ctx, item, pt, client)
	if err != nil || prof == nil || prof.Blocked {
		return false
	}
	return !prof.Satisfies(need)
}
