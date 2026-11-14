package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/sourcegraph/conc"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/output"
)

// runPassivePerHostFiltered runs pre-filtered passive modules (CanProcess already checked).
func (e *Executor) runPassivePerHostFiltered(ctx context.Context, item *httpmsg.HttpRequestResponse, eligible []modules.PassiveModule) {
	origin := originKeyFromItem(item)

	for _, module := range eligible {
		// Claim this (module, origin) pair — skip if another worker already did.
		claimKey := hostClaimKey{moduleID: module.ID(), origin: origin}
		if !e.caches.hostClaims.claimPassive(claimKey) {
			continue
		}

		o := e.runPassiveCall(
			ctx,
			func(runCtx context.Context) ([]*output.ResultEvent, error) {
				if contextual, ok := module.(modules.ContextualPassiveModule); ok {
					return contextual.ScanPerHostContext(runCtx, item, e.scanCtx)
				}
				return module.ScanPerHost(item, e.scanCtx)
			},
			module, item,
		)
		if o.failedTransiently() && ctx.Err() == nil {
			e.caches.hostClaims.releasePassive(claimKey)
		}
		e.processResults(ctx, o.events, module, item, nil)
	}
}

// runPassivePerRequestFiltered runs pre-filtered passive modules (CanProcess already checked).
func (e *Executor) runPassivePerRequestFiltered(ctx context.Context, item *httpmsg.HttpRequestResponse, eligible []modules.PassiveModule) {
	if len(eligible) == 0 {
		return
	}

	if e.cfg.ParallelPassive {
		var g conc.WaitGroup
		// sem bounds live passive goroutines across all record workers. nil (an
		// executor built without NewExecutor, e.g. in a unit test) means an
		// unbounded fan-out.
		sem := e.pool.passiveTaskSem
		for _, module := range eligible {
			mod := module
			// Acquire a global passive slot BEFORE spawning so the number of live
			// passive goroutines is bounded (not workers × modules). A cancelled
			// scan stops submitting.
			if sem != nil {
				select {
				case sem <- struct{}{}:
				case <-ctx.Done():
					g.Wait()
					return
				}
			}
			g.Go(func() {
				if sem != nil {
					defer func() { <-sem }()
				}
				results := e.runPassiveWithTimeout(
					ctx,
					func(runCtx context.Context) ([]*output.ResultEvent, error) {
						if contextual, ok := mod.(modules.ContextualPassiveModule); ok {
							return contextual.ScanPerRequestContext(runCtx, item, e.scanCtx)
						}
						return mod.ScanPerRequest(item, e.scanCtx)
					},
					mod, item,
				)
				e.processResults(ctx, results, mod, item, nil)
			})
		}
		g.Wait()
		return
	}

	for _, module := range eligible {
		results := e.runPassiveWithTimeout(
			ctx,
			func(runCtx context.Context) ([]*output.ResultEvent, error) {
				if contextual, ok := module.(modules.ContextualPassiveModule); ok {
					return contextual.ScanPerRequestContext(runCtx, item, e.scanCtx)
				}
				return module.ScanPerRequest(item, e.scanCtx)
			},
			module, item,
		)
		e.processResults(ctx, results, module, item, nil)
	}
}

func (e *Executor) runPassiveStage(ctx context.Context, req *httpmsg.HttpRequestResponse, filter *moduleFilter, inScope bool) {
	eligiblePerHost := e.filterEligiblePassive(e.perHostPassive, req, filter)
	eligiblePerRequest := e.filterEligiblePassive(e.perRequestPassive, req, filter)
	if !inScope {
		eligiblePerHost = filterNonScopeAware(eligiblePerHost)
		eligiblePerRequest = filterNonScopeAware(eligiblePerRequest)
	}
	e.runPassivePerHostFiltered(ctx, req, eligiblePerHost)
	e.runPassivePerRequestFiltered(ctx, req, eligiblePerRequest)
}

// filterEligiblePassive pre-filters passive modules by CanProcess and module filter,
// computing eligibility once per request instead of per-module in each run method.
func (e *Executor) filterEligiblePassive(mods []modules.PassiveModule, item *httpmsg.HttpRequestResponse, filter *moduleFilter) []modules.PassiveModule {
	if len(mods) == 0 {
		return nil
	}
	eligible := make([]modules.PassiveModule, 0, len(mods))
	var bodyKey string // computed once, on the first body-only module
	for _, m := range mods {
		if !filter.allows(m.ID()) {
			continue
		}
		if !e.passesTechFilter(m, item) {
			continue
		}
		if !e.passesContentClassFilter(m, item) {
			continue
		}
		// Mark considered before CanProcess so modules that always reject this
		// input shape still count toward the "modules scanned" status counter.
		e.moduleMetrics.MarkConsidered(m.ID())
		if !m.CanProcess(item) {
			continue
		}
		if bo, ok := m.(modules.BodyOnlyPassive); ok && bo.BodyOnly() {
			if bodyKey == "" {
				bodyKey = responseBodyKey(item)
			}
			if bodyKey != "-" && e.caches.hostClaims.seenBody(m.ID(), bodyKey) {
				continue
			}
		}
		eligible = append(eligible, m)
	}
	return eligible
}

// responseBodyKey identifies a response for BodyOnlyPassive dedup: the hex
// SHA-256 of its media type and body. "-" means "no body, never dedup".
func responseBodyKey(item *httpmsg.HttpRequestResponse) string {
	if item == nil || item.Response() == nil {
		return "-"
	}
	body := item.Response().Body()
	if len(body) == 0 {
		return "-"
	}
	h := sha256.New()
	ct := strings.ToLower(item.Response().Header("Content-Type"))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	h.Write([]byte(strings.TrimSpace(ct)))
	h.Write([]byte{0})
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}
