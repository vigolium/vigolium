package core

import (
	"context"

	"github.com/sourcegraph/conc"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules"
	"github.com/vigolium/vigolium/pkg/output"
)

// runPassivePerHostFiltered runs pre-filtered passive modules (CanProcess already checked).
func (e *Executor) runPassivePerHostFiltered(ctx context.Context, item *httpmsg.HttpRequestResponse, eligible []modules.PassiveModule) {
	host := hostFromItem(item)

	for _, module := range eligible {
		// Claim this (module, host) pair — skip if another worker already claimed it
		claimKey := module.ID() + ":" + host
		if _, loaded := e.perHostPassiveClaimed.LoadOrStore(claimKey, struct{}{}); loaded {
			continue
		}

		results := e.runPassiveWithTimeout(
			ctx,
			func(runCtx context.Context) ([]*output.ResultEvent, error) {
				if contextual, ok := module.(modules.ContextualPassiveModule); ok {
					return contextual.ScanPerHostContext(runCtx, item, e.scanCtx)
				}
				return module.ScanPerHost(item, e.scanCtx)
			},
			module, item,
		)
		e.processResults(ctx, results, module, item)
	}
}

// runPassivePerRequestFiltered runs pre-filtered passive modules (CanProcess already checked).
func (e *Executor) runPassivePerRequestFiltered(ctx context.Context, item *httpmsg.HttpRequestResponse, eligible []modules.PassiveModule) {
	if len(eligible) == 0 {
		return
	}

	if e.cfg.ParallelPassive {
		var g conc.WaitGroup
		for _, module := range eligible {
			mod := module
			g.Go(func() {
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
				e.processResults(ctx, results, mod, item)
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
		e.processResults(ctx, results, module, item)
	}
}
