// Package aem_content_discovery implements a routing-aware AEM repository
// content-discovery module. Unlike a filename brute-forcer, it understands Sling
// request routing (resource-path.selectors.extension) and walks the JCR tree the
// way AEM serves it: DefaultGetServlet .1.json enumerates a node's child-node
// names, which are then followed recursively, and QueryBuilder predicates search
// the repository directly. Every probe is tried through the shared dispatcher
// bypass variants (pkg/modules/infra/aem) so a partially-locked-down dispatcher
// does not hide the exposure.
package aem_content_discovery

import (
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	aem "github.com/vigolium/vigolium/pkg/modules/infra/aem"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

// reproduceRounds is deliberately one higher than the AEM family default (2): this
// module enumerates in bulk and reports Critical secret/writable findings, so every
// hit must survive an extra independent confirmation round before it is reported.
const reproduceRounds = 3

type Module struct {
	modkit.BaseActiveModule
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
			modkit.ScanScopeHost,
			modkit.AllInsertionPointTypes,
		),
		ds: dedup.LazyDiskSet("aem_content_discovery"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) IncludesBaseCanProcess() bool { return false }

func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	return ctx != nil && ctx.Request() != nil
}

func (m *Module) ScanPerHost(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}
	host := urlx.Host

	if !modkit.BeginHostProbeKey(scanCtx, httpClient, &m.ds, host) {
		return nil, nil
	}

	if !aem.ConfirmAEM(ctx, httpClient, scanCtx) {
		return nil, nil
	}

	baseURL := urlx.Scheme + "://" + urlx.Host
	var results []*output.ResultEvent

	// (A) DefaultGetServlet tree-walk: find a working .1.json read primitive across
	// the dispatcher bypasses, then recursively enumerate the repository and harvest
	// secrets / user accounts from the nodes we can read.
	results = append(results, m.runTreeWalk(ctx, httpClient, scanCtx, baseURL)...)

	// (B) QueryBuilder predicate driver: anonymously writable nodes (CVE-2025-54246
	// solution #1) and deployment package/archive disclosure.
	results = append(results, m.runQueryBuilder(ctx, httpClient, scanCtx, baseURL)...)

	return results, nil
}
