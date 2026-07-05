package llm_endpoint_fingerprint

import (
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

// Module implements the LLM Endpoint Fingerprint passive scanner. It publishes the
// "llm" tech tag so the active prompt-injection probe only targets real LLM
// endpoints, and emits one Info finding per endpoint.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new module instance.
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
			modkit.PassiveScanScopeBoth,
		),
		ds: dedup.LazyDiskSet("llm_endpoint_fingerprint"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest marks the host as running an LLM endpoint and emits an Info
// finding once per endpoint (host+path).
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if !infra.LooksLikeLLMEndpoint(ctx) {
		return nil, nil
	}
	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}

	// Publish the tech tag so tech-gated active modules (the prompt-injection probe)
	// can target this host.
	scanCtx.MarkTech(urlx.Host, "llm")

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	key := urlx.Host + urlx.Path
	if diskSet != nil && diskSet.IsSeen(key) {
		return nil, nil
	}

	return []*output.ResultEvent{{
		ModuleID:         ModuleID,
		Host:             urlx.Host,
		URL:              urlx.String(),
		ExtractedResults: []string{"llm_endpoint=" + urlx.Path},
		Info: output.Info{
			Name:        "LLM Endpoint Detected",
			Description: "This endpoint exposes an application-level LLM chat/completion API (identified by its request/response body shape). It is the attack surface for prompt injection, system-prompt leakage, and tool/agent abuse.",
			Severity:    ModuleSeverity,
			Confidence:  ModuleConfidence,
			Tags:        ModuleTags,
		},
	}}, nil
}
