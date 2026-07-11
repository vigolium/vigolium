// Package websocket_security retains the legacy module constructor for callers
// that imported it directly. The default registry uses ws_cswsh as the single
// canonical implementation so one endpoint cannot emit duplicate origin-policy
// results from two overlapping modules.
package websocket_security

import (
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/active/ws_cswsh"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

const evilOrigin = "https://evil.example.com"

type Module struct {
	modkit.BaseActiveModule
	delegate *ws_cswsh.Module
}

func New() *Module {
	m := &Module{
		BaseActiveModule: modkit.NewBaseActiveModule(
			ModuleID, ModuleName, ModuleDesc, ModuleShort, ModuleConfirmation,
			ModuleSeverity, ModuleConfidence,
			modkit.ScanScopeRequest, modkit.AllInsertionPointTypes,
		),
		delegate: ws_cswsh.New(),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, client *http.Requester, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	results, err := m.delegate.ScanPerRequest(ctx, client, scanCtx)
	for _, result := range results {
		result.ModuleID = ModuleID
		result.Info.Tags = ModuleTags
		if result.Metadata == nil {
			result.Metadata = map[string]any{}
		}
		result.Metadata["canonical_module"] = ws_cswsh.ModuleID
		result.Metadata["legacy_alias"] = true
	}
	return results, err
}
