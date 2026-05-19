package wasm_module_detect

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
)

// wasmMagicBytes is the WebAssembly binary magic number (\x00asm).
var wasmMagicBytes = []byte{0x00, 0x61, 0x73, 0x6d}

// wasmInstantiationPatterns lists WebAssembly API calls to detect in JS files.
var wasmInstantiationPatterns = []string{
	"WebAssembly.instantiate",
	"WebAssembly.compile",
	"WebAssembly.instantiateStreaming",
}

// Module implements the WebAssembly Module Detect passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new WebAssembly Module Detect module.
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
			modkit.PassiveScanScopeResponse,
		),
		ds: dedup.LazyDiskSet("passive_wasm_module_detect"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// CanProcess accepts WASM files (by extension or content type) and JS files
// (to detect WebAssembly instantiation calls).
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Response() == nil {
		return false
	}
	if len(ctx.Response().Body()) == 0 {
		return false
	}

	// Check for .wasm extension
	if u, err := ctx.URL(); err == nil && strings.HasSuffix(strings.ToLower(u.Path), ".wasm") {
		return true
	}

	ct := strings.ToLower(ctx.Response().Header("Content-Type"))

	// Check for application/wasm content type
	if strings.Contains(ct, "application/wasm") {
		return true
	}

	// Accept JS content types to check for WebAssembly usage
	if strings.Contains(ct, "javascript") || strings.Contains(ct, "ecmascript") {
		return true
	}

	return false
}

// ScanPerRequest analyzes responses for WebAssembly indicators.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	dedupKey := utils.Sha1(urlx.String())
	if diskSet != nil && diskSet.IsSeen(dedupKey) {
		return nil, nil
	}

	body := ctx.Response().Body()
	if len(body) == 0 {
		return nil, nil
	}

	// Detection 1: WASM magic bytes
	if len(body) >= 4 && body[0] == wasmMagicBytes[0] && body[1] == wasmMagicBytes[1] &&
		body[2] == wasmMagicBytes[2] && body[3] == wasmMagicBytes[3] {
		return []*output.ResultEvent{
			{
				ModuleID:         ModuleID,
				Host:             urlx.Host,
				URL:              urlx.String(),
				Matched:          urlx.String(),
				ExtractedResults: []string{"WASM binary detected (magic bytes: \\x00asm)"},
				Info: output.Info{
					Name:        "WebAssembly Binary Module",
					Description: fmt.Sprintf("WebAssembly binary module detected at %s", urlx.Path),
					Tags:        []string{"wasm", "reverse-engineering"},
				},
				Metadata: map[string]any{
					"size_bytes": len(body),
				},
			},
		}, nil
	}

	// Detection 2: WebAssembly instantiation in JS files
	ct := strings.ToLower(ctx.Response().Header("Content-Type"))
	if strings.Contains(ct, "javascript") || strings.Contains(ct, "ecmascript") {
		bodyStr := ctx.Response().BodyToString()
		var found []string
		for _, pattern := range wasmInstantiationPatterns {
			if strings.Contains(bodyStr, pattern) {
				found = append(found, pattern)
			}
		}
		if len(found) == 0 {
			return nil, nil
		}

		return []*output.ResultEvent{
			{
				ModuleID:         ModuleID,
				Host:             urlx.Host,
				URL:              urlx.String(),
				Matched:          urlx.String(),
				ExtractedResults: found,
				Info: output.Info{
					Name:        "WebAssembly Instantiation in JavaScript",
					Description: fmt.Sprintf("JavaScript file contains %d WebAssembly API call(s)", len(found)),
					Tags:        []string{"wasm", "reverse-engineering"},
				},
			},
		}, nil
	}

	return nil, nil
}
