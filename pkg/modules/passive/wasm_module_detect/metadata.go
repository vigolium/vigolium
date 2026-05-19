package wasm_module_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "wasm-module-detect"
	ModuleName  = "WebAssembly Module Detect"
	ModuleShort = "Detects WebAssembly modules and WASM instantiation in HTTP responses"
)

var (
	ModuleDesc = `## Description
Passively detects WebAssembly (WASM) module usage by identifying .wasm files,
application/wasm content types, WASM magic bytes, and WebAssembly instantiation
calls in JavaScript files.

## Notes
- Detects WASM binary files via magic bytes (\x00asm)
- Identifies WebAssembly.instantiate, WebAssembly.compile, and WebAssembly.instantiateStreaming calls in JS
- WASM modules may contain sensitive logic worth reverse engineering
- Useful for identifying client-side logic that may bypass server-side controls

## References
- https://webassembly.org/
- https://developer.mozilla.org/en-US/docs/WebAssembly`

	ModuleConfirmation = "Confirmed when response contains WASM magic bytes, application/wasm content type, or WebAssembly instantiation calls"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"javascript", "fingerprint", "light"}
)
