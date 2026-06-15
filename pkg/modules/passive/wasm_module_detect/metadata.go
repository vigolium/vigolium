package wasm_module_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "wasm-module-detect"
	ModuleName  = "WebAssembly Module Detect"
	ModuleShort = "Detects WebAssembly modules and WASM instantiation in HTTP responses"
)

var (
	ModuleDesc = `**What it means:** The application ships WebAssembly (WASM) to the browser. This passive fingerprint flags it via WASM magic bytes (the \x00asm signature), an application/wasm response, or WebAssembly.instantiate/compile calls in served JS. Informational recon, but WASM often holds proprietary client-side logic that can be inspected and bypassed.

**How it's exploited:** An attacker downloads the .wasm module and decompiles it (with wasm2wat) to reverse-engineer business logic, licensing or anti-fraud checks, and embedded secrets, and to find client-side controls to disable.

**Fix:** Treat WASM as untrusted client code: keep security decisions and secrets server-side, and avoid embedding sensitive logic or credentials.`

	ModuleConfirmation = "Confirmed when response contains WASM magic bytes, application/wasm content type, or WebAssembly instantiation calls"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"javascript", "fingerprint", "light"}
)
