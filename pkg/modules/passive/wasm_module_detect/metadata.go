package wasm_module_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "wasm-module-detect"
	ModuleName  = "WebAssembly Module Detect"
	ModuleShort = "Detects WebAssembly modules and WASM instantiation in HTTP responses"
)

var (
	ModuleDesc = `**What it means:** The application ships WebAssembly (WASM) to the browser. This passive, informational fingerprint flags it by spotting WASM binary magic bytes (the \x00asm signature) or an application/wasm response, or by finding WebAssembly.instantiate, WebAssembly.compile, or WebAssembly.instantiateStreaming calls in served JavaScript. WASM is not itself a vulnerability, but it often holds proprietary or security-sensitive client-side logic, and any logic enforced only in the browser can be inspected and bypassed.

**How it's exploited:** An attacker downloads the .wasm module and decompiles it (for example with wasm2wat or wabt) to reverse-engineer business logic, licensing or anti-fraud checks, embedded secrets, or algorithms, and to find client-side controls they can disable or replay against the server. The disclosure mainly helps map attack surface and target the client-side trust boundary.

**Fix:** Treat WASM as untrusted client code: keep all security decisions and secrets server-side, and avoid embedding sensitive logic or credentials in shipped WebAssembly modules.`

	ModuleConfirmation = "Confirmed when response contains WASM magic bytes, application/wasm content type, or WebAssembly instantiation calls"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"javascript", "fingerprint", "light"}
)
