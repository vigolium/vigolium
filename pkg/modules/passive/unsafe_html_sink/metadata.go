package unsafe_html_sink

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "unsafe-html-sink"
	ModuleName  = "Unsafe HTML Sink"
	ModuleShort = "Detects raw HTML injection sinks in JS/TS framework code"
)

var (
	ModuleDesc = `**What it means:** Static analysis of served JS, Vue, or Svelte code found a known unsafe HTML or code-execution sink - framework sinks (dangerouslySetInnerHTML, v-html, bypassSecurityTrust), DOM sinks (innerHTML, insertAdjacentHTML, document.write), or eval and new Function. Informational lead; it does not confirm untrusted input reaches the sink.

**How it's exploited:** If a value from the URL, fragment, postMessage, or other user input reaches the sink unsanitized, an attacker injects script and runs arbitrary code in the victim's browser.

**Fix:** Sanitize untrusted input before any HTML sink (for example DOMPurify) and avoid eval and new Function on dynamic data.`

	ModuleConfirmation = "Confirmed when response JavaScript or template code contains known unsafe HTML injection sinks"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"xss", "javascript", "light"}
)
