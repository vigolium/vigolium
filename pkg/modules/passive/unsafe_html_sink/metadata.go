package unsafe_html_sink

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "unsafe-html-sink"
	ModuleName  = "Unsafe HTML Sink"
	ModuleShort = "Detects raw HTML injection sinks in JS/TS framework code"
)

var (
	ModuleDesc = `**What it means:** Static analysis of the served JavaScript, TypeScript, Vue, or Svelte code found a call to a known unsafe HTML or code-execution sink. These include framework sinks like React dangerouslySetInnerHTML, Vue v-html, Svelte at-html, and Angular bypassSecurityTrust, vanilla DOM sinks like innerHTML, outerHTML, insertAdjacentHTML, and document.write, plus eval and new Function. If any of these is fed attacker-controllable data without sanitization, it becomes a DOM-based XSS or code-injection vector. This is an informational source-analysis lead: the scanner flags the sink pattern but does not confirm that untrusted input actually reaches it.

**How it's exploited:** The finding marks attack surface to investigate. An attacker reviews how each sink is supplied data, and if a value derived from the URL, fragment, postMessage, or other user input flows into it unsanitized, they craft input that injects script and executes arbitrary code in the victim's browser session.

**Fix:** Sanitize untrusted input before any HTML sink (for example DOMPurify) and avoid eval and new Function on dynamic data.`

	ModuleConfirmation = "Confirmed when response JavaScript or template code contains known unsafe HTML injection sinks"
	ModuleSeverity     = severity.Low
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"xss", "javascript", "light"}
)
