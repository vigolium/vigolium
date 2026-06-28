package dom_xss_detect

import "regexp"

var (
	sources       = regexp.MustCompile(`\b(?:document\.(URL|documentURI|URLUnencoded|baseURI|cookie|referrer)|location\.(href|search|hash|pathname)|window\.name|history\.(pushState|replaceState)(local|session)Storage)\b`)
	sinks         = regexp.MustCompile(`\b(?:eval|evaluate|execCommand|assign|navigate|getResponseHeaderopen|showModalDialog|Function|set(Timeout|Interval|Immediate)|execScript|crypto.generateCRMFRequest|ScriptElement\.(src|text|textContent|innerText)|.*?\.onEventName|document\.(write|writeln)|.*?\.innerHTML|Range\.createContextualFragment|(document|window)\.location)\b`)
	scriptExtract = regexp.MustCompile(`(?i)(?s)<script[^>]*>(.*?)</script>`)

	// openRedirectSinks matches JavaScript patterns that can trigger navigation/redirect.
	openRedirectSinks = regexp.MustCompile(`\b(?:location\.href\s*=|location\.(assign|replace)\s*\(|window\.open\s*\()`)

	// identifierPattern extracts the first JS identifier from a fragment. Hoisted
	// to package scope so it is compiled once, not per fragment inside analyse().
	identifierPattern = regexp.MustCompile(`[a-zA-Z$_][a-zA-Z0-9$_]+`)
)
