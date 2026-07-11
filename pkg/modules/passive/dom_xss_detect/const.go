package dom_xss_detect

import "regexp"

var (
	sources       = regexp.MustCompile(`\b(?:document\.(?:URL|documentURI|URLUnencoded|baseURI|cookie|referrer)|location\.(?:href|search|hash|pathname)|window\.name|(?:local|session)Storage(?:\.getItem)?\b)`)
	sinks         = regexp.MustCompile(`\b(?:eval|Function|setTimeout|setInterval|execScript|document\.(?:write|writeln)|[A-Za-z_$][A-Za-z0-9_$\.]*\.(?:innerHTML|outerHTML|srcdoc|insertAdjacentHTML)|Range\.createContextualFragment)\b`)
	scriptExtract = regexp.MustCompile(`(?i)(?s)<script[^>]*>(.*?)</script>`)

	// openRedirectSinks matches JavaScript patterns that can trigger navigation/redirect.
	openRedirectSinks = regexp.MustCompile(`\b(?:location\.href\s*=|location\.(assign|replace)\s*\(|window\.open\s*\()`)
)
