package client_prototype_pollution

import "regexp"

// ppGadgetPattern defines a known exploitable prototype pollution gadget.
type ppGadgetPattern struct {
	Name    string
	Impact  string
	Pattern *regexp.Regexp
}

// ppGadgetPatterns contains known high-impact prototype pollution gadgets.
var ppGadgetPatterns = []ppGadgetPattern{
	{
		Name:    "innerHTML gadget",
		Pattern: regexp.MustCompile(`\.innerHTML\s*=\s*[^;]*(?:config|options|settings|defaults)\[`),
		Impact:  "XSS via innerHTML assignment",
	},
	{
		Name:    "eval gadget",
		Pattern: regexp.MustCompile(`eval\s*\([^)]*(?:config|options|settings|defaults)\[`),
		Impact:  "Code execution via eval",
	},
	{
		Name:    "script.src gadget",
		Pattern: regexp.MustCompile(`\.src\s*=\s*[^;]*(?:config|options|settings|defaults)\[`),
		Impact:  "Script source override",
	},
	{
		Name:    "jQuery html() gadget",
		Pattern: regexp.MustCompile(`\.html\s*\([^)]*(?:config|options|settings|defaults)\[`),
		Impact:  "XSS via jQuery .html()",
	},
	{
		Name:    "document.write gadget",
		Pattern: regexp.MustCompile(`document\.write\s*\([^)]*(?:config|options|settings|defaults)\[`),
		Impact:  "XSS via document.write",
	},
	{
		Name:    "transport-url (generic)",
		Pattern: regexp.MustCompile(`(?:url|href|src|action)\s*[:=]\s*[^,;]*(?:this|self|that)\[`),
		Impact:  "URL override via prototype",
	},
}
