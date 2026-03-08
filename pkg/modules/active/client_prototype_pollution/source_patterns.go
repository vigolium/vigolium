package client_prototype_pollution

import "regexp"

// ppSourcePattern defines a known vulnerable URL parameter parsing pattern.
type ppSourcePattern struct {
	Name    string
	Desc    string
	Pattern *regexp.Regexp
}

// ppSourcePatterns contains known vulnerable URL parameter parsing patterns.
var ppSourcePatterns = []ppSourcePattern{
	{
		Name:    "jQuery.extend (deep)",
		Pattern: regexp.MustCompile(`\$\.extend\s*\(\s*true`),
		Desc:    "jQuery deep extend with URL-sourced input",
	},
	{
		Name:    "lodash.merge",
		Pattern: regexp.MustCompile(`_\.merge\s*\(`),
		Desc:    "lodash/underscore merge (recursive assignment)",
	},
	{
		Name:    "lodash.defaultsDeep",
		Pattern: regexp.MustCompile(`_\.defaultsDeep\s*\(`),
		Desc:    "lodash defaultsDeep (recursive assignment)",
	},
	{
		Name:    "lodash.set",
		Pattern: regexp.MustCompile(`_\.set\s*\(`),
		Desc:    "lodash set (path-based assignment)",
	},
	{
		Name:    "Object.assign from params",
		Pattern: regexp.MustCompile(`Object\.assign\s*\([^)]*(?:location|search|hash|params)`),
		Desc:    "Object.assign with URL-sourced input",
	},
	{
		Name:    "Custom recursive assign",
		Pattern: regexp.MustCompile(`(?:for|forEach)\s*\([^)]*\)\s*\{[^}]*\[[^\]]*\]\s*=`),
		Desc:    "Custom recursive property assignment loop",
	},
	{
		Name:    "decodeURIComponent with bracket notation",
		Pattern: regexp.MustCompile(`decodeURIComponent[^;]*\[[^\]]*\]\s*=`),
		Desc:    "URL-decoded value assigned via bracket notation",
	},
	{
		Name:    "URLSearchParams to object",
		Pattern: regexp.MustCompile(`URLSearchParams[^;]*forEach[^}]*\[[^\]]*\]\s*=`),
		Desc:    "URLSearchParams iterated into object via bracket notation",
	},
	{
		Name:    "location.search split parser",
		Pattern: regexp.MustCompile(`location\.search[^;]*split[^;]*\[[^\]]*\]\s*=`),
		Desc:    "Manual URL parameter parser using split + bracket assignment",
	},
	{
		Name:    "location.hash parser",
		Pattern: regexp.MustCompile(`location\.hash[^;]*(?:split|match|replace)[^;]*\[[^\]]*\]\s*=`),
		Desc:    "Hash fragment parser with bracket assignment",
	},
}
