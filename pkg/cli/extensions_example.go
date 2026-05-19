package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// extExample is one entry in the extension example catalog. Each entry is a
// complete, copy-pasteable extension in one of the supported formats. The
// catalog is intentionally self-contained (no embedded-FS lookup) so the
// output is stable for agents that reference it programmatically.
type extExample struct {
	Key      string // catalog key, e.g. "js-active-insertion"
	Lang     string // javascript | yaml | json
	Type     string // active | passive | pre_hook | post_hook | session
	Title    string // one-line description
	Filename string // suggested destination filename
	Dir      string // destination dir; empty → ~/.vigolium/extensions/
	SaveHint string // overrides the "Save as:" line entirely when set
	Fence    string // markdown fence language tag
	Code     string // the extension source
}

// destPath renders the "Save as:" location for an example.
func (e extExample) destPath() string {
	if e.SaveHint != "" {
		return e.SaveHint
	}
	dir := e.Dir
	if dir == "" {
		dir = "~/.vigolium/extensions/"
	}
	return dir + e.Filename
}

var extensionsExampleCmd = &cobra.Command{
	Use:     "example [filter]",
	Aliases: []string{"examples", "templates", "tpl"},
	Short:   "Print copy-pasteable example extensions in every supported format",
	Long: `Print self-contained example extensions covering every supported format:
JavaScript and YAML modules (active, passive, pre_hook, post_hook), the
lightweight quick-check and snippet JSON forms, and the authentication /
session config bundle in both YAML and JSON.

Without a filter, every example is printed. Pass a filter to print only the
examples whose key, language, type, or title contains the substring. Use
--list for just the catalog index, or --lang to restrict by language.

Each example is emitted inside a fenced code block with its suggested
filename so it can be copied directly into ~/.vigolium/extensions/ — or
referenced by another agent as an authoring template.`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		filter := ""
		if len(args) > 0 {
			filter = args[0]
		}
		printExtensionExamples(filter)
	},
}

var (
	exampleListOnly bool
	exampleLang     string
)

func init() {
	extensionsExampleCmd.Flags().BoolVarP(&exampleListOnly, "list", "l", false,
		"Print only the catalog index (keys + titles), no code")
	extensionsExampleCmd.Flags().StringVar(&exampleLang, "lang", "",
		"Restrict to one language: javascript (js), yaml, or json")
}

func printExtensionExamples(filter string) {
	catalog := extensionExampleCatalog()

	langFilter := strings.ToLower(strings.TrimSpace(exampleLang))
	switch langFilter {
	case "js":
		langFilter = "javascript"
	case "yml":
		langFilter = "yaml"
	}

	var matched []extExample
	for _, ex := range catalog {
		if langFilter != "" && ex.Lang != langFilter {
			continue
		}
		if !exampleMatchesFilter(ex, filter) {
			continue
		}
		matched = append(matched, ex)
	}

	if len(matched) == 0 {
		fmt.Printf("%s No examples matching %q\n", terminal.WarningSymbol(), filter)
		fmt.Printf("  Try: %s, %s, %s, %s\n",
			terminal.Gray("ext example js"),
			terminal.Gray("ext example yaml"),
			terminal.Gray("ext example pre_hook"),
			terminal.Gray("ext example --list"))
		fmt.Println()
		return
	}

	if exampleListOnly {
		fmt.Printf("\n  %s\n\n",
			terminal.BoldCyan(fmt.Sprintf("Extension Examples (%d)", len(matched))))
		tbl := terminal.NewTableWithMaxWidth(globalWidth, "KEY", "LANG", "TYPE", "DESCRIPTION")
		for _, ex := range matched {
			tbl.AddRow(
				terminal.Cyan(ex.Key),
				exampleLangLabel(ex.Lang),
				exampleTypeLabel(ex.Type),
				ex.Title,
			)
		}
		tbl.Print()
		fmt.Println()
		fmt.Printf("%s Print one example: %s\n",
			terminal.InfoSymbol(),
			terminal.Gray("vigolium ext example <key>"))
		fmt.Println()
		return
	}

	fmt.Printf("\n  %s\n",
		terminal.BoldCyan(fmt.Sprintf("Extension Examples (%d)", len(matched))))
	fmt.Printf("  %s\n",
		terminal.Gray("Copy a block to its 'Save as:' path, then load it"))

	for _, ex := range matched {
		fmt.Println()
		fmt.Printf("  %s %s\n",
			terminal.BoldCyan("▸ "+ex.Key),
			terminal.Gray("· "+exampleLangLabel(ex.Lang)+" · "+exampleTypeLabel(ex.Type)))
		fmt.Printf("  %s\n", ex.Title)
		fmt.Printf("  %s %s\n",
			terminal.Gray("Save as:"),
			terminal.Gray(ex.destPath()))
		fmt.Println()
		// Code is printed flush-left and without color so it is clean to copy
		// or parse, even on an interactive terminal.
		fmt.Println("```" + ex.Fence)
		fmt.Println(strings.TrimRight(ex.Code, "\n"))
		fmt.Println("```")
	}

	fmt.Println()
	fmt.Printf("%s Index only: %s\n",
		terminal.InfoSymbol(),
		terminal.Gray("vigolium ext example --list"))
	fmt.Printf("%s API reference: %s   Validate: %s\n",
		terminal.InfoSymbol(),
		terminal.Gray("vigolium ext docs --example"),
		terminal.Gray("vigolium ext lint <file>"))
	fmt.Printf("%s Install bundled presets: %s\n",
		terminal.InfoSymbol(),
		terminal.Gray("vigolium ext preset"))
	fmt.Println()
}

func exampleMatchesFilter(ex extExample, filter string) bool {
	if filter == "" {
		return true
	}
	f := strings.ToLower(filter)
	return strings.Contains(strings.ToLower(ex.Key), f) ||
		strings.Contains(strings.ToLower(ex.Lang), f) ||
		strings.Contains(strings.ToLower(ex.Type), f) ||
		strings.Contains(strings.ToLower(ex.Title), f)
}

func exampleLangLabel(lang string) string {
	switch lang {
	case "javascript":
		return terminal.Gray("JS")
	case "yaml":
		return terminal.Yellow("YAML")
	case "json":
		return terminal.Blue("JSON")
	default:
		return lang
	}
}

func exampleTypeLabel(t string) string {
	switch t {
	case "active":
		return terminal.Green("active")
	case "passive":
		return terminal.Cyan("passive")
	case "pre_hook", "post_hook":
		return terminal.Yellow(t)
	case "session":
		return terminal.Magenta(t)
	default:
		return t
	}
}

// extensionExampleCatalog returns the full set of example extensions, one per
// (format, type) combination. Sources mirror docs/customization/writing-extensions.md
// so the CLI and docs stay in lockstep.
func extensionExampleCatalog() []extExample {
	return []extExample{
		{
			Key:      "js-active-insertion",
			Lang:     "javascript",
			Type:     "active",
			Title:    "JS active module, per_insertion_point — inject a canary, detect reflection",
			Filename: "reflected_param_scanner.js",
			Fence:    "javascript",
			Code: `module.exports = {
  id: "reflected-param",
  name: "Reflected Parameter Scanner",
  type: "active",
  severity: "medium",
  confidence: "firm",
  tags: ["custom", "xss", "reflection"],
  scanTypes: ["per_insertion_point"],

  scanPerInsertionPoint: function(ctx, insertion) {
    // Generate a unique canary
    var canary = "VGNM" + vigolium.utils.randomString(8);

    // Build and send a request with the canary injected
    var req = insertion.buildRequest(canary);
    var resp = vigolium.http.send(req);

    if (!resp || !resp.body) return null;

    // Check if the canary appears in the response
    if (resp.body.indexOf(canary) !== -1) {
      return [{
        matched: canary,
        url: ctx.request.url,
        name: "Reflected parameter: " + insertion.name,
        description: "Parameter '" + insertion.name + "' is reflected without encoding",
        severity: "medium"
      }];
    }
    return null;
  }
};`,
		},
		{
			Key:      "js-active-request",
			Lang:     "javascript",
			Type:     "active",
			Title:    "JS active module, per_request — flag stack traces / error patterns",
			Filename: "error_pattern_detector.js",
			Fence:    "javascript",
			Code: `module.exports = {
  id: "error-pattern-detector",
  name: "Error Pattern Detector",
  type: "active",
  severity: "low",
  confidence: "firm",
  scanTypes: ["per_request"],

  scanPerRequest: function(ctx) {
    if (!ctx.response || !ctx.response.body) return null;

    var body = ctx.response.body;
    var patterns = [
      { regex: /Traceback \(most recent call last\)/i, name: "Python traceback" },
      { regex: /goroutine \d+ \[running\]/i,           name: "Go panic stack trace" },
      { regex: /SQLSTATE\[/i,                          name: "SQL error (SQLSTATE)" },
      { regex: /Fatal error:.*on line \d+/i,           name: "PHP fatal error" }
    ];

    var findings = [];
    for (var i = 0; i < patterns.length; i++) {
      if (patterns[i].regex.test(body)) {
        findings.push({
          matched: patterns[i].name,
          url: ctx.request.url,
          name: "Error pattern: " + patterns[i].name,
          description: "Response contains a " + patterns[i].name,
          severity: "low"
        });
      }
    }
    return findings.length > 0 ? findings : null;
  }
};`,
		},
		{
			Key:      "js-passive",
			Lang:     "javascript",
			Type:     "passive",
			Title:    "JS passive module — inspect responses, emit on header leak",
			Filename: "sensitive_header_leak.js",
			Fence:    "javascript",
			Code: `module.exports = {
  id: "sensitive-header-leak",
  name: "Sensitive Header Leak",
  type: "passive",
  severity: "info",
  confidence: "certain",
  scope: "response",        // request | response | both (default)
  scanTypes: ["per_request"],

  scanPerRequest: function(ctx) {
    if (!ctx.response || !ctx.response.headers) return null;

    var findings = [];
    var headers = ctx.response.headers;

    var poweredBy = headers["X-Powered-By"] || headers["x-powered-by"];
    if (poweredBy) {
      findings.push({
        matched: "X-Powered-By: " + poweredBy,
        url: ctx.request.url,
        name: "X-Powered-By header exposed",
        description: "Server technology revealed: " + poweredBy,
        severity: "info"
      });
    }

    return findings.length > 0 ? findings : null;
  }
};`,
		},
		{
			Key:      "js-pre-hook",
			Lang:     "javascript",
			Type:     "pre_hook",
			Title:    "JS pre_hook — inject auth headers before each request",
			Filename: "add_auth_header.js",
			Fence:    "javascript",
			Code: `module.exports = {
  id: "add-auth-header",
  name: "Auth Header Injector",
  type: "pre_hook",

  // Return value options:
  //   request          -> pass through unchanged
  //   { headers: {} }  -> merge these headers into the request
  //   { raw: "GET /" } -> replace the entire raw request
  //   null             -> skip this request (module won't see it)
  execute: function(request) {
    var token = vigolium.config.auth_token || "";
    if (token === "") {
      return request; // pass through unchanged
    }
    return {
      headers: {
        "Authorization": "Bearer " + token,
        "X-Correlation-ID": vigolium.utils.randomString(12)
      }
    };
  }
};`,
		},
		{
			Key:      "js-post-hook",
			Lang:     "javascript",
			Type:     "post_hook",
			Title:    "JS post_hook — escalate severity for critical URLs",
			Filename: "tag_critical_domains.js",
			Fence:    "javascript",
			Code: `module.exports = {
  id: "tag-critical-domains",
  name: "Critical Domain Tagger",
  type: "post_hook",

  // Return the (possibly modified) result, or null to suppress the finding.
  execute: function(result) {
    if (!result || !result.url) return result;

    var url = result.url.toLowerCase();
    var critical = ["payment", "admin", "auth", "checkout", "billing"];

    for (var i = 0; i < critical.length; i++) {
      if (url.indexOf(critical[i]) !== -1) {
        var sev = result.info ? result.info.severity : "info";
        var escalated = { info: "low", low: "medium", medium: "high", high: "critical" }[sev] || sev;

        return {
          url: result.url,
          matched: result.matched,
          info: {
            name: result.info.name + " [CRITICAL: " + critical[i] + "]",
            description: result.info.description,
            severity: escalated
          }
        };
      }
    }
    return result;
  }
};`,
		},
		{
			Key:      "yaml-active",
			Lang:     "yaml",
			Type:     "active",
			Title:    "YAML active module — declarative match-then-emit rules",
			Filename: "error_patterns.vgm.yaml",
			Fence:    "yaml",
			Code: `id: error-pattern-detector-yaml
name: Error Pattern Detector (YAML)
description: Detects stack traces and error messages in responses
type: active
severity: low
confidence: firm
tags: [custom, error-detection]
scan_types:
  - per_request

rules:
  - match:
      body_regex: "(?i)Traceback \\(most recent call last\\)"
    finding:
      name: "Error pattern: Python traceback"
      description: "Response body contains a Python traceback"
      severity: low

  - match:
      body_regex: "(?i)goroutine \\d+ \\[running\\]"
    finding:
      name: "Error pattern: Go panic stack trace"
      description: "Response body contains a Go panic stack trace"
      severity: low

  - match:
      body_regex: "(?i)SQLSTATE\\["
    finding:
      name: "Error pattern: SQL error"
      description: "Response body contains a SQL SQLSTATE error"
      severity: low`,
		},
		{
			Key:      "yaml-passive",
			Lang:     "yaml",
			Type:     "passive",
			Title:    "YAML passive module — header rules with matched interpolation",
			Filename: "sensitive_headers.vgm.yaml",
			Fence:    "yaml",
			Code: `id: sensitive-header-leak-yaml
name: Sensitive Header Leak (YAML)
type: passive
severity: info
confidence: certain
scope: response          # request | response | both
scan_types:
  - per_request

rules:
  - match:
      response_header: X-Powered-By
    finding:
      name: X-Powered-By header exposed
      description: "Server technology revealed via X-Powered-By header"
      matched: "{{matched}}"  # interpolates the matched header value
      severity: info

  - match:
      response_header: Server
      regex: "[0-9]+\\.[0-9]+"   # only match if value contains a version number
    finding:
      name: Server version disclosed
      description: "Server header exposes version information"
      matched: "{{matched}}"
      severity: low`,
		},
		{
			Key:      "yaml-pre-hook",
			Lang:     "yaml",
			Type:     "pre_hook",
			Title:    "YAML pre_hook — inject headers and skip static assets",
			Filename: "request_shaping.vgm.yaml",
			Fence:    "yaml",
			Code: `id: add-auth-header-yaml
name: Auth Header Injector (YAML)
type: pre_hook

# Skip this hook if the config variable is not set
skip_when:
  config_empty: auth_token

add_headers:
  Authorization: "Bearer {{config.auth_token}}"
  X-Correlation-ID: "{{rand(12)}}"

# Path suffixes that cause the request to be skipped entirely
skip_extensions:
  - .css
  - .js
  - .png
  - .jpg
  - .svg
  - .ico
  - .woff2
  - .map`,
		},
		{
			Key:      "yaml-post-hook",
			Lang:     "yaml",
			Type:     "post_hook",
			Title:    "YAML post_hook — escalate critical paths, drop noisy findings",
			Filename: "finding_shaping.vgm.yaml",
			Fence:    "yaml",
			Code: `id: tag-critical-domains-yaml
name: Critical Domain Tagger (YAML)
type: post_hook

escalate:
  when_url_contains:
    - payment
    - admin
    - auth
    - checkout
    - billing
  tag: "CRITICAL"
  bump_severity: true      # info->low, low->medium, medium->high, high->critical

drop_when:
  severity:
    - info
  url_contains:
    - /static/
    - /assets/`,
		},
		{
			Key:      "quick-check",
			Lang:     "json",
			Type:     "active",
			Title:    "Quick check — zero-JS payload-and-match (per_insertion_point & per_host)",
			Filename: "quick_checks.json",
			Fence:    "json",
			Code: `// per_insertion_point: inject payloads into each parameter, match the response
{
  "id": "ssti-jinja2",
  "severity": "high",
  "scan": "per_insertion_point",
  "payloads": ["{{7*7}}", "${7*7}", "<%=7*7%>"],
  "match": {"body_contains": "49"}
}

// per_host: send specific requests, match the response
// match fields use OR logic: body_contains, body_regex, status, header_contains
{
  "id": "debug-endpoint",
  "severity": "medium",
  "scan": "per_host",
  "requests": [
    {"method": "GET", "path": "/.env"},
    {"method": "GET", "path": "/debug/vars"}
  ],
  "match": {"status": 200, "body_regex": "(DB_PASSWORD|SECRET_KEY)"}
}`,
		},
		{
			Key:      "snippet",
			Lang:     "json",
			Type:     "active",
			Title:    "Snippet — just a function body, full vigolium.* API, auto-scaffolded",
			Filename: "snippet_idor.json",
			Fence:    "json",
			Code: `{
  "id": "idor-check",
  "severity": "high",
  "scan": "per_request",
  "body": "var related = vigolium.db.records.getRelated(ctx.record.uuid);\nvar cmp = vigolium.db.compareResponses(related);\nif (!cmp.all_similar) {\n  return [{url: ctx.request.url, matched: 'Response variance', name: 'Potential IDOR'}];\n}\nreturn null;"
}`,
		},
		{
			Key:      "session-yaml",
			Lang:     "yaml",
			Type:     "session",
			Title:    "Auth/session bundle (YAML) — login flows for authenticated scans",
			Filename: "login-flow.yaml",
			Dir:      "~/.vigolium/sessions/",
			Fence:    "yaml",
			Code: `# Load with: vigolium scan https://app.com --auth-file ~/.vigolium/sessions/login-flow.yaml
# Bare name also works: --auth-file login-flow (resolved against session_dir).
# ${VAR} expands from the environment. role: primary scans authenticated;
# role: compare sessions are replayed for IDOR/BOLA when compare_enabled.
sessions:
  # Login via JSON API, extract Bearer token (shorthand form)
  - name: admin
    role: primary
    login:
      url: "https://app.com/api/auth/login"
      method: POST
      body: '{"username":"${ADMIN_USER}","password":"${ADMIN_PASS}"}'
      type: bearer
      token_path: ".data.access_token"
      expect:
        status: [200]
        body_contains: "access_token"

  # Login via form POST, keep all session cookies (shorthand form)
  - name: regular_user
    role: compare
    login:
      url: "https://app.com/login"
      method: POST
      content_type: "application/x-www-form-urlencoded"
      body: "username=${USER_NAME}&password=${USER_PASS}"
      type: cookie

  # Extract a token via regex, apply it as a header
  - name: legacy_user
    role: compare
    login:
      url: "https://app.com/legacy/login"
      method: POST
      content_type: "application/x-www-form-urlencoded"
      body: "user=legacy&pass=legacy123"
      extract:
        - source: regex
          pattern: 'token="([^"]+)"'
          apply_as: "Authorization: Bearer {value}"

  # Multi-step: fetch a CSRF token (into var:csrf), then submit the login
  - name: csrf_app_user
    role: compare
    login:
      steps:
        - url: "https://app.com/login"
          method: GET
          extract:
            - source: regex
              pattern: 'name="csrf_token" value="([^"]+)"'
              apply_as: "var:csrf"
        - url: "https://app.com/login"
          method: POST
          content_type: "application/x-www-form-urlencoded"
          body: "username=user1&password=pass123&csrf_token={csrf}"
          extract:
            - source: cookie

  # Static token, no login request needed
  - name: api_key_user
    role: compare
    headers:
      X-API-Key: "${API_KEY}"`,
		},
		{
			Key:      "session-json",
			Lang:     "json",
			Type:     "session",
			Title:    "Auth/session bundle (JSON) — same schema as YAML, auto-detected",
			Filename: "login-flow.json",
			Dir:      "~/.vigolium/sessions/",
			Fence:    "json",
			Code: `{
  "sessions": [
    {
      "name": "admin",
      "role": "primary",
      "login": {
        "url": "https://app.com/api/auth/login",
        "method": "POST",
        "content_type": "application/json",
        "body": "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}",
        "type": "bearer",
        "token_path": ".data.access_token",
        "expect": { "status": [200], "body_contains": "access_token" }
      }
    },
    {
      "name": "regular_user",
      "role": "compare",
      "login": {
        "url": "https://app.com/login",
        "method": "POST",
        "content_type": "application/x-www-form-urlencoded",
        "body": "username=${USER_NAME}&password=${USER_PASS}",
        "extract": [ { "source": "cookie" } ]
      }
    },
    {
      "name": "legacy_user",
      "role": "compare",
      "login": {
        "url": "https://app.com/legacy/login",
        "method": "POST",
        "content_type": "application/x-www-form-urlencoded",
        "body": "user=legacy&pass=legacy123",
        "extract": [
          { "source": "regex", "pattern": "token=\"([^\"]+)\"", "apply_as": "Authorization: Bearer {value}" }
        ]
      }
    },
    {
      "name": "api_key_user",
      "role": "compare",
      "headers": { "X-API-Key": "${API_KEY}" }
    }
  ]
}`,
		},
		{
			Key:      "session-strategy-yaml",
			Lang:     "yaml",
			Type:     "session",
			Title:    "Session strategy config — how sessions behave during a scan",
			Filename: "vigolium-configs.yaml",
			SaveHint: "~/.vigolium/vigolium-configs.yaml  (under scanning_strategy:)",
			Fence:    "yaml",
			Code: `scanning_strategy:
  session:
    # Where bare --auth-file names resolve (e.g. "myapp" -> myapp.yaml here)
    session_dir: ~/.vigolium/sessions/

    # Apply primary-session credentials during discovery/spidering too
    use_in_discovery: true

    # Replay primary requests with compare sessions for IDOR/BOLA
    compare_enabled: true

    # Re-run login flows on this Go-duration interval ("" = login once)
    reauth_interval: ""

    # Reactively re-authenticate when these status codes are seen
    reauth_on_status: [401, 403]

    # GET this URL after login to verify credentials (2xx expected; "" = off)
    validate_url: "/api/me"`,
		},
	}
}
