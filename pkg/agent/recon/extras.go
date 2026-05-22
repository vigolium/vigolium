package recon

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// runJSFingerprint matches client-side framework markers in baseResp.Body
// against jsFingerprintRules. Pure: no extra HTTP fetches.
func runJSFingerprint(baseResp *probeResponse) []JSFrameworkSignal {
	if baseResp == nil || baseResp.Body == "" {
		return nil
	}
	body := baseResp.Body
	lower := strings.ToLower(body)

	var out []JSFrameworkSignal
	seen := map[string]bool{}
	add := func(sig JSFrameworkSignal) {
		if seen[sig.Name] {
			return
		}
		seen[sig.Name] = true
		out = append(out, sig)
	}

	for _, rule := range jsFingerprintRules {
		if rule.body != "" && strings.Contains(lower, rule.body) {
			add(JSFrameworkSignal{Name: rule.name, Tag: rule.tag, Evidence: rule.evidence})
		}
	}
	for _, src := range extractScriptSrcs(body) {
		for _, rule := range jsFingerprintRules {
			if rule.srcMatch == "" {
				continue
			}
			if strings.Contains(strings.ToLower(src), rule.srcMatch) {
				add(JSFrameworkSignal{Name: rule.name, Tag: rule.tag, Evidence: "script src: " + src})
			}
		}
	}

	return out
}

type jsRule struct {
	name     string
	tag      string
	body     string // case-folded substring to match in HTML/inline JS
	srcMatch string // case-folded substring to match against <script src> URLs
	evidence string
}

// jsFingerprintRules: list specific signals (e.g. Next.js) before
// generic ones (React) — first match per Name wins.
var jsFingerprintRules = []jsRule{
	{name: "next", tag: "nextjs", body: `__next_data__`, srcMatch: "/_next/static/", evidence: "Next.js hydration data or _next/static asset path detected"},
	{name: "nuxt", tag: "nuxt", body: `window.__nuxt__`, srcMatch: "/_nuxt/", evidence: "Nuxt hydration data or _nuxt asset path detected"},
	{name: "vite", tag: "javascript", body: ``, srcMatch: "/@vite/client", evidence: "Vite dev client script reachable (likely staging/dev surface)"},
	{name: "webpack", tag: "javascript", body: `webpackchunk`, srcMatch: "", evidence: "Webpack runtime marker (webpackChunk) present in inline JS"},
	{name: "react", tag: "react", body: `react-dom`, srcMatch: "react", evidence: "React or react-dom markers present"},
	{name: "vue", tag: "javascript", body: `__vue__`, srcMatch: "vue.runtime", evidence: "Vue runtime markers present"},
	{name: "angular", tag: "angular", body: `ng-version`, srcMatch: "", evidence: "Angular ng-version attribute present in DOM"},
	{name: "svelte", tag: "javascript", body: `__svelte`, srcMatch: "", evidence: "Svelte runtime markers present"},
	{name: "graphql-client", tag: "graphql", body: `__apollo_client__`, srcMatch: "", evidence: "Apollo Client globals — GraphQL backend likely"},
}

// scriptSrcRE captures `src="..."` and `src='...'` attribute values
// loosely from HTML. Not a real parser, but good enough for the small
// dump of <script> tags a base URL typically returns.
var scriptSrcRE = regexp.MustCompile(`(?i)<script[^>]+\bsrc\s*=\s*["']([^"']+)["']`)

// extractScriptSrcs pulls up to 16 <script src> values from html. The
// cap keeps the matcher loop bounded even for response bodies bloated
// with inline analytics.
func extractScriptSrcs(html string) []string {
	matches := scriptSrcRE.FindAllStringSubmatch(html, 16)
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		if len(m) >= 2 {
			out = append(out, m[1])
		}
	}
	return out
}

// computeFaviconHash returns the MD5 hex of /favicon.ico, or "" on any
// error or empty response.
func computeFaviconHash(ctx context.Context, client *http.Client, baseURL string, cfg Config) string {
	resp, err := doProbe(ctx, client, http.MethodGet, baseURL+"/favicon.ico", cfg)
	if err != nil || resp == nil || resp.Body == "" {
		return ""
	}
	if !isReachable(resp.Status) {
		return ""
	}
	sum := md5.Sum([]byte(resp.Body))
	return hex.EncodeToString(sum[:])
}

// vhostVariants returns Host header variants likely to surface
// staging/admin/default vhost behavior: localhost, admin.<host>, and
// the resolved IP (when distinct from the original).
func vhostVariants(baseHost string) []string {
	host := baseHost
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	out := []string{"localhost"}
	if !strings.HasPrefix(host, "admin.") && strings.Contains(host, ".") {
		out = append(out, "admin."+host)
	}
	if ips, err := net.LookupHost(host); err == nil && len(ips) > 0 {
		ip := ips[0]
		if ip != host && ip != "127.0.0.1" && ip != "::1" {
			out = append(out, ip)
		}
	}
	return out
}

// runVHostProbe sends GET / once per vhost variant and flags status
// flips or >256-byte body deltas vs baseResp. One probe per variant —
// any more starts to look like host fuzzing.
func runVHostProbe(ctx context.Context, client *http.Client, baseURL string, baseHost string, baseResp *probeResponse, cfg Config) []VHostFinding {
	if baseResp == nil {
		return nil
	}
	baselineLen := len(baseResp.Body)
	baselineCode := baseResp.Status

	variants := vhostVariants(baseHost)
	out := make([]VHostFinding, 0, len(variants))
	for _, v := range variants {
		resp, err := doProbeWithHostHeader(ctx, client, baseURL+"/", v, cfg)
		if err != nil || resp == nil {
			continue
		}
		delta := len(resp.Body) - baselineLen
		if delta < 0 {
			delta = -delta
		}
		// Only flag when something meaningful changed: a different status,
		// or a body length delta >256 bytes. Small jitter (date/CSRF token
		// regenerations) gets ignored.
		if resp.Status == baselineCode && delta < 256 {
			continue
		}
		reason := vhostReason(v, baselineCode, resp.Status, delta)
		out = append(out, VHostFinding{
			Host:         v,
			StatusCode:   resp.Status,
			BodyDelta:    delta,
			BaselineCode: baselineCode,
			Reason:       reason,
		})
	}
	return out
}

func vhostReason(host string, baselineCode, observedCode, delta int) string {
	switch {
	case baselineCode == observedCode && delta >= 256:
		return fmt.Sprintf("Host=%s returned same %d status but body differs by %d bytes (possible distinct vhost)", host, observedCode, delta)
	case baselineCode != observedCode:
		return fmt.Sprintf("Host=%s flipped status %d→%d (possible isolation issue or distinct vhost)", host, baselineCode, observedCode)
	}
	return fmt.Sprintf("Host=%s anomaly (status=%d, body delta=%d)", host, observedCode, delta)
}

// doProbeWithHostHeader is doProbe with an explicit Host header
// override. URL still drives DNS resolution.
func doProbeWithHostHeader(ctx context.Context, client *http.Client, targetURL, hostHeader string, cfg Config) (*probeResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", cfg.UserAgent)
	req.Header.Set("Accept", "*/*")
	applyExtraHeaders(req, cfg)
	if hostHeader != "" {
		req.Host = hostHeader
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, int64(cfg.MaxBodyBytes)))
	return &probeResponse{
		URL:     targetURL,
		Status:  resp.StatusCode,
		Headers: resp.Header.Clone(),
		Body:    string(body),
	}, nil
}

var methodMatrixMethods = []string{
	http.MethodPut,
	http.MethodDelete,
	http.MethodPatch,
}

// runMethodMatrix probes each path with PUT/DELETE/PATCH and records
// methods that returned anything other than 405/501. A path that 200s
// on PUT or DELETE is a strong broken-access-control signal. Probes
// fan out bounded by cfg.Concurrency.
func runMethodMatrix(ctx context.Context, client *http.Client, baseURL string, paths []string, cfg Config) map[string][]string {
	if len(paths) == 0 {
		return nil
	}
	type result struct {
		path, method string
	}
	concurrency := cfg.Concurrency
	if concurrency <= 0 {
		concurrency = 8
	}
	sem := make(chan struct{}, concurrency)
	results := make(chan result, len(paths)*len(methodMatrixMethods))
	var wg sync.WaitGroup
	for _, p := range paths {
		for _, m := range methodMatrixMethods {
			wg.Add(1)
			go func(path, method string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				resp, err := doProbe(ctx, client, method, baseURL+path, cfg)
				if err != nil || resp == nil {
					return
				}
				if resp.Status == http.StatusMethodNotAllowed || resp.Status == http.StatusNotImplemented {
					return
				}
				results <- result{path: path, method: method}
			}(p, m)
		}
	}
	wg.Wait()
	close(results)

	out := make(map[string][]string, len(paths))
	for r := range results {
		out[r.path] = append(out[r.path], r.method)
	}
	for k := range out {
		sort.Strings(out[k])
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// runLoginFormScrape returns LoginCandidate entries for every <form>
// in baseResp.Body that contains an <input type="password">. Form
// actions are kept relative — the planner resolves them itself.
func runLoginFormScrape(baseResp *probeResponse, baseURL string) []LoginCandidate {
	if baseResp == nil || baseResp.Body == "" {
		return nil
	}
	body := baseResp.Body
	out := []LoginCandidate{}
	for _, form := range extractForms(body) {
		if !formHasPassword(form) {
			continue
		}
		out = append(out, LoginCandidate{
			URL:          baseURL,
			UsernameName: bestUsernameField(form),
			PasswordName: bestPasswordField(form),
			Action:       formAction(form),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

var (
	formBlockRE = regexp.MustCompile(`(?is)<form\b[^>]*>(.*?)</form>`)
	formAttrsRE = regexp.MustCompile(`(?is)<form\b([^>]*)>`)
	inputRE     = regexp.MustCompile(`(?is)<input\b[^>]*>`)
	attrRE      = regexp.MustCompile(`(?i)\b([a-z\-]+)\s*=\s*("([^"]*)"|'([^']*)')`)
)

type formCapture struct {
	openTag string
	body    string
}

func extractForms(html string) []formCapture {
	matches := formBlockRE.FindAllStringSubmatchIndex(html, -1)
	out := make([]formCapture, 0, len(matches))
	for _, m := range matches {
		full := html[m[0]:m[1]]
		inner := html[m[2]:m[3]]
		openMatch := formAttrsRE.FindString(full)
		out = append(out, formCapture{openTag: openMatch, body: inner})
	}
	return out
}

func formHasPassword(f formCapture) bool {
	for _, in := range inputRE.FindAllString(f.body, -1) {
		if attrEquals(in, "type", "password") {
			return true
		}
	}
	return false
}

func bestUsernameField(f formCapture) string {
	for _, in := range inputRE.FindAllString(f.body, -1) {
		typ := attrValue(in, "type")
		name := attrValue(in, "name")
		if name == "" {
			continue
		}
		switch strings.ToLower(typ) {
		case "email", "text", "":
			return name
		}
	}
	return ""
}

func bestPasswordField(f formCapture) string {
	for _, in := range inputRE.FindAllString(f.body, -1) {
		if attrEquals(in, "type", "password") {
			return attrValue(in, "name")
		}
	}
	return ""
}

func formAction(f formCapture) string {
	return attrValue(f.openTag, "action")
}

func attrValue(tag, name string) string {
	matches := attrRE.FindAllStringSubmatch(tag, -1)
	for _, m := range matches {
		if !strings.EqualFold(m[1], name) {
			continue
		}
		if m[3] != "" {
			return m[3]
		}
		return m[4]
	}
	return ""
}

func attrEquals(tag, name, want string) bool {
	return strings.EqualFold(attrValue(tag, name), want)
}

// extractReachablePaths returns paths from a recon report (well-knowns,
// sensitives, API specs) for the method-matrix sweep. Capped at maxPaths.
func extractReachablePaths(report *TechStackReport, maxPaths int) []string {
	if report == nil {
		return nil
	}
	seen := map[string]bool{"/": true}
	out := []string{"/"}
	add := func(p string) {
		if p == "" || seen[p] || len(out) >= maxPaths {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	for _, w := range report.WellKnown {
		add(w.Path)
	}
	for _, s := range report.SensitivePaths {
		add(s.Path)
	}
	for _, spec := range report.APISpecs {
		if u, err := url.Parse(spec.URL); err == nil && u.Path != "" {
			add(u.Path)
		}
	}
	return out
}
