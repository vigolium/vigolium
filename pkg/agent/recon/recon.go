package recon

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Config controls a recon sweep. Zero-valued fields use safe defaults.
type Config struct {
	// Concurrency caps parallel probes. Default 8.
	Concurrency int
	// Timeout is the per-probe HTTP timeout. Default 5s.
	Timeout time.Duration
	// MaxBodyBytes caps the response body we keep per probe before
	// fingerprinting. Default 64KB.
	MaxBodyBytes int
	// UserAgent overrides the User-Agent header. Default
	// "vigolium-recon/1".
	UserAgent string
	// VerifyTLS, when true, enables TLS certificate verification. The
	// default (zero value) skips verification to match the swarm probe
	// client — recon targets are routinely staging/dev hosts with
	// self-signed certs.
	VerifyTLS bool
	// ExtraHeaders are sent on every probe. Used by the swarm CLI to
	// inject --cookie / --header / a synthesized auth-config into recon
	// so authenticated pages get fingerprinted instead of redirected to
	// /login. Header names are sent as-given (no canonicalisation).
	ExtraHeaders map[string]string
}

func (c Config) effective() Config {
	if c.Concurrency <= 0 {
		c.Concurrency = 8
	}
	if c.Timeout <= 0 {
		c.Timeout = 5 * time.Second
	}
	if c.MaxBodyBytes <= 0 {
		c.MaxBodyBytes = 64 * 1024
	}
	if c.UserAgent == "" {
		c.UserAgent = "vigolium-recon/1"
	}
	return c
}

// Run executes a recon sweep against targetURL and returns the
// structured report. targetURL must include scheme and host
// (e.g. "https://example.com"). Path/query are ignored — recon always
// probes paths off the host root.
//
// Run is safe to cancel via ctx; in-flight probes terminate at the
// next context check and the partial report is returned. ProbeErrors
// counts probes that failed for any reason.
func Run(ctx context.Context, targetURL string, cfg Config) (*TechStackReport, error) {
	cfg = cfg.effective()
	parsed, err := url.Parse(targetURL)
	if err != nil || parsed.Host == "" {
		return nil, err
	}
	baseURL := parsed.Scheme + "://" + parsed.Host

	client := newProbeClient(cfg)
	defer client.CloseIdleConnections()

	report := &TechStackReport{
		Hostname:       parsed.Host,
		BaseURL:        baseURL,
		GeneratedAt:    time.Now(),
		AllowedMethods: map[string][]string{},
	}
	started := time.Now()

	// Aggregate state guarded by a single mutex — the work is small
	// enough that lock contention isn't a concern.
	var (
		mu         sync.Mutex
		responses  []*probeResponse
		errs       int
		probes     int
		apiSpecs   []APISpecDetection
		wellKnowns []WellKnownEntry
		sensitives []SensitivePathEntry
	)
	addResp := func(r *probeResponse) {
		if r == nil {
			return
		}
		mu.Lock()
		responses = append(responses, r)
		mu.Unlock()
	}

	sem := make(chan struct{}, cfg.Concurrency)
	var wg sync.WaitGroup

	submit := func(fn func()) {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			fn()
		}()
	}

	// --- Base URL fetch (drives header/cookie/body fingerprints + security-header audit) ---
	submit(func() {
		resp, err := doProbe(ctx, client, http.MethodGet, baseURL+"/", cfg)
		mu.Lock()
		probes++
		mu.Unlock()
		if err != nil {
			mu.Lock()
			errs++
			mu.Unlock()
			return
		}
		addResp(resp)
		// Security headers audit on base URL.
		audit := auditSecurityHeaders(resp.Headers)
		mu.Lock()
		report.SecurityHeaders = audit
		mu.Unlock()
	})

	// --- API spec discovery ---
	for _, spec := range apiSpecPaths {
		spec := spec
		submit(func() {
			resp, err := doProbe(ctx, client, http.MethodGet, baseURL+spec.Path, cfg)
			mu.Lock()
			probes++
			if err != nil {
				errs++
			}
			mu.Unlock()
			if err != nil || resp == nil {
				return
			}
			addResp(resp)
			if isReachable(resp.Status) && looksLikeAPISpec(spec.Kind, resp) {
				mu.Lock()
				apiSpecs = append(apiSpecs, APISpecDetection{
					URL:        baseURL + spec.Path,
					Kind:       spec.Kind,
					StatusCode: resp.Status,
					Reachable:  true,
				})
				mu.Unlock()
			}
		})
	}

	// --- GraphQL introspection probe (POST) ---
	for _, p := range graphqlProbePaths {
		p := p
		submit(func() {
			resp, err := doIntrospect(ctx, client, baseURL+p, cfg)
			mu.Lock()
			probes++
			if err != nil {
				errs++
			}
			mu.Unlock()
			if err != nil || resp == nil {
				return
			}
			addResp(resp)
			if isReachable(resp.Status) && strings.Contains(resp.Body, `"__schema"`) {
				mu.Lock()
				apiSpecs = append(apiSpecs, APISpecDetection{
					URL:        baseURL + p,
					Kind:       "graphql",
					StatusCode: resp.Status,
					Reachable:  true,
					Note:       "introspection enabled",
				})
				mu.Unlock()
			}
		})
	}

	// --- Well-known paths ---
	for _, p := range wellKnownPaths {
		p := p
		submit(func() {
			resp, err := doProbe(ctx, client, http.MethodGet, baseURL+p, cfg)
			mu.Lock()
			probes++
			if err != nil {
				errs++
			}
			mu.Unlock()
			if err != nil || resp == nil {
				return
			}
			addResp(resp)
			if !isReachable(resp.Status) {
				return
			}
			snippet := ""
			if len(resp.Body) > 0 && len(resp.Body) < 4096 && looksTextual(resp.Headers, resp.Body) {
				snippet = truncate(resp.Body, 200)
			}
			mu.Lock()
			wellKnowns = append(wellKnowns, WellKnownEntry{
				Path:       p,
				StatusCode: resp.Status,
				Snippet:    snippet,
			})
			mu.Unlock()
		})
	}

	// --- Stack-probe paths (reachability-only signals) ---
	for _, sp := range stackProbePaths {
		sp := sp
		submit(func() {
			resp, err := doProbe(ctx, client, http.MethodGet, baseURL+sp.Path, cfg)
			mu.Lock()
			probes++
			if err != nil {
				errs++
			}
			mu.Unlock()
			if err != nil || resp == nil {
				return
			}
			addResp(resp)
			if !isReachable(resp.Status) {
				return
			}
			mu.Lock()
			report.Stacks = appendDetection(report.Stacks, StackDetection{
				Name:       sp.Name,
				Category:   sp.Category,
				Tag:        sp.Tag,
				Confidence: ConfidenceHigh,
				Evidence:   []string{sp.Reason + " (" + sp.Path + " " + httpStatus(resp.Status) + ")"},
			})
			mu.Unlock()
		})
	}

	// --- Sensitive paths (record reachability, not contents) ---
	for _, sp := range sensitivePaths {
		sp := sp
		submit(func() {
			resp, err := doProbe(ctx, client, http.MethodGet, baseURL+sp.Path, cfg)
			mu.Lock()
			probes++
			if err != nil {
				errs++
			}
			mu.Unlock()
			if err != nil || resp == nil {
				return
			}
			if !isReachable(resp.Status) {
				return
			}
			mu.Lock()
			sensitives = append(sensitives, SensitivePathEntry{
				Path:       sp.Path,
				StatusCode: resp.Status,
				Reason:     sp.Reason,
			})
			mu.Unlock()
		})
	}

	// --- OPTIONS probes (Allow header collection + CORS detection) ---
	for _, p := range optionsProbePaths {
		p := p
		submit(func() {
			resp, err := doProbe(ctx, client, http.MethodOptions, baseURL+p, cfg)
			mu.Lock()
			probes++
			if err != nil {
				errs++
			}
			mu.Unlock()
			if err != nil || resp == nil {
				return
			}
			if allow := resp.Header("Allow"); allow != "" {
				methods := splitMethods(allow)
				mu.Lock()
				report.AllowedMethods[p] = methods
				mu.Unlock()
			}
		})
	}

	// --- CORS preflight with foreign origin (one probe only) ---
	const testOrigin = "https://recon-probe.invalid"
	submit(func() {
		resp, err := doCORSProbe(ctx, client, baseURL+"/", testOrigin, cfg)
		mu.Lock()
		probes++
		if err != nil {
			errs++
		}
		mu.Unlock()
		if err != nil || resp == nil {
			return
		}
		ao := resp.Header("Access-Control-Allow-Origin")
		if ao == "" {
			return
		}
		cors := &CORSDetection{
			TestedOrigin:     testOrigin,
			AllowOrigin:      ao,
			AllowCredentials: resp.Header("Access-Control-Allow-Credentials"),
			AllowMethods:     resp.Header("Access-Control-Allow-Methods"),
			Permissive:       ao == "*",
			Reflective:       ao == testOrigin,
		}
		mu.Lock()
		report.CORS = cors
		mu.Unlock()
	})

	wg.Wait()

	// Run fingerprint rules only against responses worth inspecting —
	// 404s and connection errors typically carry no Server/X-Powered-By
	// headers worth fingerprinting, and the rules iterate ~18 times
	// per response.
	var baseResp *probeResponse
	for _, r := range responses {
		if r.URL == baseURL+"/" {
			baseResp = r
		}
		if !isReachable(r.Status) {
			continue
		}
		runFingerprintRules(report, r)
	}

	report.APISpecs = apiSpecs
	report.WellKnown = wellKnowns
	report.SensitivePaths = sensitives

	// --- Phase 2 probes (no extra base fetch — reuse baseResp) ---
	if baseResp != nil {
		if signals := runJSFingerprint(baseResp); len(signals) > 0 {
			report.JSSignals = signals
		}
		if logins := runLoginFormScrape(baseResp, baseURL+"/"); len(logins) > 0 {
			report.LoginCandidates = logins
		}
	}

	// --- Phase 2 probes (each adds 1 probe; cheap individually) ---
	if hash := computeFaviconHash(ctx, client, baseURL, cfg); hash != "" {
		report.FaviconHash = hash
		probes++
	}
	if vhosts := runVHostProbe(ctx, client, baseURL, parsed.Host, baseResp, cfg); len(vhosts) > 0 {
		report.VHostFindings = vhosts
		probes += len(vhosts)
	}
	// Method matrix: probe PUT/DELETE/PATCH against up to 8 already-reachable
	// paths. 8 paths × 3 methods = 24 extra probes max — well under recon's
	// usual fan-out, and we only do it when there's surface worth probing.
	if paths := extractReachablePaths(report, 8); len(paths) > 0 {
		if matrix := runMethodMatrix(ctx, client, baseURL, paths, cfg); len(matrix) > 0 {
			report.MethodMatrix = matrix
			for _, methods := range matrix {
				probes += len(methods)
			}
		}
	}

	report.ProbeCount = probes
	report.ProbeErrors = errs
	report.Duration = time.Since(started)
	return report, nil
}

// runFingerprintRules applies stackRules to one response and merges the
// resulting detections into the report. Calls are made from a single
// goroutine after the fan-out has joined, so no locking is needed.
func runFingerprintRules(report *TechStackReport, r *probeResponse) {
	for _, rule := range stackRules {
		ok, version, ev := rule.Match(r)
		if !ok {
			continue
		}
		det := StackDetection{
			Name:       rule.Name,
			Category:   rule.Cat,
			Tag:        rule.Tag,
			Version:    version,
			Confidence: rule.Conf,
		}
		if ev != "" {
			det.Evidence = append(det.Evidence, ev+" (from "+r.URL+")")
		}
		report.Stacks = appendDetection(report.Stacks, det)
	}
}

// appendDetection merges a detection into an existing slice by Name.
// When the name already exists the new evidence is appended and the
// higher-confidence value wins. Versions, if any, follow the same rule
// — first non-empty wins to avoid overwriting a precise version with a
// generic detection.
func appendDetection(dst []StackDetection, in StackDetection) []StackDetection {
	for i := range dst {
		if dst[i].Name != in.Name {
			continue
		}
		dst[i].Evidence = append(dst[i].Evidence, in.Evidence...)
		if dst[i].Version == "" && in.Version != "" {
			dst[i].Version = in.Version
		}
		if in.Confidence > dst[i].Confidence {
			dst[i].Confidence = in.Confidence
		}
		return dst
	}
	return append(dst, in)
}

func newProbeClient(cfg Config) *http.Client {
	return &http.Client{
		Timeout: cfg.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: !cfg.VerifyTLS}, //nolint:gosec
		},
		// Don't follow redirects — a 301 from /robots.txt to /login is itself signal.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func doProbe(ctx context.Context, client *http.Client, method, targetURL string, cfg Config) (*probeResponse, error) {
	req, err := http.NewRequestWithContext(ctx, method, targetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", cfg.UserAgent)
	req.Header.Set("Accept", "*/*")
	applyExtraHeaders(req, cfg)
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

// applyExtraHeaders writes cfg.ExtraHeaders onto req, skipping any that
// would clobber the request line (Host) or break the recon contract
// (User-Agent / Accept are already set above and shouldn't be overridden
// from the synthesized auth config).
func applyExtraHeaders(req *http.Request, cfg Config) {
	if len(cfg.ExtraHeaders) == 0 {
		return
	}
	for k, v := range cfg.ExtraHeaders {
		if v == "" {
			continue
		}
		switch http.CanonicalHeaderKey(k) {
		case "Host":
			req.Host = v
			continue
		case "User-Agent", "Accept":
			continue
		}
		req.Header.Set(k, v)
	}
}

// doIntrospect sends a minimal GraphQL introspection query. The body is
// kept tiny so legitimate GraphQL endpoints respond with __schema and
// non-GraphQL endpoints reject the request cheaply.
func doIntrospect(ctx context.Context, client *http.Client, targetURL string, cfg Config) (*probeResponse, error) {
	const query = `{"query":"{__schema{types{name}}}"}`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, strings.NewReader(query))
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", cfg.UserAgent)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	applyExtraHeaders(req, cfg)
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

// doCORSProbe sends a preflight OPTIONS with a foreign Origin so we can
// observe Access-Control-Allow-Origin behavior. The request advertises
// a benign GET to keep the probe non-mutating.
func doCORSProbe(ctx context.Context, client *http.Client, targetURL, origin string, cfg Config) (*probeResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodOptions, targetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", cfg.UserAgent)
	req.Header.Set("Origin", origin)
	req.Header.Set("Access-Control-Request-Method", "GET")
	applyExtraHeaders(req, cfg)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	// We don't care about the body for CORS.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return &probeResponse{
		URL:     targetURL,
		Status:  resp.StatusCode,
		Headers: resp.Header.Clone(),
	}, nil
}

// auditSecurityHeaders flags missing trackedSecurityHeaders on the base
// URL response. Present headers keep their original casing for display.
func auditSecurityHeaders(h http.Header) SecurityHeadersAudit {
	audit := SecurityHeadersAudit{Present: map[string]string{}}
	for _, name := range trackedSecurityHeaders {
		v := h.Get(name)
		if v == "" {
			audit.Missing = append(audit.Missing, name)
		} else {
			audit.Present[name] = v
		}
	}
	return audit
}

// isReachable treats 2xx and 3xx as "this path exists". 401/403 are
// also treated as reachable for stack/sensitive probes — an auth-gated
// /actuator/env is still very much a Spring Boot signal.
func isReachable(status int) bool {
	if status >= 200 && status < 400 {
		return true
	}
	if status == 401 || status == 403 {
		return true
	}
	return false
}

// looksLikeAPISpec sanity-checks the body of a candidate spec response
// so we don't flag generic 200 OK HTML responses returned by a catch-all
// route. Cheap heuristics — no JSON/YAML parse.
func looksLikeAPISpec(kind string, r *probeResponse) bool {
	body := r.Body
	switch kind {
	case "openapi":
		return strings.Contains(body, `"openapi"`) || strings.Contains(body, "openapi:") ||
			strings.Contains(body, `"swagger"`) // some servers serve OpenAPI v2 at openapi.json
	case "swagger":
		return strings.Contains(body, `"swagger"`) || strings.Contains(body, "swagger:") ||
			strings.Contains(body, `"openapi"`)
	case "postman":
		return strings.Contains(body, `"_postman_id"`) || strings.Contains(body, `"info"`)
	case "asyncapi":
		return strings.Contains(body, `"asyncapi"`) || strings.Contains(body, "asyncapi:")
	}
	return false
}

// looksTextual returns true when a response is small, looks text-like,
// and is therefore safe to snippet into the report. Used for
// /robots.txt-style entries.
func looksTextual(h http.Header, body string) bool {
	ct := strings.ToLower(h.Get("Content-Type"))
	if ct == "" {
		// Permit only printable ASCII bodies when Content-Type is absent.
		for _, b := range body {
			if b > 0x7e || (b < 0x20 && b != '\n' && b != '\r' && b != '\t') {
				return false
			}
		}
		return true
	}
	return strings.HasPrefix(ct, "text/") ||
		strings.Contains(ct, "json") ||
		strings.Contains(ct, "xml") ||
		strings.Contains(ct, "yaml")
}

func splitMethods(allow string) []string {
	parts := strings.Split(allow, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func httpStatus(code int) string {
	if code == 0 {
		return "no response"
	}
	switch code / 100 {
	case 2:
		return "200-class"
	case 3:
		return "redirect"
	case 4:
		if code == 401 {
			return "401"
		}
		if code == 403 {
			return "403"
		}
		return "client error"
	case 5:
		return "server error"
	}
	return "unknown"
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
