// Package recon performs a lightweight, conservative reconnaissance sweep
// against a target host before the swarm plan agent runs. The output
// (TechStackReport) is rendered into the planner prompt so module
// selection and focus areas are informed by detected stack, exposed
// well-known paths, CORS posture, and security-header gaps — coverage
// that black-box scans previously had to infer from raw request/response
// records alone.
package recon

import (
	"encoding/json"
	"fmt"
	"time"
)

// Confidence is the strength of a stack-detection signal. Higher values
// outrank lower ones in appendDetection's merge logic and in Render's
// sort. The JSON wire format is a string ("high"/"medium"/"low") so
// recon-report.json stays human-readable.
type Confidence int

const (
	ConfidenceLow    Confidence = 1
	ConfidenceMedium Confidence = 2
	ConfidenceHigh   Confidence = 3
)

func (c Confidence) String() string {
	switch c {
	case ConfidenceHigh:
		return "high"
	case ConfidenceMedium:
		return "medium"
	case ConfidenceLow:
		return "low"
	}
	return ""
}

func (c Confidence) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.String())
}

func (c *Confidence) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	switch s {
	case "high":
		*c = ConfidenceHigh
	case "medium":
		*c = ConfidenceMedium
	case "low":
		*c = ConfidenceLow
	case "":
		*c = 0
	default:
		return fmt.Errorf("invalid confidence %q", s)
	}
	return nil
}

// TechStackReport is the structured output of a recon sweep against one
// host. Persisted to the session dir as recon-report.json and rendered
// into the plan agent's prompt context via Render().
type TechStackReport struct {
	Hostname        string               `json:"hostname"`
	BaseURL         string               `json:"base_url"`
	GeneratedAt     time.Time            `json:"generated_at"`
	Stacks          []StackDetection     `json:"stacks,omitempty"`
	APISpecs        []APISpecDetection   `json:"api_specs,omitempty"`
	WellKnown       []WellKnownEntry     `json:"well_known,omitempty"`
	SecurityHeaders SecurityHeadersAudit `json:"security_headers"`
	CORS            *CORSDetection       `json:"cors,omitempty"`
	AllowedMethods  map[string][]string  `json:"allowed_methods,omitempty"` // path -> methods reported by OPTIONS Allow
	SensitivePaths  []SensitivePathEntry `json:"sensitive_paths,omitempty"` // /.env, /.git/HEAD, etc.

	// Expanded recon signals (task A). These are added to maximize
	// no-source coverage by surfacing surface-area hints that lightweight
	// well-known probing alone won't catch.

	// JSSignals records JavaScript-framework markers parsed from the base
	// URL's HTML (inline scripts + <script src> URLs). Webpack chunks,
	// Next.js _next/static paths, Vite client, React/Vue/Angular runtimes,
	// SPA SSR markers, etc. Drives "this app is a Next.js SPA" hints to
	// the plan agent so it can prefer client-side / SPA-specific modules.
	JSSignals []JSFrameworkSignal `json:"js_signals,omitempty"`

	// FaviconHash is the MD5 of /favicon.ico. Useful for the planner to
	// correlate with known signatures (Shodan/favicon hash databases).
	FaviconHash string `json:"favicon_hash,omitempty"`

	// VHostFindings records anomalies observed when probing alternate
	// Host headers (localhost, admin.<host>, target IP). Differences in
	// body length / status often surface virtual-host isolation issues,
	// staging environments, or admin panels.
	VHostFindings []VHostFinding `json:"vhost_findings,omitempty"`

	// MethodMatrix records per-path HTTP methods that returned non-405
	// responses beyond what the conservative OPTIONS probe revealed. Useful
	// when servers don't implement Allow on OPTIONS but still accept e.g.
	// PUT/DELETE on a path that returns 200 to GET — a strong access-
	// control flag for the planner.
	MethodMatrix map[string][]string `json:"method_matrix,omitempty"`

	// LoginCandidates records HTML forms scraped from probed pages that
	// look like login pages (input[type=password] present). Surfaces to
	// the planner so it can recommend authenticated scans when creds are
	// available, and so the CLI can suggest `--browser-auth` to the user.
	LoginCandidates []LoginCandidate `json:"login_candidates,omitempty"`

	ProbeCount  int           `json:"probe_count"`
	ProbeErrors int           `json:"probe_errors,omitempty"`
	Duration    time.Duration `json:"duration"`
	Notes       []string      `json:"notes,omitempty"`
}

// JSFrameworkSignal is a single client-side framework / bundler signal
// extracted from the base URL response (HTML body or fetched JS).
type JSFrameworkSignal struct {
	Name     string `json:"name"`              // "next", "react", "vue", "angular", "vite", "webpack", "svelte", "nuxt"
	Tag      string `json:"tag,omitempty"`     // module tag the planner can emit
	Evidence string `json:"evidence,omitempty"`
}

// VHostFinding records a Host-header variant whose response differs
// from the baseline in a way worth telling the planner about.
type VHostFinding struct {
	Host         string `json:"host"`               // Host header value sent
	StatusCode   int    `json:"status_code"`        // observed status
	BodyDelta    int    `json:"body_delta"`         // |observed - baseline| body length
	BaselineCode int    `json:"baseline_code"`      // baseline status (default GET / with normal Host)
	Reason       string `json:"reason,omitempty"`   // human-readable why-it-matters
}

// LoginCandidate is a probed page that exposes a login form.
type LoginCandidate struct {
	URL          string `json:"url"`
	UsernameName string `json:"username_name,omitempty"` // best-guess name= attribute of the username field
	PasswordName string `json:"password_name,omitempty"` // best-guess name= attribute of the password field
	Action       string `json:"action,omitempty"`        // form action URL (relative or absolute)
}

// StackDetection is a single framework / CMS / server / language signal.
// One detection may have multiple lines of evidence collected from
// different probes; the renderer flattens these for the prompt.
type StackDetection struct {
	Name       string     `json:"name"`               // e.g. "spring-boot", "wordpress", "express", "nginx"
	Category   string     `json:"category"`           // "cms", "framework", "server", "language", "metaframework", "cdn"
	Version    string     `json:"version,omitempty"`  // extracted version when available
	Tag        string     `json:"tag,omitempty"`      // module tag the planner may emit, e.g. "spring", "wordpress"
	Evidence   []string   `json:"evidence,omitempty"` // human-readable evidence lines
	Confidence Confidence `json:"confidence"`
}

// APISpecDetection records a discovered OpenAPI/Swagger/GraphQL endpoint.
type APISpecDetection struct {
	URL        string `json:"url"`
	Kind       string `json:"kind"` // "openapi", "swagger", "graphql", "postman", "asyncapi"
	StatusCode int    `json:"status_code"`
	Reachable  bool   `json:"reachable"`
	Note       string `json:"note,omitempty"` // e.g. "introspection enabled"
}

// WellKnownEntry records a probed /.well-known/* path.
type WellKnownEntry struct {
	Path       string `json:"path"`
	StatusCode int    `json:"status_code"`
	Snippet    string `json:"snippet,omitempty"` // first ~200 bytes when the response is small and text/plain
}

// SecurityHeadersAudit summarizes which security-relevant headers were
// present or missing on the base URL response.
type SecurityHeadersAudit struct {
	Present map[string]string `json:"present,omitempty"`
	Missing []string          `json:"missing,omitempty"`
}

// CORSDetection summarizes the response to an OPTIONS preflight with a
// foreign Origin. Permissive/Reflective flags are what the planner
// actually cares about.
type CORSDetection struct {
	TestedOrigin     string `json:"tested_origin"`
	AllowOrigin      string `json:"allow_origin,omitempty"`
	AllowCredentials string `json:"allow_credentials,omitempty"`
	AllowMethods     string `json:"allow_methods,omitempty"`
	Reflective       bool   `json:"reflective,omitempty"` // ACAO echoed the tested origin
	Permissive       bool   `json:"permissive,omitempty"` // ACAO == "*"
}

// SensitivePathEntry flags a path whose mere reachability is a concern
// (e.g. /.git/HEAD). We deliberately do NOT capture body contents here
// to avoid persisting secrets to the session dir.
type SensitivePathEntry struct {
	Path       string `json:"path"`
	StatusCode int    `json:"status_code"`
	Reason     string `json:"reason"` // e.g. "git metadata exposed", "env file reachable"
}

// HasSignal reports whether the report carries any signal worth showing
// the planner. Reports with no detections, no specs, no CORS issues, and
// no missing security headers are skipped to keep the prompt lean.
func (r *TechStackReport) HasSignal() bool {
	if r == nil {
		return false
	}
	if len(r.Stacks) > 0 || len(r.APISpecs) > 0 || len(r.SensitivePaths) > 0 {
		return true
	}
	if r.CORS != nil && (r.CORS.Permissive || r.CORS.Reflective) {
		return true
	}
	if len(r.SecurityHeaders.Missing) > 0 {
		return true
	}
	if len(r.AllowedMethods) > 0 {
		return true
	}
	if len(r.JSSignals) > 0 || len(r.VHostFindings) > 0 ||
		len(r.LoginCandidates) > 0 || len(r.MethodMatrix) > 0 || r.FaviconHash != "" {
		return true
	}
	for _, w := range r.WellKnown {
		if w.StatusCode > 0 && w.StatusCode < 400 {
			return true
		}
	}
	return false
}

// ModuleTagSuggestions returns the set of unique module tags the
// detected stacks suggest the planner should focus the scan on. Order
// is preserved by detection order so high-confidence detections appear
// first. JS framework signals contribute their tags too (Next.js,
// React, Vue, Angular, etc.) when no equivalent stack detection was
// already added.
func (r *TechStackReport) ModuleTagSuggestions() []string {
	if r == nil {
		return nil
	}
	seen := make(map[string]struct{}, len(r.Stacks)+len(r.JSSignals))
	out := make([]string, 0, len(r.Stacks)+len(r.JSSignals))
	for _, s := range r.Stacks {
		if s.Tag == "" {
			continue
		}
		if _, ok := seen[s.Tag]; ok {
			continue
		}
		seen[s.Tag] = struct{}{}
		out = append(out, s.Tag)
	}
	for _, j := range r.JSSignals {
		if j.Tag == "" {
			continue
		}
		if _, ok := seen[j.Tag]; ok {
			continue
		}
		seen[j.Tag] = struct{}{}
		out = append(out, j.Tag)
	}
	return out
}
