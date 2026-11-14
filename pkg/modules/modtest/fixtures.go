package modtest

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	mrand "math/rand/v2"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

// Benign fixtures (MEAS-3): servers with no vulnerability that nonetheless
// behave the ways real targets do and that a careless oracle mistakes for one -
// reflection that is escaped, a WAF answering payloads, a catch-all 200, latency,
// content that changes per request, a rate limiter. Every registered active
// module must stay silent against all of them (pkg/modules/benign_sweep_test.go).
//
// Each constructor returns a fresh handler with its own state, so give every
// module run its own server.

// Fixture names a benign fixture and builds its handler.
type Fixture struct {
	Name string
	// TimingOnly marks fixtures that only timing modules are run against (they
	// are slow by construction).
	TimingOnly bool
	// Deterministic fixtures answer the same input the same way, so a module's
	// request count against them is reproducible and can carry a budget.
	// random_content and slow_host (random latency) vary run to run.
	Deterministic bool
	New           func() http.Handler
}

// BenignFixtures lists every benign fixture.
func BenignFixtures() []Fixture {
	return []Fixture{
		{Name: "safe_echo", Deterministic: true, New: SafeEcho},
		{Name: "waf_block", Deterministic: true, New: WAFBlock},
		{Name: "soft_404", Deterministic: true, New: Soft404},
		{Name: "slow_host", TimingOnly: true, New: func() http.Handler { return SlowHost(300*time.Millisecond, 200*time.Millisecond) }},
		{Name: "random_content", New: RandomContent},
		{Name: "rate_limit_429", Deterministic: true, New: func() http.Handler { return RateLimit429(4) }},
	}
}

// requestValues returns every input the request carried: query and form
// values, plus a JSON body flattened to its leaf strings. Keys are sorted so
// responses are deterministic.
func requestValues(r *http.Request) (keys []string, vals map[string]string) {
	vals = make(map[string]string)
	for k, v := range r.URL.Query() {
		vals[k] = strings.Join(v, ",")
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	switch {
	case strings.Contains(ct, "json"):
		var doc any
		if json.Unmarshal(body, &doc) == nil {
			flattenJSON("", doc, vals)
		} else if len(body) > 0 {
			vals["_body"] = string(body)
		}
	case len(body) > 0:
		if form, err := url.ParseQuery(string(body)); err == nil {
			for k, v := range form {
				vals[k] = strings.Join(v, ",")
			}
		} else {
			vals["_body"] = string(body)
		}
	}
	for k := range vals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys, vals
}

func flattenJSON(prefix string, v any, out map[string]string) {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			name := k
			if prefix != "" {
				name = prefix + "." + k
			}
			flattenJSON(name, child, out)
		}
	case []any:
		for i, child := range t {
			flattenJSON(fmt.Sprintf("%s[%d]", prefix, i), child, out)
		}
	default:
		out[prefix] = fmt.Sprint(t)
	}
}

func writePage(w http.ResponseWriter, status int, title, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, "<!DOCTYPE html>\n<html><head><title>%s</title></head><body>\n%s\n</body></html>\n", title, body)
}

// SafeEcho reflects every input back, correctly encoded for its context: HTML
// escaped in an HTML page for query/form input, JSON encoded in a JSON
// response for JSON bodies. Reflection is not injection.
func SafeEcho() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isJSON := strings.Contains(strings.ToLower(r.Header.Get("Content-Type")), "json")
		keys, vals := requestValues(r)
		if isJSON {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "received": vals})
			return
		}
		var sb strings.Builder
		sb.WriteString("<h1>Search</h1>\n<ul>\n")
		for _, k := range keys {
			fmt.Fprintf(&sb, "<li><b>%s</b>: <span>%s</span></li>\n", html.EscapeString(k), html.EscapeString(vals[k]))
		}
		sb.WriteString("</ul>")
		writePage(w, http.StatusOK, "Results", sb.String())
	})
}

// wafTriggers are substrings a typical managed rule set blocks on.
var wafTriggers = []string{
	"'", "\"", "<", ">", "`", ";", "|", "$(", "${", "{{", "../", "..\\", "%00",
	"select", "union", "sleep", "benchmark", "waitfor", "pg_sleep", "script",
	"onerror", "javascript:", "/etc/", "win.ini", "http://", "https://", "$where", "$ne", "$gt",
}

// WAFBlock answers 200 with a stable page for clean input and a 403 block page
// (Cloudflare-style) for anything containing a common attack token. A payload
// that "changes the response" here only tripped the WAF.
func WAFBlock() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, vals := requestValues(r)
		raw := strings.ToLower(r.URL.Path + " " + r.URL.RawQuery)
		for _, h := range []string{"User-Agent", "X-Forwarded-For", "Cookie"} {
			raw += " " + strings.ToLower(r.Header.Get(h))
		}
		for _, v := range vals {
			raw += " " + strings.ToLower(v)
		}
		if dec, err := url.QueryUnescape(raw); err == nil {
			raw += " " + dec
		}
		for _, t := range wafTriggers {
			if strings.Contains(raw, t) {
				w.Header().Set("Server", "cloudflare")
				w.Header().Set("CF-RAY", "8a1b2c3d4e5f6789-AMS")
				writePage(w, http.StatusForbidden, "Attention Required! | Cloudflare",
					`<h1>Sorry, you have been blocked</h1><p>You are unable to access this site.</p>`+
						`<p>This website is using a security service to protect itself from online attacks.</p>`)
				return
			}
		}
		writePage(w, http.StatusOK, "Catalog", "<h1>Catalog</h1><p>Welcome to the store.</p>")
	})
}

// Soft404 answers every path with 200 and a "not found" page that echoes the
// (escaped) path, the way catch-all SPA and CMS routes do. Existence probes
// that trust the status code see every file "present".
func Soft404() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" || r.URL.Path == "/search" || r.URL.Path == "/api/items" {
			SafeEcho().ServeHTTP(w, r)
			return
		}
		writePage(w, http.StatusOK, "Page not found",
			fmt.Sprintf("<h1>Oops!</h1><p>We could not find <code>%s</code>.</p><a href=\"/\">Home</a>", html.EscapeString(r.URL.Path)))
	})
}

// SlowHost serves SafeEcho after base latency plus up to jitter of uniformly
// random extra delay on every request, payload or not. Timing oracles must
// not read a uniformly slow, noisy host as an injected sleep.
func SlowHost(base, jitter time.Duration) http.Handler {
	echo := SafeEcho()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d := base
		if jitter > 0 {
			d += time.Duration(mrand.Int64N(int64(jitter)))
		}
		select {
		case <-time.After(d):
		case <-r.Context().Done():
			return
		}
		echo.ServeHTTP(w, r)
	})
}

// RandomContent returns a page whose body changes on every request (a random
// token of random length, like a CSRF nonce or ad slot), independent of input.
// Differential oracles must not read instability as a payload effect.
func RandomContent() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := 8 + mrand.IntN(56)
		buf := make([]byte, n)
		_, _ = rand.Read(buf)
		rows := 1 + mrand.IntN(5)
		var sb strings.Builder
		for i := range rows {
			fmt.Fprintf(&sb, "<p>item-%d %s</p>\n", i, hex.EncodeToString(buf[:1+mrand.IntN(n)]))
		}
		writePage(w, http.StatusOK, "Feed", fmt.Sprintf("<input type=hidden name=csrf value=%q>\n%s", hex.EncodeToString(buf), sb.String()))
	})
}

// RateLimit429 serves SafeEcho for the first allow requests, then answers
// every later request 429 with Retry-After - an application limiter that has
// engaged. A payload "causing" a 429 proves nothing.
func RateLimit429(allow int64) http.Handler {
	var n atomic.Int64
	echo := SafeEcho()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) <= allow {
			echo.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Retry-After", "1")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, `{"error":"rate limit exceeded","retry_after":1}`+"\n")
	})
}
