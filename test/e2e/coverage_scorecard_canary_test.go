//go:build canary

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/internal/runner"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/source"
	"github.com/vigolium/vigolium/pkg/types"
)

// Ground-truth coverage scorecards.
//
// These tests answer "did Vigolium actually catch the vulns that are really in
// this app?" — not against a hand-picked module per endpoint (that's the
// whitebox benchmark), but against a source-derived ground-truth catalog. Each
// catalog entry was extracted by reading the vulnerable app's own source
// (/Users/j3ssie/Desktop/vuln-apps/{DVWA,VAmPI,juice-shop,crAPI}), or — for
// vulnerable-java, whose shipped image diverges from its benchmark definition —
// by reverse-engineering the live endpoints, giving exact route, parameter, and
// sink — and tagged with a reachability tier:
//
//   - tierReachable   — a request/response DAST can trigger AND observe it from a
//                       single (or dual) HTTP exchange. These are the honest
//                       must-catch cases; the tests hard-gate a floor of them.
//   - tierPartial     — reachable only with auth + a second identity, response
//                       diffing, timing/OAST, or a multi-step flow. Logged as
//                       CATCH/MISS but never gated (a generic scan may miss them
//                       legitimately).
//   - tierUnreachable — fundamentally invisible to a server-response scanner:
//                       DOM-only XSS, offline JWT forgery, client-side logic,
//                       broken crypto. Documented so the scorecard is honest
//                       about what NOT to expect, never scanned/gated.
//
// The scan seeds each app's real vulnerable surface (DVWA: the exact vulnerable
// requests with the app's own default params + an authenticated session; VAmPI:
// its published OpenAPI spec) into a stateless file DB, runs the FULL active +
// passive module set (tech-gating disabled so capability — not gating — is what
// is measured), then matches every persisted finding back to the catalog.

// gtTier is a ground-truth reachability tier (see file header).
type gtTier string

const (
	tierReachable   gtTier = "reachable"
	tierPartial     gtTier = "partial"
	tierUnreachable gtTier = "unreachable"
)

// gtVuln is one source-verified vulnerability plus how to seed it and how to
// recognize a matching finding.
type gtVuln struct {
	id    string // short slug
	class string // vuln class label (sqli, xss-reflected, lfi, ...)
	tier  gtTier

	// Seeding (tierReachable/tierPartial only). When seedPath is set, a request
	// is synthesized and fed to the scan; tierUnreachable entries leave it empty.
	seedMethod      string
	seedPath        string // path + query, e.g. "/vulnerabilities/sqli/?id=1&Submit=Submit"
	seedBody        string
	seedContentType string

	// Matching: a finding counts as a catch when its URL contains routeMatch
	// (when set) AND its ModuleID contains any of modules (when set). An empty
	// modules slice means "any finding on this route counts".
	routeMatch string
	modules    []string

	note string
}

// logScanCommand prints the equivalent `vigolium scan` CLI invocation for an
// in-process scorecard scan, so a reader can reproduce it by hand. The scorecard
// runs the scan in-process (via the runner, the same engine the CLI uses) for
// speed and direct DB assertions; this line is the copy-pasteable equivalent.
// Credential header VALUES are masked — the token/cookie is ephemeral and
// re-minted each run — with a note on how to obtain a fresh one.
func logScanCommand(t *testing.T, label string, inputSpec string, targets, headers []string) {
	t.Helper()
	parts := []string{"vigolium", "scan"}
	if inputSpec != "" {
		parts = append(parts, "-i", inputSpec)
	}
	for _, tg := range targets {
		parts = append(parts, "-t", "'"+tg+"'")
	}
	for _, h := range headers {
		parts = append(parts, "-H", "'"+maskCredentialHeader(h)+"'")
	}
	parts = append(parts, "--modules", "all", "--only", "dynamic-assessment", "--no-tech-filter", "-S", "--db", "/tmp/scan.sqlite")
	t.Logf("[%s] ▶ replicate this scan on the CLI:\n    %s", label, strings.Join(parts, " "))
}

// maskCredentialHeader replaces a credential header's secret value with a
// placeholder so the logged command is safe to share while still showing the
// header shape needed to reproduce the scan.
func maskCredentialHeader(h string) string {
	lower := strings.ToLower(strings.TrimSpace(h))
	switch {
	case strings.HasPrefix(lower, "cookie:"):
		return "Cookie: <your-session-cookie>"
	case strings.HasPrefix(lower, "authorization: bearer"):
		return "Authorization: Bearer <your-jwt>"
	case strings.HasPrefix(lower, "authorization:"):
		return "Authorization: <your-credential>"
	}
	return h
}

// catalogTargets builds the seed URLs (baseURL + seedPath) for every seedable
// GET catalog entry. These feed target-based ingestion, which faithfully
// reproduces `vigolium scan -t <url> -H <header>`: the auth/transport headers on
// opts.Headers reach the modules' probes. (A hand-built slice source does NOT —
// on an authenticated app like DVWA the cookie never reaches the probes, so the
// injection modules see login redirects and report nothing. Confirmed against
// the real binary: target-based catches DVWA SQLi/LFI/XSS, slice-source misses.)
// POST-body entries can't be expressed as a GET target, so they are skipped here
// and reported as MISS with a note rather than seeded.
func catalogTargets(baseURL string, catalog []gtVuln) []string {
	seen := map[string]bool{}
	var targets []string
	for _, v := range catalog {
		if v.seedPath == "" || v.seedBody != "" || (v.seedMethod != "" && v.seedMethod != "GET") {
			continue
		}
		u := baseURL + v.seedPath
		if !seen[u] {
			seen[u] = true
			targets = append(targets, u)
		}
	}
	return targets
}

// dynamicAssessmentOpts builds the options shared by every scorecard scan: a
// silent, stateless, tech-filter-off, dynamic-assessment-only run (no discovery,
// spidering, external harvest, or known-issue scan) over the given targets with
// the given active module set. Callers layer on their auth carrier
// (opts.Headers / opts.AuthFiles) and, for seeded scans, an input source.
func dynamicAssessmentOpts(targets, modules []string) *types.Options {
	opts := types.DefaultOptions()
	opts.Targets = targets
	opts.Modules = modules
	opts.PassiveModules = []string{"all"}
	opts.Silent = true
	opts.Stateless = true
	opts.HeuristicsCheck = "none"
	opts.NoTechFilter = true // measure capability, not tech-stack gating
	opts.DiscoverEnabled = false
	opts.SpideringEnabled = false
	opts.ExternalHarvestEnabled = false
	opts.KnownIssueScanEnabled = false
	opts.SkipDynamicAssessment = false
	opts.ScanMaxDuration = 10 * time.Minute
	return opts
}

// scorecardSettings builds the settings shared by every scorecard scan: the
// defaults with the hardening-advisory gate forced OFF.
//
// The gate (internal/runner/module_tiers.go) suppresses the modules tagged
// "hygiene" — missing security headers, CSP/HSTS/SRI audits, cookie attributes,
// TLS policy — below --intensity deep, because on a real crawl they file one
// near-identical Info/Low row per URL and bury the exploitable findings. That is
// the right default for an operator's report and the wrong one here: a scorecard
// measures what Vigolium *can* detect against a fixed ground truth, so a
// capability the default run merely declines to print must still be measured.
// Same reasoning as dynamicAssessmentOpts's NoTechFilter.
//
// Safe to apply to every scorecard: it only ever adds findings, so it can turn a
// ground-truth MISS into a CATCH but never the reverse.
func scorecardSettings() *config.Settings {
	settings := config.DefaultSettings()
	hygiene := true
	settings.DynamicAssessment.HygieneModules = &hygiene
	return settings
}

// scorecardFindings reads back every finding from a scorecard scan's DB —
// including candidate/observation record-kinds, not just confirmed findings: a
// module that downgrades a detection to a candidate under FP-hardening still
// counts as "the scanner caught it" for coverage, and the default query would
// hide those, understating real coverage.
func scorecardFindings(t *testing.T, db *database.DB) []*database.Finding {
	t.Helper()
	findings, err := database.NewFindingsQueryBuilder(db, database.QueryFilters{
		ProjectUUID: database.DefaultProjectUUID,
		Limit:       1000,
		RecordKinds: []string{database.RecordKindFinding, database.RecordKindCandidate, database.RecordKindObservation},
	}).Execute(context.Background())
	require.NoError(t, err, "read back findings")
	return findings
}

// scorecardRecords reads back the ingested HTTP records from a scan's DB, used to
// prove an authenticated scan reached the protected (2xx) surface.
func scorecardRecords(t *testing.T, db *database.DB) []*database.HTTPRecord {
	t.Helper()
	records, err := database.NewQueryBuilder(db, database.QueryFilters{ProjectUUID: database.DefaultProjectUUID}).Execute(context.Background())
	require.NoError(t, err, "read back records")
	return records
}

// runScorecardScan runs the full active+passive module set over the given targets
// exactly as `vigolium scan -t <targets...> -H <headers...> --only
// dynamic-assessment` would: targets are the input source, auth/transport headers
// are applied via opts.Headers, and every finding (including candidate/observation
// record-kinds) is returned. tech-gating is disabled to measure capability.
func runScorecardScan(t *testing.T, targets []string, headers []string) []*database.Finding {
	t.Helper()
	logScanCommand(t, "scorecard", "", targets, headers)

	db, repo := setupStatelessTempDB(t)
	opts := dynamicAssessmentOpts(targets, []string{"all"})
	opts.Headers = headers

	r, err := runner.New(opts)
	require.NoError(t, err, "create scorecard scan runner")
	r.SetSettings(scorecardSettings())
	r.SetRepository(repo)
	t.Cleanup(func() { r.Close() })

	err = r.RunNativeScan()
	skipIfTargetDied(t, err, targets[0])
	require.NoError(t, err, "scorecard scan should complete without error")
	return scorecardFindings(t, db)
}

// runSeededScorecardScan ingests the seed items into a stateless file DB and runs
// the full dynamic-assessment module set over them (no discovery/spidering — the
// surface is provided), then returns the persisted findings. Mirrors the real
// `vigolium scan --stateless` DA path (see runImportToDBScan) but over an
// arbitrary seed set with tech-filtering disabled.
func runSeededScorecardScan(t *testing.T, baseURL string, items []*httpmsg.HttpRequestResponse, headers []string) []*database.Finding {
	t.Helper()
	// The seeded scans feed a spec/import source (e.g. VAmPI's OpenAPI); the CLI
	// equivalent imports that spec and points it at the live base URL.
	logScanCommand(t, "seeded-scorecard", "<import-spec e.g. vampi-openapi3.yml>", []string{baseURL}, headers)

	db, repo := setupStatelessTempDB(t)
	opts := dynamicAssessmentOpts([]string{baseURL}, []string{"all"})
	opts.Headers = headers

	src := source.NewSliceSource(items, opts.Modules)
	r, err := runner.NewWithInputSource(opts, src)
	require.NoError(t, err, "create seeded scan runner")
	r.SetSettings(scorecardSettings())
	r.SetRepository(repo)
	t.Cleanup(func() { r.Close() })

	require.NoError(t, r.RunNativeScan(), "seeded dynamic-assessment scan should complete without error")
	return scorecardFindings(t, db)
}

// matchVuln reports whether any finding satisfies the catalog entry's match rule,
// returning the matching "moduleID (record_kind)" for the scorecard log.
func matchVuln(v gtVuln, findings []*database.Finding) (bool, string) {
	// A catalog entry with neither a routeMatch nor a module list has no matching
	// criteria — it is documentation only (e.g. crAPI vulns not seeded by this
	// scan). Never let such an entry match an arbitrary finding.
	if v.routeMatch == "" && len(v.modules) == 0 {
		return false, ""
	}
	for _, f := range findings {
		if v.routeMatch != "" && !strings.Contains(f.URL, v.routeMatch) {
			continue
		}
		if len(v.modules) == 0 {
			return true, findingLabel(f)
		}
		for _, m := range v.modules {
			if moduleIDMatches(f.ModuleID, m) {
				return true, findingLabel(f)
			}
		}
	}
	return false, ""
}

// moduleIDMatches reports whether pattern appears in moduleID at a word boundary
// (the start of the ID, or right after a '-' separator). This keeps a class
// pattern like "sqli" matching "sqli-error-based" while NOT matching
// "nosqli-operator-injection" — one vuln class's ID being a substring of
// another's would otherwise inflate coverage or mask a regression.
func moduleIDMatches(moduleID, pattern string) bool {
	for i := 0; ; {
		idx := strings.Index(moduleID[i:], pattern)
		if idx < 0 {
			return false
		}
		at := i + idx
		if at == 0 || moduleID[at-1] == '-' {
			return true
		}
		i = at + 1
	}
}

// findingLabel renders a finding as "module-id (record-kind)" for the scorecard,
// marking candidate/observation catches so a lower-confidence detection is
// visibly distinguished from a confirmed finding.
func findingLabel(f *database.Finding) string {
	kind := f.RecordKind
	if kind == "" {
		kind = database.RecordKindFinding
	}
	return f.ModuleID + " (" + kind + ")"
}

// scorecardResult is the per-tier tally the caller gates on.
type scorecardResult struct {
	caught map[string]bool // vuln id -> caught
	reTot  int             // reachable-tier total
	reHit  int             // reachable-tier caught
}

// reportScorecard logs a per-vuln CATCH/MISS line and a tier summary, and returns
// the tally. tierUnreachable entries are printed as SKIP (never expected).
func reportScorecard(t *testing.T, app string, catalog []gtVuln, findings []*database.Finding) scorecardResult {
	t.Helper()
	res := scorecardResult{caught: map[string]bool{}}

	// Stable order: reachable first, then partial, then unreachable.
	order := map[gtTier]int{tierReachable: 0, tierPartial: 1, tierUnreachable: 2}
	sorted := append([]gtVuln(nil), catalog...)
	sort.SliceStable(sorted, func(i, j int) bool { return order[sorted[i].tier] < order[sorted[j].tier] })

	partHit, partTot := 0, 0
	for _, v := range sorted {
		if v.tier == tierUnreachable {
			t.Logf("[%s][%-11s] %-30s %-22s SKIP  (%s)", app, v.tier, v.id, v.class, v.note)
			continue
		}
		caught, by := matchVuln(v, findings)
		res.caught[v.id] = caught
		status, detail := "MISS", ""
		if caught {
			status, detail = "CATCH", " via "+by
		}
		t.Logf("[%s][%-11s] %-30s %-22s %s%s", app, v.tier, v.id, v.class, status, detail)
		switch v.tier {
		case tierReachable:
			res.reTot++
			if caught {
				res.reHit++
			}
		case tierPartial:
			partTot++
			if caught {
				partHit++
			}
		}
	}
	t.Logf("[%s] SCORECARD — reachable: %d/%d caught | partial: %d/%d | (unreachable tier not expected)",
		app, res.reHit, res.reTot, partHit, partTot)

	// Dump every module that fired (with its record-kind) so the scorecard is
	// self-documenting: a MISS can be told apart from a catalog-matcher gap.
	fired := map[string]int{}
	for _, f := range findings {
		fired[findingLabel(f)]++
	}
	keys := make([]string, 0, len(fired))
	for k := range fired {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	t.Logf("[%s] all findings (%d total across %d module/kind combos): %v", app, len(findings), len(keys), keys)
	return res
}

// mustCatch asserts the named catalog entries were caught — the honest hard gate
// (only classes we have independent evidence Vigolium detects).
func mustCatch(t *testing.T, app string, res scorecardResult, ids ...string) {
	t.Helper()
	for _, id := range ids {
		assert.Truef(t, res.caught[id], "[%s] expected to CATCH ground-truth vuln %q but it was MISSED", app, id)
	}
}

// ---------------------------------------------------------------------------
// DVWA — /Users/j3ssie/Desktop/vuln-apps/DVWA, security=low (source-verified)
// ---------------------------------------------------------------------------

func dvwaCatalog() []gtVuln {
	return []gtVuln{
		// --- Cleanly DAST-reachable (single/dual request, server-observable) ---
		{id: "dvwa-sqli", class: "sqli", tier: tierReachable,
			seedMethod: "GET", seedPath: "/vulnerabilities/sqli/?id=1&Submit=Submit",
			routeMatch: "/vulnerabilities/sqli/", modules: []string{"sqli"},
			note: "sqli/source/low.php:10 raw string interpolation of $id → error-based"},
		{id: "dvwa-sqli-blind", class: "sqli-blind", tier: tierReachable,
			seedMethod: "GET", seedPath: "/vulnerabilities/sqli_blind/?id=1&Submit=Submit",
			routeMatch: "/vulnerabilities/sqli_blind/", modules: []string{"sqli"},
			note: "sqli_blind/source/low.php:11 boolean/time oracle (200 vs 404)"},
		{id: "dvwa-xss-reflected", class: "xss-reflected", tier: tierReachable,
			seedMethod: "GET", seedPath: "/vulnerabilities/xss_r/?name=test",
			routeMatch: "/vulnerabilities/xss_r/", modules: []string{"xss"},
			note: "xss_r/source/low.php:8 $_GET['name'] echoed unencoded"},
		{id: "dvwa-cmdi", class: "rce-cmdi", tier: tierReachable,
			seedMethod: "POST", seedPath: "/vulnerabilities/exec/", seedBody: "ip=127.0.0.1&Submit=Submit",
			seedContentType: "application/x-www-form-urlencoded",
			routeMatch:      "/vulnerabilities/exec/", modules: []string{"command", "cmdi", "code-exec", "rce"},
			note: "exec/source/low.php:14 shell_exec('ping -c 4 '.$target) reflected in <pre> (fires as code-exec)"},
		{id: "dvwa-lfi", class: "lfi", tier: tierReachable,
			seedMethod: "GET", seedPath: "/vulnerabilities/fi/?page=include.php",
			routeMatch: "/vulnerabilities/fi/", modules: []string{"lfi", "file-inclusion", "traversal", "path"},
			note: "fi/index.php:36 include($_GET['page']) unfiltered"},
		{id: "dvwa-open-redirect", class: "open-redirect", tier: tierReachable,
			seedMethod: "GET", seedPath: "/vulnerabilities/open_redirect/source/low.php?redirect=https://example.org/",
			routeMatch: "/open_redirect/", modules: []string{"openredirect", "open-redirect"},
			note: "open_redirect/source/low.php:4 header('location: '.$_GET['redirect'])"},
		{id: "dvwa-api-v1-password-exposure", class: "excessive-data-exposure", tier: tierReachable,
			seedMethod: "GET", seedPath: "/vulnerabilities/api/v1/user/",
			routeMatch: "/api/v1/user", modules: []string{"secret", "exposure", "sensitive", "info-disclosure"},
			note: "api/src/User.php:38 v1 toArray() includes password hash; raw API needs no DVWA session"},

		// --- Reachable-but-partial (2 requests / passive / active state-change) ---
		{id: "dvwa-xss-stored", class: "xss-stored", tier: tierPartial,
			seedMethod: "POST", seedPath: "/vulnerabilities/xss_s/",
			seedBody:        "txtName=z&mtxMessage=hello&btnSign=Sign+Guestbook",
			seedContentType: "application/x-www-form-urlencoded",
			routeMatch:      "/vulnerabilities/xss_s/", modules: []string{"xss"},
			note: "xss_s stores unencoded input; detection needs store-then-read (2 requests)"},
		{id: "dvwa-csrf", class: "csrf", tier: tierPartial,
			seedMethod: "GET", seedPath: "/vulnerabilities/csrf/?password_new=x&password_conf=x&Change=Change",
			routeMatch: "/vulnerabilities/csrf/", modules: []string{"csrf"},
			note: "csrf/source/low.php password-change via tokenless GET (missing-token is passive)"},
		{id: "dvwa-brute-force", class: "brute-force+sqli", tier: tierPartial,
			seedMethod: "GET", seedPath: "/vulnerabilities/brute/?username=admin&password=password&Login=Login",
			routeMatch: "/vulnerabilities/brute/", modules: []string{"sqli", "brute", "credential"},
			note: "brute/source/low.php:12 no lockout + username SQLi (admin' -- )"},
		{id: "dvwa-weak-session-id", class: "weak-session-id", tier: tierPartial,
			seedMethod: "POST", seedPath: "/vulnerabilities/weak_id/",
			routeMatch: "/vulnerabilities/weak_id/", modules: []string{"session", "cookie"},
			note: "weak_id/source/low.php:9 sequential dvwaSession cookie (compare across requests)"},
		{id: "dvwa-api-cmdi-connectivity", class: "rce-cmdi-blind", tier: tierPartial,
			seedMethod: "POST", seedPath: "/vulnerabilities/api/v2/health/connectivity",
			seedBody: `{"target":"127.0.0.1"}`, seedContentType: "application/json",
			routeMatch: "/health/connectivity", modules: []string{"command", "cmdi", "oast"},
			note: "api/src/HealthController.php:88 exec(ping+$target) blind — needs timing/OAST"},

		// --- Fundamentally unreachable by a server-response scanner ---
		{id: "dvwa-xss-dom", class: "xss-dom", tier: tierUnreachable,
			note: "xss_d payload lives only in document.location→document.write; never in server body"},
		{id: "dvwa-weak-crypto", class: "weak-crypto", tier: tierUnreachable,
			note: "cryptography/source/low.php hardcoded XOR key — source-only design flaw"},
		{id: "dvwa-js-client-control", class: "client-side-control", tier: tierUnreachable,
			note: "javascript/ token = md5(rot13(phrase)) enforced client-side; not response-visible"},
	}
}

// TestCoverageScorecard_DVWA seeds DVWA's exact source-verified vulnerable
// requests (authenticated, security=low) and scores the full module set against
// the ground truth. The hard gate covers the injection classes Vigolium is known
// to detect (proven independently by TestDVWA_SQLi / _XSS / _LFI); everything
// else is reported as CATCH/MISS for a coverage picture without brittle gating.
func TestCoverageScorecard_DVWA(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping canary test in short mode")
	}

	app := startDVWA(t)
	cookie := setupDVWA(t, app.BaseURL)
	// Cookie unlocks the vulnerable pages; Accept-Encoding: identity avoids DVWA's
	// malformed gzip that truncates the reflected payload (see dvwa_test.go). Passed
	// as opts.Headers (== `vigolium scan -H`) so they reach every module probe.
	headers := []string{"Cookie: " + cookie, "Accept-Encoding: identity"}

	catalog := dvwaCatalog()
	targets := catalogTargets(app.BaseURL, catalog)
	findings := runScorecardScan(t, targets, headers)

	res := reportScorecard(t, "dvwa", catalog, findings)

	// Measured reality via the real `vigolium scan -t <url> -H <cookie>` path
	// (confirmed byte-for-byte against the shipped binary):
	//   - CAUGHT: error-based SQLi (sqli-error-based), reflected XSS
	//     (xss-light-url-params), LFI (lfi-generic), and open-redirect — plus the
	//     username SQLi on the brute-force page.
	//   - MISSED here for benign reasons, not a scanner gap: blind SQLi is a
	//     distinct technique (the error-based module already flags that endpoint);
	//     cmdi is POST-only so it isn't expressible as a GET target (the binary
	//     DOES catch it via a POST request — `vigolium scan-request`); the DVWA
	//     API v1 endpoint is absent in this image.
	// Gate the injection trio + open-redirect the shipped binary reliably fires.
	mustCatch(t, "dvwa", res, "dvwa-sqli", "dvwa-xss-reflected", "dvwa-lfi", "dvwa-open-redirect")
	assert.GreaterOrEqual(t, res.reHit, 4,
		"expected Vigolium to catch the SQLi/XSS/LFI/open-redirect DAST-reachable DVWA vulns")
}

// ---------------------------------------------------------------------------
// VAmPI — /Users/j3ssie/Desktop/vuln-apps/VAmPI (source-verified)
// ---------------------------------------------------------------------------

func vampiCatalog() []gtVuln {
	return []gtVuln{
		// Reachable unauthenticated, in-band.
		{id: "vampi-sqli-username", class: "sqli", tier: tierReachable,
			routeMatch: "/users/v1/", modules: []string{"sqli", "sql-syntax"},
			note: "user_model.py:72 f-string SQL; a quote → 500 Werkzeug traceback (debug=True)"},
		{id: "vampi-debug-data-exposure", class: "excessive-data-exposure", tier: tierReachable,
			routeMatch: "_debug", modules: []string{"secret", "exposure", "sensitive", "info-disclosure"},
			note: "users.py:24 /users/v1/_debug returns every user's cleartext password"},
		{id: "vampi-swagger-disclose", class: "api-docs-exposure", tier: tierReachable,
			routeMatch: "", modules: []string{"swagger", "api-doc", "openapi"},
			note: "VAmPI serves Swagger UI at / (openapi3.yml)"},
		{id: "vampi-flask-debug-traceback", class: "debug-mode", tier: tierReachable,
			routeMatch: "", modules: []string{"debug", "stacktrace", "error", "traceback", "info-disclosure"},
			note: "app.py:17 debug=True → interactive Werkzeug traceback on any 500"},

		// Reachable only with auth + a second identity / response diff / timing.
		{id: "vampi-bola-password-change", class: "bola", tier: tierPartial,
			routeMatch: "/password", modules: []string{"bola", "idor", "auth"},
			note: "users.py:186 PUT /users/v1/{username}/password keys off path, no owner check"},
		{id: "vampi-bola-book", class: "bola", tier: tierPartial,
			routeMatch: "/books/v1/", modules: []string{"bola", "idor"},
			note: "books.py:50 GET /books/v1/{title} returns any user's secret; needs 2 identities"},
		{id: "vampi-mass-assignment-admin", class: "mass-assignment", tier: tierPartial,
			routeMatch: "/register", modules: []string{"mass-assign", "privilege"},
			note: "users.py:60 register accepts admin:true; verify via login+/me"},
		{id: "vampi-user-enumeration", class: "user-enumeration", tier: tierPartial,
			routeMatch: "/login", modules: []string{"enum", "user-enum", "info-disclosure"},
			note: "users.py:101 distinct messages for unknown-user vs wrong-password"},
		{id: "vampi-jwt-weak-secret", class: "jwt-weak-secret", tier: tierPartial,
			routeMatch: "", modules: []string{"jwt"},
			note: "config.py:13 SECRET_KEY='random' HS256 — passive detect + offline crack"},
		{id: "vampi-regexdos-email", class: "regexdos", tier: tierPartial,
			routeMatch: "/email", modules: []string{"redos", "regex", "dos"},
			note: "users.py:144 catastrophic-backtracking email regex; timing probe"},

		// Not reachable by generic request/response scanning.
		{id: "vampi-jwt-alg-none", class: "jwt-alg-none", tier: tierUnreachable,
			note: "decode pins algorithms=['HS256'] — alg=none is NOT exploitable here"},
	}
}

// TestCoverageScorecard_VAmPI seeds VAmPI from its published OpenAPI spec (the
// realistic way to scan a JSON API — a black-box crawl can't discover API routes)
// and scores the full module set against the ground truth. Reuses the
// spec → DB → scan-all path proven by TestVAmPI_ImportOpenAPI_DBScan.
func TestCoverageScorecard_VAmPI(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping canary test in short mode")
	}

	app := startVAmPI(t)
	initVAmPIDB(t, app.BaseURL)

	// Seed VAmPI's own OpenAPI spec (points parsed requests at the live container)
	// and run the full active/passive set over every ingested record.
	items := parseVAmPIOpenAPI(t, app.BaseURL)
	require.NotEmpty(t, items, "OpenAPI parse should produce requests")
	findings := runSeededScorecardScan(t, app.BaseURL, items, nil)

	catalog := vampiCatalog()
	res := reportScorecard(t, "vampi", catalog, findings)

	// VAmPI is a single-threaded Flask dev server: when the full canary suite
	// runs many containers at once it can fall over mid-scan, leaving the scan
	// with no responses to analyze (hence no reachable-tier catch). A confirmed
	// unreachable target is environmental, never a scanner regression, so skip
	// rather than fail. A healthy target still has to clear the floor below.
	if res.reHit == 0 && !vampiReachable(app.BaseURL) {
		t.Skip("VAmPI became unreachable during the scan (container died under load); skipping (environmental)")
	}

	// Honest hard floor: the _debug excessive-data-exposure (cleartext passwords
	// in the body) is the most reliably detectable VAmPI vuln. SQLi via the
	// debug=True 500 traceback is reported but not gated (depends on whether the
	// spec-driven probes reach an unhandled-exception path).
	mustCatch(t, "vampi", res, "vampi-debug-data-exposure")
	assert.GreaterOrEqual(t, res.reHit, 1,
		"expected Vigolium to catch at least one DAST-reachable VAmPI vuln")
}

// ---------------------------------------------------------------------------
// Juice Shop — /Users/j3ssie/Desktop/vuln-apps/juice-shop (source-verified)
// ---------------------------------------------------------------------------

func juiceShopCatalog() []gtVuln {
	return []gtVuln{
		// Reachable unauthenticated, in-band.
		{id: "juice-sqli-search", class: "sqli", tier: tierReachable,
			seedMethod: "GET", seedPath: "/rest/products/search?q=test",
			routeMatch: "/rest/products/search", modules: []string{"sqli", "sql-syntax"},
			note: "routes/search.ts:23 raw ${criteria} in SELECT; q=' → SQLITE_ERROR"},
		{id: "juice-nosqli-track-order", class: "nosqli", tier: tierReachable,
			seedMethod: "GET", seedPath: "/rest/track-order/1",
			routeMatch: "/rest/track-order", modules: []string{"nosqli", "nosql"},
			note: "routes/trackOrder.ts:18 $where string-built with :id"},
		{id: "juice-open-redirect", class: "open-redirect", tier: tierReachable,
			seedMethod: "GET", seedPath: "/redirect?to=https://evil.example/%3Fx%3Dhttps://github.com/juice-shop/juice-shop",
			routeMatch: "/redirect", modules: []string{"openredirect", "open-redirect"},
			note: "insecurity.ts:135 substring allowlist bypass"},
		{id: "juice-metrics-exposure", class: "info-disclosure", tier: tierReachable,
			seedMethod: "GET", seedPath: "/metrics",
			routeMatch: "/metrics", modules: []string{"metric", "exposure", "prometheus", "health"},
			note: "server.ts:718 unauthenticated Prometheus /metrics"},
		{id: "juice-appconfig-exposure", class: "info-disclosure", tier: tierReachable,
			seedMethod: "GET", seedPath: "/rest/admin/application-configuration",
			routeMatch: "/application-configuration", modules: []string{"exposure", "config", "sensitive", "secret", "info-disclosure"},
			note: "appConfiguration.ts:9 dumps full merged config unauthenticated"},
		{id: "juice-swagger-exposure", class: "api-docs-exposure", tier: tierReachable,
			seedMethod: "GET", seedPath: "/api-docs",
			routeMatch: "/api-docs", modules: []string{"swagger", "api-doc", "openapi"},
			note: "server.ts:286 swagger-ui at /api-docs"},
		{id: "juice-ftp-directory-listing", class: "directory-listing", tier: tierReachable,
			seedMethod: "GET", seedPath: "/ftp/",
			routeMatch: "/ftp", modules: []string{"directory-listing", "listing"},
			note: "server.ts:269 serveIndex('/ftp') browsable dir"},
		{id: "juice-product-tamper", class: "broken-access-control", tier: tierReachable,
			seedMethod: "PUT", seedPath: "/api/Products/1", seedBody: `{"description":"tampered"}`,
			seedContentType: "application/json",
			routeMatch:      "/api/Products", modules: []string{"bfla", "bola", "access", "method"},
			note: "server.ts:369 PUT /api/Products/:id auth middleware commented out"},

		// Reachable only with auth / second identity / OAST.
		{id: "juice-idor-basket", class: "idor-bola", tier: tierPartial,
			routeMatch: "/rest/basket/", modules: []string{"idor", "bola"},
			note: "basket.ts:19 findOne({id}) no ownership check; needs user JWT + neighbor id"},
		{id: "juice-ssrf-profile-image", class: "ssrf", tier: tierPartial,
			routeMatch: "/profile/image/url", modules: []string{"ssrf"},
			note: "profileImageUrlUpload.ts:24 fetch(req.body.imageUrl); needs JWT + OAST"},
		{id: "juice-whoami-hash-leak", class: "excessive-data-exposure", tier: tierPartial,
			routeMatch: "/rest/user/whoami", modules: []string{"exposure", "secret", "sensitive"},
			note: "currentUser.ts:22 ?fields= lets caller project password hash; needs JWT"},
		{id: "juice-nosqli-reviews", class: "nosqli", tier: tierPartial,
			routeMatch: "/rest/products/reviews", modules: []string{"nosqli", "nosql"},
			note: "updateProductReviews.ts:18 operator injection in body id; needs JWT"},

		// Not reachable by generic request/response scanning.
		{id: "juice-dom-xss", class: "xss-dom", tier: tierUnreachable,
			note: "localXssChallenge is a pure Angular DOM sink; no server reflection"},
		{id: "juice-jwt-forgery", class: "jwt-forgery", tier: tierUnreachable,
			note: "alg:none / RS256→HS256 confusion need offline token forging vs the JWKS"},
	}
}

// TestCoverageScorecard_JuiceShop seeds Juice Shop's source-verified reachable
// REST endpoints and scores the full module set. Findings on Juice Shop are more
// variable than DVWA/VAmPI (some challenges are disabledEnv under Docker), so the
// gate is a soft floor plus the SQLi we independently observe firing on the
// product search endpoint.
func TestCoverageScorecard_JuiceShop(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping canary test in short mode")
	}

	app := startJuiceShop(t)

	catalog := juiceShopCatalog()
	targets := catalogTargets(app.BaseURL, catalog)
	findings := runScorecardScan(t, targets, nil)

	res := reportScorecard(t, "juiceshop", catalog, findings)

	// SQLi on /rest/products/search is the anchor we independently observe
	// (TestJuiceShop_SQLi + the autonomous scan both surface it).
	mustCatch(t, "juiceshop", res, "juice-sqli-search")
	assert.GreaterOrEqual(t, res.reHit, 3,
		"expected Vigolium to catch at least 3 of the DAST-reachable Juice Shop vulns")
}

// ---------------------------------------------------------------------------
// crAPI — /Users/j3ssie/Desktop/vuln-apps/crAPI (source-verified, documented)
// ---------------------------------------------------------------------------
//
// crAPI's catalog is captured here for completeness, but almost every entry is a
// business-logic / object-level-auth issue that requires a valid JWT plus a
// second user's object id (UUID/VIN/report id) and cross-user response diffing —
// work a generic black-box scan does not perform. The few unauthenticated
// surfaces (the MailHog inbox at /mailhog/, the decorator-less Django order/VIN
// endpoints, path-traversal download_report, exposed pprof/debug) need the full
// multi-service compose stack running, not a single container. Rather than ship a
// flaky multi-service scan, this test documents the ground truth and skips.

func crapiCatalog() []gtVuln {
	return []gtVuln{
		{id: "crapi-mailhog-inbox", class: "unauthorized-access", tier: tierReachable,
			routeMatch: "/mailhog", modules: []string{"exposure", "auth", "access"},
			note: "nginx proxies /mailhog/ unauthenticated — leaks OTP/VIN emails"},
		{id: "crapi-order-bola", class: "bola", tier: tierReachable,
			routeMatch: "/workshop/api/shop/orders/", modules: []string{"idor-detection", "idor-params"},
			note: "shop/views.py:104 GET orders/{id} numeric BOLA — reads another user's order (email/phone PII). Caught by the single-identity idor-detection ([5=3 → 4]) after the singular-noun + JSON-shape fixes."},
		{id: "crapi-order-bola-authz", class: "bola-2identity", tier: tierReachable,
			routeMatch: "/workshop/api/shop/orders/", modules: []string{"authz-compare"},
			note: "Same order BOLA, confirmed the rigorous way: a multi-session --auth-file (primary + compare identities) lets authz-compare replay the request as a SECOND user and flag identical cross-user access (High). This is the object-ownership comparison a single token can't do."},
		{id: "crapi-mechanic-report-bola", class: "bola", tier: tierReachable,
			routeMatch: "/mechanic_report", modules: []string{"idor-detection", "authz-compare"},
			note: "mechanic/views.py:208 GET mechanic_report?report_id={n} numeric BOLA — reads another user's service report. Caught by idor-detection (neighbor enum) and authz-compare (2nd identity)."},
		{id: "crapi-download-report-traversal", class: "path-traversal", tier: tierReachable,
			routeMatch: "/download_report", modules: []string{"traversal", "path", "lfi"},
			note: "mechanic/views.py:377 validates pre-decode then unquote → ../ escape"},
		{id: "crapi-pprof-debug", class: "debug-exposure", tier: tierReachable,
			routeMatch: "/debug/pprof", modules: []string{"debug", "pprof", "exposure"},
			note: "community routes.go:43 net/http/pprof mounted when DEBUG=1"},

		{id: "crapi-vehicle-location-bola", class: "bola", tier: tierPartial,
			note: "identity VehicleController.getLocationBOLA; needs JWT + victim car UUID"},
		{id: "crapi-users-all-bfla", class: "bfla", tier: tierPartial,
			note: "workshop AdminUserView dumps all users; needs any valid JWT"},
		{id: "crapi-ssrf-contact-mechanic", class: "ssrf", tier: tierPartial,
			note: "merchant/views.py:82 requests.get(mechanic_api); needs JWT + OAST"},
		{id: "crapi-sqli-coupon", class: "sqli", tier: tierPartial,
			note: "shop/views.py:386 concatenated coupon_code SQL; needs JWT"},
		{id: "crapi-nosqli-coupon", class: "nosqli", tier: tierPartial,
			note: "community coupon_controller.go FindOne(raw body); needs JWT + $operators"},
		{id: "crapi-otp-bruteforce", class: "rate-limit", tier: tierPartial,
			note: "identity OtpServiceImpl 4-digit OTP, no lockout on v2/check-otp"},

		{id: "crapi-jwt-alg-none", class: "jwt-forgery", tier: tierUnreachable,
			note: "JwtProvider falls back to PlainJWT.parse — forge unsigned; needs token crafting"},
		{id: "crapi-jwt-kid-devnull", class: "jwt-forgery", tier: tierUnreachable,
			note: "kid=/dev/null → HMAC secret 'AA=='; offline signing"},
		{id: "crapi-jwt-jku-ssrf", class: "jwt-forgery", tier: tierUnreachable,
			note: "jku header trusts attacker JWKS URL; offline forging"},
	}
}

// TestCoverageScorecard_crAPI documents the source-verified crAPI ground truth
// and skips: crAPI needs its full docker-compose stack (identity/workshop/
// community/web gateway) plus authenticated multi-step flows that are out of
// scope for a single-container canary. The catalog is kept in-tree so the
// analysis is captured and can be wired to a live compose harness later.
// crapiBaseURL returns the crAPI web gateway URL (VIGOLIUM_CRAPI_URL overrides
// the default that `make crapi-up` publishes).
func crapiBaseURL() string {
	if v := os.Getenv("VIGOLIUM_CRAPI_URL"); v != "" {
		return v
	}
	return "http://127.0.0.1:8888"
}

// crapiReachable reports whether the crAPI stack is serving on baseURL.
func crapiReachable(baseURL string) bool {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(baseURL + "/")
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode < 500
}

// writeCrapiMultiSessionAuth registers two crAPI identities and writes a
// multi-session --auth-file bundle (primary + compare) whose sessions log in via
// crAPI's bearer flow. The compare (second) identity is what lets authz-compare
// perform real cross-user object-authorization comparison. Returns the file path.
func writeCrapiMultiSessionAuth(t *testing.T, baseURL string) string {
	t.Helper()
	client := &http.Client{Timeout: 15 * time.Second}
	users := []struct{ name, email, number string }{
		{"vig-attacker", "vig-attacker@example.com", "9876500011"},
		{"vig-victim", "vig-victim@example.com", "9876500022"},
	}
	for _, u := range users {
		body, _ := json.Marshal(map[string]string{"name": u.name, "email": u.email, "number": u.number, "password": "Scan!pass123"})
		if resp, err := client.Post(baseURL+"/identity/api/auth/signup", "application/json", bytes.NewReader(body)); err == nil {
			_ = resp.Body.Close()
		}
	}

	cfg := fmt.Sprintf(`sessions:
  - name: attacker
    role: primary
    login:
      url: %[1]s/identity/api/auth/login
      method: POST
      content_type: application/json
      body: '{"email":"%[2]s","password":"Scan!pass123"}'
      type: bearer
      token_path: token
  - name: victim
    role: compare
    login:
      url: %[1]s/identity/api/auth/login
      method: POST
      content_type: application/json
      body: '{"email":"%[3]s","password":"Scan!pass123"}'
      type: bearer
      token_path: token
`, baseURL, users[0].email, users[1].email)

	path := filepath.Join(t.TempDir(), "crapi-auth.yaml")
	require.NoError(t, os.WriteFile(path, []byte(cfg), 0o600))
	return path
}

// runAuthFileScan runs the full module set over targets using a session config
// file — the in-process equivalent of `vigolium scan -t ... --auth-file <file>`.
// The runner loads the sessions, hydrates their tokens via the login flow, merges
// the primary identity's headers onto every request, and wires the compare
// (second) identity into the authz-compare module for cross-user BOLA detection.
func runAuthFileScan(t *testing.T, targets []string, authFile string, modules []string) ([]*database.HTTPRecord, []*database.Finding) {
	t.Helper()
	tparts := make([]string, 0, len(targets))
	for _, tg := range targets {
		tparts = append(tparts, "-t '"+tg+"'")
	}
	modArg := "all"
	if len(modules) > 0 {
		modArg = strings.Join(modules, ",")
	}
	t.Logf("[auth-file-scan] ▶ replicate this scan on the CLI:\n    vigolium scan %s --auth-file %s --modules %s --only dynamic-assessment --no-tech-filter -S --db /tmp/scan.sqlite",
		strings.Join(tparts, " "), authFile, modArg)

	db, repo := setupStatelessTempDB(t)

	scanModules := []string{"all"}
	if len(modules) > 0 {
		scanModules = modules
	}
	opts := dynamicAssessmentOpts(targets, scanModules)
	opts.AuthFiles = []string{authFile}

	r, err := runner.New(opts)
	require.NoError(t, err, "create auth-file scan runner")
	r.SetSettings(scorecardSettings())
	r.SetRepository(repo)
	t.Cleanup(func() { r.Close() })

	require.NoError(t, r.RunNativeScan(), "auth-file scan should complete without error")
	return scorecardRecords(t, db), scorecardFindings(t, db)
}

// TestCoverageScorecard_crAPI runs a real authenticated scan against crAPI when
// its compose stack is up (`make crapi-up`), using a multi-session --auth-file
// (primary + compare identities). It scores the numeric-ID order and
// mechanic-report BOLAs: idor-detection catches them single-identity (after the
// singular-noun + JSON-shape fixes), and authz-compare confirms them the rigorous
// way by replaying each request as a second user. crAPI is a 13-service stack
// that can't be auto-started via testcontainers, so the test skips (with
// instructions) when the stack isn't reachable.
func TestCoverageScorecard_crAPI(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping canary test in short mode")
	}

	catalog := crapiCatalog()
	baseURL := crapiBaseURL()
	if !crapiReachable(baseURL) {
		var re, part, un int
		for _, v := range catalog {
			switch v.tier {
			case tierReachable:
				re++
			case tierPartial:
				part++
			case tierUnreachable:
				un++
			}
		}
		t.Logf("crAPI ground truth: %d reachable, %d partial (need auth+2nd identity), %d unreachable (offline JWT forgery)", re, part, un)
		t.Skipf("crAPI not reachable at %s — bring up its compose stack with `make crapi-up` (VIGOLIUM_CRAPI_URL overrides the URL)", baseURL)
	}

	authFile := writeCrapiMultiSessionAuth(t, baseURL)

	// order 3 belongs to another seeded user (robot001@example.com) and
	// mechanic_report 1 to yet another; reading them — and enumerating neighbors,
	// or replaying as the compare identity — is a cross-user BOLA leaking PII.
	targets := []string{
		baseURL + "/workshop/api/shop/orders/3",
		baseURL + "/workshop/api/mechanic/mechanic_report?report_id=1",
	}
	// Focus on the object-authorization family. The active idor-detection and
	// authz-compare confirmations are HTTP-heavy (baseline + neighbor/2nd-identity
	// replays); under a full 300-module scan against one host they get starved by
	// the per-host rate limit and only the passive idor flag survives. A scoped
	// authenticated-BOLA scan is the realistic way an operator drives these.
	bolaModules := []string{"idor-detection", "authz-compare", "idor-params-detect", "bfla-detection"}
	records, findings := runAuthFileScan(t, targets, authFile, bolaModules)

	// (1) HARD: the session reached the protected crAPI surface.
	var reached []string
	for _, r := range records {
		if r.StatusCode >= 200 && r.StatusCode < 300 {
			reached = append(reached, r.Method+" "+r.URL)
		}
	}
	t.Logf("[crapi-auth] authenticated scan reached %d/%d records with 2xx: %v", len(reached), len(records), reached)
	assert.NotEmpty(t, reached, "authenticated crAPI scan should reach the protected endpoints")

	// (2) HARD: the numeric BOLAs are caught both single-identity (idor-detection)
	// and with a second identity (authz-compare, High) via the --auth-file bundle.
	res := reportScorecard(t, "crapi-auth", catalog, findings)
	mustCatch(t, "crapi-auth", res,
		"crapi-order-bola", "crapi-order-bola-authz", "crapi-mechanic-report-bola")
}

// ---------------------------------------------------------------------------
// vulnerable-java — DataDog/vulnerable-java-application (live endpoints RE'd)
// ---------------------------------------------------------------------------
//
// The shipped image's real endpoints differ from the stale benchmark definition:
// the pages are JS-driven and POST JSON to /test-domain, /test-website, and
// /view-file. Confirmed by hand against the running container:
//   - POST /test-domain {"domainName":"example.com; id"} runs `ping <domainName>`
//     and reflects the injected command output → RCE as root (CWE-78). The app
//     validates that domainName starts with a real host, so the payload must
//     APPEND to the base value ("example.com; id"), not replace it.
//   - POST /test-website {"url":...} fetches the URL server-side and returns the
//     body → in-band SSRF (CWE-918).
//   - POST /view-file {"path":...} reads the path with an /etc/passwd denylist →
//     path traversal that needs a bypass (CWE-22).
// All are unauthenticated JSON-body POSTs — a good exercise of JSON insertion
// point fuzzing (INS_PARAM_JSON) for the injection modules.

func vulnerableJavaCatalog() []gtVuln {
	return []gtVuln{
		{id: "vjava-cmdi", class: "rce-cmdi", tier: tierReachable,
			seedMethod: "POST", seedPath: "/test-domain",
			seedBody: `{"domainName":"example.com"}`, seedContentType: "application/json",
			routeMatch: "/test-domain", modules: []string{"command", "cmdi", "code-exec", "rce"},
			note: "ping <domainName> in JSON body; append '; cmd' to a valid domain → RCE (uid=0 confirmed)"},
		{id: "vjava-ssrf", class: "ssrf", tier: tierReachable,
			seedMethod: "POST", seedPath: "/test-website",
			seedBody:        `{"url":"http://example.com","customHeaderKey":"","customHeaderValue":""}`,
			seedContentType: "application/json",
			routeMatch:      "/test-website", modules: []string{"ssrf"},
			note: "server fetches url JSON field and returns the body → in-band SSRF"},
		{id: "vjava-lfi", class: "lfi", tier: tierPartial,
			seedMethod: "POST", seedPath: "/view-file",
			seedBody: `{"path":"/tmp/files/x.txt"}`, seedContentType: "application/json",
			routeMatch: "/view-file", modules: []string{"lfi", "traversal", "path"},
			note: "reads path JSON field with an /etc/passwd denylist — needs a traversal bypass"},
		{id: "vjava-security-headers", class: "security-headers", tier: tierReachable,
			seedMethod: "GET", seedPath: "/index.html",
			routeMatch: "", modules: []string{"security-headers", "permissions-policy"},
			note: "missing security headers (passive baseline)"},
	}
}

// jsonSeedItems builds request/response items (GET or POST-with-JSON-body) from a
// catalog for a no-auth slice-source scan. Used for apps whose vulnerable surface
// is JSON-body POST endpoints (vulnerable-java) rather than GET query params.
func jsonSeedItems(t *testing.T, baseURL string, catalog []gtVuln) []*httpmsg.HttpRequestResponse {
	t.Helper()
	var items []*httpmsg.HttpRequestResponse
	for _, v := range catalog {
		if v.seedPath == "" {
			continue
		}
		method := v.seedMethod
		if method == "" {
			method = "GET"
		}
		var hdrs map[string]string
		if v.seedContentType != "" {
			hdrs = map[string]string{"Content-Type": v.seedContentType}
		}
		rr, err := httpmsg.GetRawRequestFromURLWithMethod(baseURL+v.seedPath, method, hdrs, []byte(v.seedBody))
		require.NoError(t, err, "seed request for %s", v.id)
		items = append(items, rr)
	}
	return items
}

// startVulnerableJava boots the DataDog vulnerable-java container.
func startVulnerableJava(t *testing.T) *VulnerableApp {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)

	app, err := StartContainer(ctx, ContainerConfig{
		Image:       "ghcr.io/datadog/vulnerable-java-application:latest",
		ExposedPort: "8000/tcp",
		WaitStrategy: wait.ForHTTP("/").
			WithPort("8000").
			WithStartupTimeout(120 * time.Second),
		ReadyEndpoint: "/",
	})
	require.NoError(t, err, "Failed to start vulnerable-java container")
	t.Cleanup(func() { _ = app.Stop() })

	t.Logf("vulnerable-java running at %s", app.BaseURL)
	return app
}

// TestCoverageScorecard_VulnerableJava scores Vigolium against DataDog's
// vulnerable-java (JSON-body POST cmdi/SSRF/LFI). It seeds the confirmed
// vulnerable endpoints and runs the full module set over the JSON bodies. The
// gate is calibrated to what the pipeline reliably fires; the scorecard log
// records the rest so a JSON-body coverage gap is visible rather than hidden.
func TestCoverageScorecard_VulnerableJava(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping canary test in short mode")
	}

	app := startVulnerableJava(t)

	catalog := vulnerableJavaCatalog()
	items := jsonSeedItems(t, app.BaseURL, catalog)
	findings := runSeededScorecardScan(t, app.BaseURL, items, nil)

	res := reportScorecard(t, "vulnerable-java", catalog, findings)

	// Measured reality (runner/full-scan path):
	//   - command-injection-echo DOES fuzz the JSON body and catch the RCE (it
	//     appends to the "example.com" base value so the app's domain validation
	//     passes). BUT under a full all-modules scan its reflect-and-confirm is
	//     timing-sensitive and fires intermittently run-to-run — so cmdi is
	//     reported in the scorecard log but NOT hard-gated (a flaky catch would
	//     make the canary flap). This intermittency is itself a finding worth a
	//     module-level follow-up.
	//   - SSRF misses (in-band SSRF via a JSON url field — a reachable MISS worth
	//     investigating); LFI needs an /etc/passwd denylist bypass (tierPartial).
	//   - NOTE: `scan-request`/`scan-url`'s *direct* path (runScanWithRR) missed
	//     the cmdi that the runner path catches — a separate direct-vs-runner gap.
	// Gate the reliable passive baseline; the scorecard log carries the rest.
	mustCatch(t, "vulnerable-java", res, "vjava-security-headers")
	assert.GreaterOrEqual(t, res.reHit, 1,
		"expected Vigolium to at least flag the vulnerable-java passive baseline")
}

// ---------------------------------------------------------------------------
// Authenticated scan — Juice Shop with credentials (the "real auth" test)
// ---------------------------------------------------------------------------
//
// This exercises the credentialed-scan path the operator uses in practice:
//   vigolium scan -t <protected-url> -H "Authorization: Bearer <jwt>"
//
// It answers two separate questions the unauthenticated scorecards can't:
//   1. Does the credential actually REACH the protected surface? (yes — the
//      guarded endpoint returns 401 without the token and 2xx with it, so the
//      scan runs modules against real authenticated responses). This is the
//      part that is hard-gated.
//   2. Does a generic DAST then DETECT the auth-gated LOGIC flaws (BOLA/IDOR)?
//      Reaching the surface is necessary but not sufficient: true object-level
//      authorization bugs need object-ownership semantics (and often a second
//      identity) that a generic scanner does not model. So the auth-gated
//      catalog is scored and logged, but NOT gated — the honest, measured result
//      is that these are missed even with a valid session.

// authenticateJuiceShop registers a fresh user and logs in, returning the JWT
// bearer token. Juice Shop tokens are non-expiring, so one token covers a scan.
func authenticateJuiceShop(t *testing.T, baseURL string) string {
	t.Helper()
	client := &http.Client{Timeout: 15 * time.Second}
	const email, pw = "scan-auth@example.test", "Passw0rd!23"

	regBody, _ := json.Marshal(map[string]any{
		"email": email, "password": pw, "passwordRepeat": pw,
		"securityQuestion": map[string]int{"id": 1}, "securityAnswer": "x",
	})
	// Register is best-effort — a re-run reuses the existing account, which login handles.
	if resp, err := client.Post(baseURL+"/api/Users", "application/json", bytes.NewReader(regBody)); err == nil {
		_ = resp.Body.Close()
	}

	loginBody, _ := json.Marshal(map[string]string{"email": email, "password": pw})
	loginResp, err := client.Post(baseURL+"/rest/user/login", "application/json", bytes.NewReader(loginBody))
	require.NoError(t, err, "juice-shop login")
	defer func() { _ = loginResp.Body.Close() }()
	body, _ := io.ReadAll(loginResp.Body)
	var lr struct {
		Authentication struct {
			Token string `json:"token"`
		} `json:"authentication"`
	}
	require.NoError(t, json.Unmarshal(body, &lr), "parse login response: %s", string(body))
	require.NotEmpty(t, lr.Authentication.Token, "juice-shop login should return a JWT")
	return lr.Authentication.Token
}

// runAuthScanRecords runs the full module set over targets with auth/transport
// headers (== `vigolium scan -t ... -H ...`), returning BOTH the ingested HTTP
// records (to prove the credential reached the protected surface) and the
// findings (to score auth-gated detection).
func runAuthScanRecords(t *testing.T, targets []string, headers []string) ([]*database.HTTPRecord, []*database.Finding) {
	t.Helper()
	logScanCommand(t, "auth-scan", "", targets, headers)

	db, repo := setupStatelessTempDB(t)
	opts := dynamicAssessmentOpts(targets, []string{"all"})
	opts.Headers = headers

	r, err := runner.New(opts)
	require.NoError(t, err, "create auth scan runner")
	r.SetSettings(scorecardSettings())
	r.SetRepository(repo)
	t.Cleanup(func() { r.Close() })

	require.NoError(t, r.RunNativeScan(), "authenticated scan should complete without error")
	return scorecardRecords(t, db), scorecardFindings(t, db)
}

func juiceShopAuthCatalog() []gtVuln {
	return []gtVuln{
		{id: "js-auth-idor-basket", class: "idor-bola", tier: tierReachable,
			routeMatch: "/rest/basket/", modules: []string{"idor", "bola"},
			note: "GET /rest/basket/{id} numeric IDOR: an attacker's token reads a foreign basket. Now CAUGHT by idor-detection after two fixes — singular resource-noun recognition (basket→baskets) in ClassifyPathContext, and a JSON structural-shape signature in CompareResponses so same-shape baskets of different sizes are compared."},
		{id: "js-auth-whoami-exposure", class: "excessive-data-exposure", tier: tierPartial,
			routeMatch: "/rest/user/whoami", modules: []string{"secret", "exposure", "sensitive"},
			note: "GET /rest/user/whoami?fields= field projection; version-dependent (patched in this image)."},
	}
}

// TestCoverageScorecard_JuiceShop_Authenticated runs a credentialed scan against
// Juice Shop and verifies (hard) that the bearer token reaches the protected
// surface, then scores (soft) whether the auth-gated logic flaws are detected.
func TestCoverageScorecard_JuiceShop_Authenticated(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping canary test in short mode")
	}

	app := startJuiceShop(t)
	token := authenticateJuiceShop(t, app.BaseURL)

	// The basket endpoint is guarded: without a credential it is not a 2xx.
	client := &http.Client{Timeout: 10 * time.Second}
	unauth, err := client.Get(app.BaseURL + "/rest/basket/1")
	require.NoError(t, err, "unauth basket probe")
	unauthStatus := unauth.StatusCode
	_ = unauth.Body.Close()
	t.Logf("unauthenticated GET /rest/basket/1 → %d (protected)", unauthStatus)

	// Basket 1 belongs to ANOTHER user, so a 2xx here is both proof the credential
	// was applied AND the raw IDOR primitive itself.
	targets := []string{
		app.BaseURL + "/rest/basket/1",
		app.BaseURL + "/rest/user/whoami",
	}
	headers := []string{"Authorization: Bearer " + token}
	records, findings := runAuthScanRecords(t, targets, headers)

	// (1) HARD: the credential reached the protected surface — at least one
	// authenticated record came back 2xx (the unauth probe above did not).
	var reached []string
	for _, r := range records {
		if r.StatusCode >= 200 && r.StatusCode < 300 {
			reached = append(reached, r.Method+" "+r.URL)
		}
	}
	t.Logf("[juiceshop-auth] authenticated scan reached %d/%d records with 2xx: %v",
		len(reached), len(records), reached)
	assert.NotEmpty(t, reached,
		"authenticated scan should reach the protected surface (2xx) — proving the -H Bearer credential was applied")
	assert.GreaterOrEqual(t, unauthStatus, 400,
		"the basket endpoint should be protected (>=400) without a credential")

	// (2) Score auth-gated detection. The numeric basket IDOR is now hard-gated:
	// after the singular resource-noun + JSON-shape comparison fixes, an
	// authenticated scan flags the cross-user basket read. The whoami field-leak
	// stays soft (version-dependent / patched in this image).
	authCatalog := juiceShopAuthCatalog()
	res := reportScorecard(t, "juiceshop-auth", authCatalog, findings)
	mustCatch(t, "juiceshop-auth", res, "js-auth-idor-basket")
}
