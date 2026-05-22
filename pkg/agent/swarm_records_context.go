package agent

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/vigolium/vigolium/pkg/agent/authsession"
	agentinput "github.com/vigolium/vigolium/pkg/agent/input"
	"github.com/vigolium/vigolium/pkg/agent/parsing"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/terminal"

	"go.uber.org/zap"
)

func (s *SwarmRunner) normalizeInputs(ctx context.Context, cfg SwarmConfig) ([]*httpmsg.HttpRequestResponse, string, error) {
	var allRecords []*httpmsg.HttpRequestResponse
	var targetURL string

	for _, input := range cfg.Inputs {
		records, err := agentinput.NormalizeInput(ctx, input, cfg.InputType, s.repo)
		if err != nil {
			return nil, "", fmt.Errorf("failed to normalize input: %w", err)
		}
		allRecords = append(allRecords, records...)
	}

	// Extract target URL from first record
	if len(allRecords) > 0 && allRecords[0].Request() != nil {
		if u, err := allRecords[0].URL(); err == nil {
			targetURL = u.String()
		}
	}

	return allRecords, targetURL, nil
}

// pathToPrefix returns the 2-segment URL-path prefix of a raw path string.
// Strips query strings and leading slashes; "/" stays "/". Used by both
// recordPathPrefix (which wraps records) and the plan coverage check
// (which scans free-text focus areas for path-like substrings).
func pathToPrefix(p string) string {
	if qIdx := strings.Index(p, "?"); qIdx >= 0 {
		p = p[:qIdx]
	}
	p = strings.TrimPrefix(p, "/")
	if p == "" {
		return "/"
	}
	parts := strings.Split(p, "/")
	if len(parts) > 2 {
		return "/" + strings.Join(parts[:2], "/")
	}
	return "/" + strings.Join(parts, "/")
}

// recordPathPrefix returns the 2-segment URL-path prefix of a record's
// request, used by selectPlanRecords for cluster-based diversity. Returns
// "" when the request is missing or has no path. Examples:
//
//	"/api/users/123"        → "/api/users"
//	"/api/users?id=1"       → "/api/users"
//	"/login"                → "/login"
//	"/"                     → "/"
func recordPathPrefix(rr *httpmsg.HttpRequestResponse) string {
	if rr == nil || rr.Request() == nil {
		return ""
	}
	return pathToPrefix(rr.Request().Path())
}

// selectPlanRecords filters and ranks records for the plan phase, returning
// at most maxRecords of the most "interesting" ones. Interesting means the
// request has query parameters, a body, or uses a non-GET method. Static
// asset requests are deprioritised.
//
// The selection runs in two passes so coverage is never starved by score:
//  1. Bucket records by 2-segment URL prefix and pick the top-scored record
//     from each bucket (one representative per cluster, up to maxRecords).
//  2. If slots remain, fill them with the remaining best-scored records
//     using the same prefix-penalty diversity scheme as before.
//
// maxRecords == 0 means "no limit" — return every record (with static
// assets deprioritised away from the front but still included). The CLI
// surfaces this as `--max-plan-records 0`.
func selectPlanRecords(records []*httpmsg.HttpRequestResponse, maxRecords int) []*httpmsg.HttpRequestResponse {
	if maxRecords < 0 {
		maxRecords = 0
	}
	if maxRecords == 0 {
		// 0 = no cap; return everything in original order.
		out := make([]*httpmsg.HttpRequestResponse, len(records))
		copy(out, records)
		return out
	}
	if len(records) <= maxRecords {
		return records
	}

	// Static file extensions to deprioritise
	staticExts := map[string]bool{
		".css": true, ".js": true, ".png": true, ".jpg": true, ".jpeg": true,
		".gif": true, ".svg": true, ".ico": true, ".woff": true, ".woff2": true,
		".ttf": true, ".eot": true, ".map": true, ".webp": true, ".avif": true,
	}

	type scored struct {
		record *httpmsg.HttpRequestResponse
		score  int
		index  int // preserve original order for tie-breaking
	}

	scored_records := make([]scored, 0, len(records))
	for i, rr := range records {
		s := 0
		req := rr.Request()
		if req == nil {
			scored_records = append(scored_records, scored{rr, s, i})
			continue
		}

		// Non-GET methods are more interesting (POST, PUT, DELETE, PATCH)
		method := strings.ToUpper(req.Method())
		if method != "GET" && method != "HEAD" && method != "OPTIONS" {
			s += 3
		}

		// Has request body
		if len(req.Body()) > 0 {
			s += 3
		}

		// Has query parameters (check for '?' in path)
		path := req.Path()
		if strings.Contains(path, "?") {
			s += 2
		}

		// Check for interesting content types
		ct := strings.ToLower(req.Header("Content-Type"))
		if strings.Contains(ct, "json") || strings.Contains(ct, "xml") || strings.Contains(ct, "form") {
			s += 1
		}

		// Has auth-related headers
		if req.HasHeader("Authorization") || req.HasHeader("Cookie") || req.HasHeader("X-API-Key") {
			s += 1
		}

		// Penalise static assets
		pathLower := strings.ToLower(path)
		if qIdx := strings.Index(pathLower, "?"); qIdx >= 0 {
			pathLower = pathLower[:qIdx]
		}
		if dotIdx := strings.LastIndex(pathLower, "."); dotIdx >= 0 {
			if staticExts[pathLower[dotIdx:]] {
				s -= 5
			}
		}

		// Penalise error responses (4xx/5xx without body suggest less interesting endpoints)
		if rr.HasResponse() {
			sc := rr.Response().StatusCode()
			if sc == 404 || sc == 405 {
				s -= 3
			} else if sc >= 400 {
				s -= 1
			}
		}

		scored_records = append(scored_records, scored{rr, s, i})
	}

	// Sort by score descending, then by original index ascending (stable-ish)
	sort.Slice(scored_records, func(i, j int) bool {
		if scored_records[i].score != scored_records[j].score {
			return scored_records[i].score > scored_records[j].score
		}
		return scored_records[i].index < scored_records[j].index
	})

	// Diversity-aware selection. Two passes:
	//
	//   Pass 1 — prefix coverage: bucket records by 2-segment URL prefix,
	//     pick the top-scored representative of each bucket. This guarantees
	//     every URL-prefix cluster on the surface has at least one slot in
	//     the planner's view, even when low-scoring (e.g. error endpoints,
	//     OPTIONS-only routes) — these are exactly the spots that hide
	//     non-obvious bugs (IDOR, broken access control, header injection).
	//
	//   Pass 2 — fill: if slots remain, greedily pick the next best-scored
	//     record, with a penalty for adding another record under an
	//     already-represented prefix. Same logic as before, but only runs
	//     after every cluster is covered.
	type candidate struct {
		scored
		prefix string
	}
	candidates := make([]candidate, len(scored_records))
	for i, sr := range scored_records {
		candidates[i] = candidate{scored: sr, prefix: recordPathPrefix(sr.record)}
	}

	selected := make([]scored, 0, maxRecords)
	prefixCount := make(map[string]int)
	used := make(map[int]bool) // track used indices

	// Pass 1: one rep per prefix.
	// candidates is already sorted by score desc (we sort scored_records above),
	// so the first time we encounter a prefix the candidate is the best for it.
	for i, c := range candidates {
		if len(selected) >= maxRecords {
			break
		}
		if c.prefix == "" {
			continue
		}
		if prefixCount[c.prefix] > 0 {
			continue
		}
		used[i] = true
		selected = append(selected, c.scored)
		prefixCount[c.prefix] = 1
	}

	// Pass 2: fill remaining slots with the next best records, penalising
	// over-represented prefixes so we don't end up with 25 variants of /api/users.
	for len(selected) < maxRecords {
		bestIdx := -1
		bestEffective := -100
		for i, c := range candidates {
			if used[i] {
				continue
			}
			effective := c.score
			if c.prefix != "" {
				effective -= prefixCount[c.prefix] * 2
			}
			if effective > bestEffective || (effective == bestEffective && bestIdx >= 0 && c.index < candidates[bestIdx].index) {
				bestEffective = effective
				bestIdx = i
			}
		}
		if bestIdx < 0 {
			break
		}
		used[bestIdx] = true
		selected = append(selected, candidates[bestIdx].scored)
		if candidates[bestIdx].prefix != "" {
			prefixCount[candidates[bestIdx].prefix]++
		}
	}

	// Re-sort by original index to preserve request order
	sort.Slice(selected, func(i, j int) bool {
		return selected[i].index < selected[j].index
	})

	result := make([]*httpmsg.HttpRequestResponse, len(selected))
	for i, s := range selected {
		result[i] = s.record
	}
	return result
}

// buildRecordSummary generates a compact one-line-per-record summary of ALL records.
// This is appended to the plan agent context when records were filtered down by
// selectPlanRecords, so the agent sees the full API surface at a glance even when
// only the top-N most interesting records have full request/response details.
func buildRecordSummary(records []*httpmsg.HttpRequestResponse) string {
	if len(records) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n## All Discovered Endpoints (summary)\n\n")
	b.WriteString("| # | Method | Path | Status |\n")
	b.WriteString("|---|--------|------|--------|\n")
	for i, rr := range records {
		method := "?"
		path := "?"
		status := "?"
		if req := rr.Request(); req != nil {
			method = req.Method()
			path = req.Path()
			if qIdx := strings.Index(path, "?"); qIdx >= 0 {
				path = path[:qIdx]
			}
		}
		if rr.HasResponse() {
			status = fmt.Sprintf("%d", rr.Response().StatusCode())
		}
		fmt.Fprintf(&b, "| %d | %s | %s | %s |\n", i+1, method, path, status)
	}
	return b.String()
}

// buildSmartHTTPContext builds a formatted HTTP context string for the master agent prompt.
// It always includes full raw requests and response headers, but truncates response bodies
// to maxRespBytes to manage token usage.
func buildSmartHTTPContext(records []*httpmsg.HttpRequestResponse, maxRespBytes int) string {
	if maxRespBytes <= 0 {
		maxRespBytes = 2048
	}

	var rc strings.Builder
	for i, rr := range records {
		if i > 0 {
			rc.WriteString("\n---\n\n")
		}
		fmt.Fprintf(&rc, "### Request %d\n\n", i+1)
		if rr.Request() != nil {
			rc.WriteString("```http\n")
			rc.Write(rr.Request().Raw())
			rc.WriteString("\n```\n")
		}
		if rr.Response() != nil && len(rr.Response().Raw()) > 0 {
			respRaw := rr.Response().Raw()
			// Split response into headers and body
			headerEnd := bytes.Index(respRaw, []byte("\r\n\r\n"))
			if headerEnd < 0 {
				headerEnd = bytes.Index(respRaw, []byte("\n\n"))
			}

			rc.WriteString("\n```http\n")
			if headerEnd >= 0 {
				// Write full headers
				rc.Write(respRaw[:headerEnd])
				rc.WriteString("\r\n\r\n")
				// Truncate body if needed
				body := respRaw[headerEnd+4:] // skip \r\n\r\n
				if bytes.HasPrefix(respRaw[headerEnd:], []byte("\n\n")) {
					body = respRaw[headerEnd+2:]
				}
				if len(body) > maxRespBytes {
					rc.Write(body[:maxRespBytes])
					fmt.Fprintf(&rc, "\n... (truncated from %d bytes)", len(body))
				} else {
					rc.Write(body)
				}
			} else {
				// No header/body split found, truncate whole response
				if len(respRaw) > maxRespBytes {
					rc.Write(respRaw[:maxRespBytes])
					fmt.Fprintf(&rc, "\n... (truncated from %d bytes)", len(respRaw))
				} else {
					rc.Write(respRaw)
				}
			}
			rc.WriteString("\n```\n")
		}
	}
	return rc.String()
}

// queryDiscoveredRecords fetches HTTP records from the database that were created
// during the discovery phase for the target hostname.
func (s *SwarmRunner) queryDiscoveredRecords(ctx context.Context, cfg SwarmConfig, targetURL string) []*httpmsg.HttpRequestResponse {
	if s.repo == nil || targetURL == "" {
		return nil
	}

	hostname := hostnameFromURL(targetURL)
	if hostname == "" {
		return nil
	}

	dbRecords, err := s.repo.GetRecordsByHostname(ctx, cfg.ProjectUUID, hostname, 500)
	if err != nil {
		zap.L().Warn("Failed to query discovered records", zap.Error(err))
		return nil
	}

	var records []*httpmsg.HttpRequestResponse
	for _, dbRec := range dbRecords {
		rr, parseErr := httpmsg.ParseRawRequestWithURL(string(dbRec.RawRequest), dbRec.URL)
		if parseErr != nil {
			continue
		}
		records = append(records, rr)
	}
	return records
}

// deduplicateRecords removes duplicate records by method+URL.
func deduplicateRecords(records []*httpmsg.HttpRequestResponse) []*httpmsg.HttpRequestResponse {
	seen := make(map[string]bool, len(records))
	var result []*httpmsg.HttpRequestResponse
	for _, rr := range records {
		key := ""
		if rr.Request() != nil {
			key = rr.Request().Method()
			if u, err := rr.URL(); err == nil {
				key += " " + u.String()
			}
		}
		if key != "" && seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, rr)
	}
	return result
}

// filterSourceRecordsByHostname converts AgentHTTPRecords to HttpRequestResponse,
// keeping only those whose hostname matches the target URL's hostname.
// Relative URLs are resolved against the target URL using net/url.ResolveReference
// for correct path handling (e.g., "../api/v2", "/api/users", "endpoint").
// Returns records and a parallel slice of notes (aligned 1:1 with records).
func filterSourceRecordsByHostname(agentRecords []AgentHTTPRecord, targetURL string) ([]*httpmsg.HttpRequestResponse, []string) {
	if targetURL == "" {
		// Source-only mode: keep all records without hostname filtering.
		normalized, _ := parsing.NormalizeAgentRecords(agentRecords)
		var passthrough []*httpmsg.HttpRequestResponse
		var passthroughNotes []string
		for _, rec := range normalized {
			rr, convertErr := ToHTTPRequestResponse(rec)
			if convertErr != nil {
				continue
			}
			passthrough = append(passthrough, rr)
			passthroughNotes = append(passthroughNotes, rec.Notes)
		}
		return passthrough, passthroughNotes
	}
	targetParsed, err := url.Parse(targetURL)
	if err != nil {
		return nil, nil
	}
	targetHost := targetParsed.Host // includes port

	// Build a base URL for resolving relative references.
	// Ensure it ends with "/" so relative paths resolve correctly against the origin.
	baseURL := &url.URL{
		Scheme: targetParsed.Scheme,
		Host:   targetParsed.Host,
		Path:   "/",
	}

	// Normalize records first — fix garbled URLs, truncated bodies, malformed headers.
	normalized, dropped := parsing.NormalizeAgentRecords(agentRecords)
	if dropped > 0 {
		zap.L().Info("Normalized agent records",
			zap.Int("input", len(agentRecords)),
			zap.Int("normalized", len(normalized)),
			zap.Int("dropped", dropped))
	}

	var filtered []*httpmsg.HttpRequestResponse
	var notes []string
	skipped := 0
	for _, rec := range normalized {
		recURL := rec.URL

		// Resolve relative URLs against the target base using standard URL resolution.
		if !strings.HasPrefix(recURL, "http://") && !strings.HasPrefix(recURL, "https://") {
			ref, refErr := url.Parse(recURL)
			if refErr != nil {
				skipped++
				continue
			}
			recURL = baseURL.ResolveReference(ref).String()
		}

		recParsed, parseErr := url.Parse(recURL)
		if parseErr != nil {
			skipped++
			continue
		}
		if recParsed.Host != targetHost {
			skipped++
			continue
		}

		// Rewrite the record URL to be fully qualified
		rec.URL = recURL
		rr, convertErr := ToHTTPRequestResponse(rec)
		if convertErr != nil {
			zap.L().Debug("Skipping source record", zap.String("url", rec.URL), zap.Error(convertErr))
			skipped++
			continue
		}
		filtered = append(filtered, rr)
		notes = append(notes, rec.Notes)
	}

	if skipped > 0 {
		zap.L().Debug("Filtered source records by hostname",
			zap.String("target_host", targetHost),
			zap.Int("matched", len(filtered)),
			zap.Int("skipped", skipped))
	}

	return filtered, notes
}

// formatRouteStatusSummary returns a parenthesized summary of HTTP status code
// classes for probed records, e.g. "(2xx: 45, 3xx: 5, 4xx: 12, 5xx: 2, no-response: 3)".
func formatRouteStatusSummary(records []*httpmsg.HttpRequestResponse) string {
	var s2xx, s3xx, s4xx, s5xx, noResp int
	for _, rr := range records {
		if !rr.HasResponse() {
			noResp++
			continue
		}
		code := rr.Response().StatusCode()
		switch {
		case code >= 200 && code < 300:
			s2xx++
		case code >= 300 && code < 400:
			s3xx++
		case code >= 400 && code < 500:
			s4xx++
		case code >= 500:
			s5xx++
		default:
			noResp++
		}
	}
	var parts []string
	if s2xx > 0 {
		parts = append(parts, terminal.Green(fmt.Sprintf("2xx: %d", s2xx)))
	}
	if s3xx > 0 {
		parts = append(parts, terminal.Cyan(fmt.Sprintf("3xx: %d", s3xx)))
	}
	if s4xx > 0 {
		parts = append(parts, terminal.Yellow(fmt.Sprintf("4xx: %d", s4xx)))
	}
	if s5xx > 0 {
		parts = append(parts, terminal.Red(fmt.Sprintf("5xx: %d", s5xx)))
	}
	if noResp > 0 {
		parts = append(parts, terminal.Muted(fmt.Sprintf("no-response: %d", noResp)))
	}
	if len(parts) == 0 {
		return ""
	}
	return terminal.Muted("(") + strings.Join(parts, terminal.Muted(", ")) + terminal.Muted(")")
}

// injectAuthHeaders adds discovered auth headers to records that don't already
// have authentication. This ensures probing uses real credentials instead of
// requiring each record to independently carry auth info.
// Records are replaced in-place in the slice with new instances carrying auth headers.
func injectAuthHeaders(records []*httpmsg.HttpRequestResponse, authHeaders map[string]string) {
	if len(authHeaders) == 0 {
		return
	}

	injected := 0
	for i, rr := range records {
		if rr.Request() == nil {
			continue
		}

		// Skip records that already have auth headers
		hasAuth := false
		for _, h := range rr.Request().Headers() {
			if authsession.IsAuthHeader(h.Name) {
				hasAuth = true
				break
			}
		}
		if hasAuth {
			continue
		}

		// Build a new request with auth headers added
		newReq := rr.Request()
		for k, v := range authHeaders {
			newReq = newReq.WithAddedHeader(k, v)
		}

		records[i] = httpmsg.NewHttpRequestResponse(newReq, rr.Response())
		injected++
	}

	if injected > 0 {
		zap.L().Info("Injected auth headers into source-discovered records",
			zap.Int("injected", injected), zap.Int("total", len(records)))
	}
}
