package firebase_rtdb_exposure

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

var (
	// Extract RTDB URLs from response body
	rtdbURLRe = regexp.MustCompile(`https://([a-z0-9][a-z0-9-]*[a-z0-9])\.firebaseio\.com`)

	// Secret patterns in exposed data
	secretPatterns = []struct {
		name    string
		pattern *regexp.Regexp
	}{
		{"JWT Token", regexp.MustCompile(`eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{16,}`)},
		{"Stripe Secret Key", regexp.MustCompile(`sk_live_[a-zA-Z0-9]{24,}`)},
		{"Private Key", regexp.MustCompile(`-----BEGIN (?:RSA )?PRIVATE KEY-----`)},
		{"Slack Token", regexp.MustCompile(`xox[bprs]-[a-zA-Z0-9-]+`)},
	}
)

// Common RTDB subpaths that often contain sensitive data
var rtdbSubpaths = []string{
	"users",
	"user",
	"profiles",
	"config",
	"settings",
	"admin",
	"roles",
	"tokens",
	"accounts",
	"messages",
	"orders",
	"private",
}

type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

type rtdbExchange struct {
	status       int
	body         string
	rawRequest   string
	fullResponse string
}

func New() *Module {
	m := &Module{
		BaseActiveModule: modkit.NewBaseActiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.AllInsertionPointTypes,
		),
		ds: dedup.LazyDiskSet("firebase_rtdb_exposure"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) IncludesBaseCanProcess() bool { return false }

func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Request() == nil {
		return false
	}
	return ctx.Response() != nil
}

func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	if !ctx.HasResponse() {
		return nil, nil
	}

	body := ctx.Response().BodyToString()
	if body == "" {
		return nil, nil
	}

	// Extract RTDB URLs from response
	matches := rtdbURLRe.FindAllStringSubmatch(body, 10)
	if len(matches) == 0 {
		return nil, nil
	}

	// Deduplicate database names
	seen := make(map[string]struct{})
	var dbNames []string
	for _, match := range matches {
		if len(match) > 1 {
			name := match[1]
			if _, ok := seen[name]; !ok {
				seen[name] = struct{}{}
				dbNames = append(dbNames, name)
			}
		}
	}

	var diskSet *dedup.DiskSet
	if scanCtx != nil {
		diskSet = m.ds.Get(scanCtx.DedupMgr())
	}
	probeClient, err := httpClient.CloneWithoutCredentials()
	if err != nil {
		return nil, nil
	}

	var results []*output.ResultEvent
	for _, dbName := range dbNames {
		dedupKey := dbName + ".firebaseio.com"
		if diskSet != nil && diskSet.IsSeen(dedupKey) {
			continue
		}

		dbURL := fmt.Sprintf("https://%s.firebaseio.com", dbName)

		// Probe root with shallow=true
		if result := m.probeRTDB(ctx, probeClient, dbURL, "", true); result != nil {
			results = append(results, result)
			continue
		}

		// Root denied — probe common subpaths. Each readable subpath proves the SAME
		// signal (this database has world-readable paths), so collapse them into ONE
		// finding per database instead of writing an http_record per subpath; the
		// extra readable paths ride along as inline evidence.
		var subResults []*output.ResultEvent
		for _, subpath := range rtdbSubpaths {
			if result := m.probeRTDB(ctx, probeClient, dbURL, subpath, false); result != nil {
				subResults = append(subResults, result)
			}
		}
		results = append(results, modkit.CollapseFindings(subResults, modkit.CollapseSpec{
			Key: func(*output.ResultEvent) string { return dbURL },
		})...)
	}

	return results, nil
}

// looksLikeRTDBData reports whether a 200 body is genuine Firebase Realtime
// Database content: it must parse as JSON and be a non-empty object or array
// (the shape of an exposed data tree). It rejects invalid JSON (HTML/error
// interstitials returned with a 200), empty/null trees, a lone {"error": ...}
// Firebase error envelope, and bare scalars — all of which are not evidence of a
// world-readable database.
func looksLikeRTDBData(body string) bool {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" || trimmed == "null" || trimmed == "{}" || trimmed == "[]" {
		return false
	}
	var v interface{}
	if err := json.Unmarshal([]byte(trimmed), &v); err != nil {
		return false
	}
	switch t := v.(type) {
	case map[string]interface{}:
		if len(t) == 0 {
			return false
		}
		if _, hasErr := t["error"]; hasErr && len(t) == 1 {
			return false // lone {"error": ...} Firebase envelope, not data
		}
		return true
	case []interface{}:
		return len(t) > 0
	default:
		return false // bare scalar node — too weak to confirm exposure
	}
}

func (m *Module) probeRTDB(
	_ *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	dbURL string,
	subpath string,
	shallow bool,
) *output.ResultEvent {
	targetPath := "/.json"
	if subpath != "" {
		targetPath = "/" + subpath + ".json"
	}
	targetURL := dbURL + targetPath
	if shallow {
		targetURL += "?shallow=true"
	}

	first, ok := fetchRTDB(httpClient, targetURL, dbURL)
	if !ok || first.status != 200 {
		return nil
	}
	respBody := first.body

	// Skip permission denied responses
	if strings.Contains(respBody, "Permission denied") {
		return nil
	}

	// Strict drop-on-fail: a 200 is only an exposure when the body is genuine,
	// non-trivial RTDB data — a non-empty JSON object/array. This drops 200s that
	// are not valid JSON (interstitials / error pages on a coincidentally-matched
	// host), empty/null trees, Firebase error envelopes, and bare scalars.
	if !looksLikeRTDBData(respBody) {
		return nil
	}
	replay, ok := fetchRTDB(httpClient, targetURL, dbURL)
	if !ok || replay.status != 200 || !looksLikeRTDBData(replay.body) {
		return nil
	}

	assessment := assessRTDBData(respBody)
	kind := output.RecordKindCandidate
	grade := output.EvidenceGradeDifferential
	name := "Firebase RTDB Public Read Candidate (Root)"
	desc := fmt.Sprintf("Firebase Realtime Database at %s reproducibly returns a non-empty JSON tree without credentials. Public read may be intentional; sensitive values and write access were not established.", dbURL)
	sev := severity.Medium
	if subpath != "" {
		name = fmt.Sprintf("Firebase RTDB Public Read Candidate (/%s)", subpath)
		desc = fmt.Sprintf("Firebase Realtime Database at %s reproducibly returns non-empty JSON from /%s without credentials. Public read may be intentional; sensitive values and write access were not established.", dbURL, subpath)
	}
	if len(assessment) > 0 {
		kind = output.RecordKindFinding
		grade = output.EvidenceGradeImpact
		name = "Sensitive Data Read from Firebase RTDB"
		desc = fmt.Sprintf("Firebase Realtime Database at %s returned credential-free JSON containing sensitive field or private-credential evidence: %s.", dbURL, strings.Join(assessment, ", "))
		sev = severity.High
	}

	// Truncate response for storage
	responseStr := first.fullResponse
	if len(responseStr) > 4096 {
		responseStr = responseStr[:4096] + "\n... (truncated)"
	}

	return &output.ResultEvent{
		ModuleID:      ModuleID,
		RecordKind:    kind,
		EvidenceGrade: grade,
		URL:           targetURL,
		Matched:       targetURL,
		Request:       first.rawRequest,
		Response:      responseStr,
		AdditionalEvidence: []string{
			output.BuildEvidence("credential-free RTDB replay", replay.rawRequest, replay.fullResponse),
		},
		ExtractedResults: assessment,
		Info: output.Info{
			Name:        name,
			Description: desc,
			Severity:    sev,
			Confidence:  severity.Certain,
			Tags:        []string{"firebase", "rtdb", "data-exposure"},
		},
		Metadata: map[string]any{
			"database":                 dbURL,
			"subpath":                  subpath,
			"shallow":                  shallow,
			"credential_free":          true,
			"sensitive_data_confirmed": len(assessment) > 0,
			"write_access_tested":      false,
		},
	}
}

func fetchRTDB(httpClient *http.Requester, targetURL, dbURL string) (rtdbExchange, bool) {
	host := strings.TrimPrefix(strings.TrimPrefix(dbURL, "https://"), "http://")
	rawReq := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nAccept: application/json\r\n\r\n", targetURL, host)
	fuzzedReq, err := httpmsg.ParseRawRequest(rawReq)
	if err != nil {
		return rtdbExchange{}, false
	}
	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true, NoClustering: true})
	if err != nil {
		return rtdbExchange{}, false
	}
	defer resp.Close()
	if resp.Response() == nil || infra.IsBlockedResponse(resp) {
		return rtdbExchange{}, false
	}
	return rtdbExchange{
		status:       resp.Response().StatusCode,
		body:         resp.BodyString(),
		rawRequest:   rawReq,
		fullResponse: resp.FullResponseString(),
	}, true
}

var sensitiveRTDBKeys = map[string]bool{
	"password": true, "passwd": true, "secret": true, "private_key": true,
	"id_token": true, "refresh_token": true, "access_token": true,
	"session_token": true, "ssn": true, "credit_card": true, "card_number": true,
	"email": true, "phone": true, "address": true,
}

// assessRTDBData returns labels only; it never copies sensitive values into the
// finding summary. Boolean shallow-tree markers do not qualify as sensitive
// values, so {"tokens":true} remains a public-read candidate.
func assessRTDBData(body string) []string {
	labels := map[string]bool{}
	for _, pattern := range secretPatterns {
		if pattern.pattern.MatchString(body) {
			labels["private credential: "+pattern.name] = true
		}
	}
	var value any
	if json.Unmarshal([]byte(body), &value) == nil {
		walkRTDBValue(value, 0, labels)
	}
	result := make([]string, 0, len(labels))
	for label := range labels {
		result = append(result, label)
	}
	sort.Strings(result)
	return result
}

func walkRTDBValue(value any, depth int, labels map[string]bool) {
	if depth > 8 || len(labels) >= 20 {
		return
	}
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			normalized := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(key), "-", "_"))
			if sensitiveRTDBKeys[normalized] && substantiveRTDBValue(child) {
				labels["sensitive field: "+normalized] = true
			}
			walkRTDBValue(child, depth+1, labels)
		}
	case []any:
		for _, child := range typed {
			walkRTDBValue(child, depth+1, labels)
		}
	}
}

func substantiveRTDBValue(value any) bool {
	switch typed := value.(type) {
	case string:
		trimmed := strings.TrimSpace(typed)
		return len(trimmed) >= 3 && !modkit.IsPlaceholderValue(trimmed)
	case float64:
		return typed != 0
	default:
		return false
	}
}
