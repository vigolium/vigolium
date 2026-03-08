package firebase_fingerprint

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

var (
	// Firebase config extraction
	projectIDRe     = regexp.MustCompile(`["']projectId["']\s*:\s*["']([a-z0-9-]+)["']`)
	apiKeyRe        = regexp.MustCompile(`["']apiKey["']\s*:\s*["'](AIza[a-zA-Z0-9_-]{35})["']`)
	databaseURLRe   = regexp.MustCompile(`["']databaseURL["']\s*:\s*["'](https://[a-z0-9-]+\.firebaseio\.com)["']`)
	storageBucketRe = regexp.MustCompile(`["']storageBucket["']\s*:\s*["']([a-z0-9-]+\.appspot\.com)["']`)
	authDomainRe    = regexp.MustCompile(`["']authDomain["']\s*:\s*["']([a-z0-9-]+\.firebaseapp\.com)["']`)
	appIDRe         = regexp.MustCompile(`["']appId["']\s*:\s*["']([0-9]+:[0-9]+:web:[a-f0-9]+)["']`)

	// FCM server key patterns
	fcmServerKeyRe = regexp.MustCompile(`(?:Authorization:\s*key=|["']server_key["']\s*:\s*["']|fcm[_.]?key["']\s*:\s*["'])(AAAA[a-zA-Z0-9_-]{100,})`)

	// App Check debug token
	appCheckDebugRe = regexp.MustCompile(`(?:APPCHECK_DEBUG_TOKEN|FIREBASE_APPCHECK_DEBUG_TOKEN)\s*[=:]\s*["']?([a-f0-9-]{36,})`)

	// RTDB auth token in URL
	rtdbAuthTokenRe = regexp.MustCompile(`[a-z0-9-]+\.firebaseio\.com[^\s"']*[?&]auth=([a-zA-Z0-9._-]+)`)

	// Storage download token in URL
	storageTokenRe = regexp.MustCompile(`firebasestorage\.googleapis\.com/v0/b/[^\s"']*[?&]token=([a-f0-9-]{36})`)

	// Firestore collection references
	collectionRefRe = regexp.MustCompile(`(?:collection|doc|collectionGroup)\s*\(\s*["']([a-zA-Z0-9_-]+)["']`)

	// Cloud Functions URL
	cloudFuncURLRe = regexp.MustCompile(`https://([a-z0-9-]+)-([a-z0-9-]+)\.cloudfunctions\.net/([a-zA-Z0-9_-]+)`)

	// Staging/dev indicators in project ID
	devProjectRe = regexp.MustCompile(`(?i)-(dev|staging|test|qa|sandbox|debug|local)$`)
)

// Firebase detection signals
var firebaseSignals = []struct {
	check  func(body string, headers func(string) string) bool
	strong bool
}{
	{check: func(body string, _ func(string) string) bool {
		return strings.Contains(body, "firebase.initializeApp") || strings.Contains(body, "initializeApp({")
	}, strong: true},
	{check: func(body string, _ func(string) string) bool {
		return strings.Contains(body, "firebaseConfig")
	}, strong: true},
	{check: func(body string, _ func(string) string) bool {
		return strings.Contains(body, ".firebaseio.com")
	}, strong: true},
	{check: func(body string, _ func(string) string) bool {
		return strings.Contains(body, "firebasestorage.googleapis.com")
	}, strong: true},
	{check: func(body string, _ func(string) string) bool {
		return strings.Contains(body, "/__/firebase/")
	}, strong: true},
	{check: func(body string, _ func(string) string) bool {
		return strings.Contains(body, "firebase-messaging-sw.js")
	}, strong: false},
	{check: func(body string, _ func(string) string) bool {
		return strings.Contains(body, "identitytoolkit.googleapis.com")
	}, strong: true},
	{check: func(body string, _ func(string) string) bool {
		return strings.Contains(body, ".cloudfunctions.net")
	}, strong: true},
	{check: func(body string, _ func(string) string) bool {
		return strings.Contains(body, ".firebaseapp.com")
	}, strong: false},
}

type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

func New() *Module {
	m := &Module{
		BasePassiveModule: modkit.NewBasePassiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.PassiveScanScopeResponse,
		),
		ds: dedup.LazyDiskSet("firebase_fingerprint"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if !ctx.HasResponse() {
		return nil, nil
	}

	ct := strings.ToLower(ctx.Response().Header("Content-Type"))
	isHTML := strings.Contains(ct, "text/html")
	isJS := strings.Contains(ct, "javascript") || strings.Contains(ct, "application/json")
	if !isHTML && !isJS {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}

	host := urlx.Host
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(host) {
		return nil, nil
	}

	body := ctx.Response().BodyToString()
	hdr := func(name string) string { return ctx.Response().Header(name) }

	// Check for Firebase signals
	detected := false
	for _, sig := range firebaseSignals {
		if sig.check(body, hdr) && sig.strong {
			detected = true
			break
		}
	}
	if !detected {
		return nil, nil
	}

	// Extract config values
	projectID := extractFirst(projectIDRe, body)
	apiKey := extractFirst(apiKeyRe, body)
	databaseURL := extractFirst(databaseURLRe, body)
	storageBucket := extractFirst(storageBucketRe, body)
	authDomain := extractFirst(authDomainRe, body)
	appID := extractFirst(appIDRe, body)

	// Build extracted results
	var extracted []string
	if projectID != "" {
		extracted = append(extracted, fmt.Sprintf("projectId: %s", projectID))
	}
	if apiKey != "" {
		extracted = append(extracted, fmt.Sprintf("apiKey: %s", apiKey))
	}
	if databaseURL != "" {
		extracted = append(extracted, fmt.Sprintf("databaseURL: %s", databaseURL))
	}
	if storageBucket != "" {
		extracted = append(extracted, fmt.Sprintf("storageBucket: %s", storageBucket))
	}
	if authDomain != "" {
		extracted = append(extracted, fmt.Sprintf("authDomain: %s", authDomain))
	}
	if appID != "" {
		extracted = append(extracted, fmt.Sprintf("appId: %s", appID))
	}

	// Extract collection references
	collections := uniqueMatches(collectionRefRe, body)
	for _, col := range collections {
		extracted = append(extracted, fmt.Sprintf("Collection: %s", col))
	}

	// Extract Cloud Functions URLs
	funcURLs := cloudFuncURLRe.FindAllString(body, -1)
	for _, u := range funcURLs {
		extracted = append(extracted, fmt.Sprintf("Function: %s", u))
	}

	desc := "Firebase usage detected"
	if projectID != "" {
		desc = fmt.Sprintf("Firebase project '%s' detected", projectID)
	}

	var results []*output.ResultEvent

	// Main fingerprint finding
	if len(extracted) > 0 {
		metadata := map[string]any{
			"platform":      "firebase",
			"projectId":     projectID,
			"apiKey":        apiKey,
			"databaseURL":   databaseURL,
			"storageBucket": storageBucket,
			"authDomain":    authDomain,
			"appId":         appID,
		}
		if len(collections) > 0 {
			metadata["collections"] = collections
		}

		results = append(results, &output.ResultEvent{
			ModuleID:         ModuleID,
			Host:             host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			ExtractedResults: extracted,
			Info: output.Info{
				Name:        "Firebase Installation Detected",
				Description: desc,
				Severity:    severity.Info,
				Confidence:  severity.Certain,
				Tags:        []string{"firebase", "fingerprint", "baas"},
			},
			Metadata: metadata,
		})
	}

	// Security issue: FCM server key leaked
	if m := fcmServerKeyRe.FindStringSubmatch(body); len(m) > 1 {
		results = append(results, &output.ResultEvent{
			ModuleID: ModuleID,
			Host:     host,
			URL:      urlx.String(),
			Matched:  "FCM server key: " + m[1][:20] + "...",
			Info: output.Info{
				Name:        "Firebase FCM Server Key Leaked",
				Description: "Legacy FCM server key exposed in frontend code — attackers can send push notifications to app users",
				Severity:    severity.High,
				Confidence:  severity.Certain,
				Tags:        []string{"firebase", "secret-leak", "fcm"},
			},
		})
	}

	// Security issue: App Check debug token
	if m := appCheckDebugRe.FindStringSubmatch(body); len(m) > 1 {
		results = append(results, &output.ResultEvent{
			ModuleID: ModuleID,
			Host:     host,
			URL:      urlx.String(),
			Matched:  "App Check debug token: " + m[1],
			Info: output.Info{
				Name:        "Firebase App Check Debug Token Leaked",
				Description: "App Check debug token embedded in public assets — bypasses App Check enforcement",
				Severity:    severity.High,
				Confidence:  severity.Certain,
				Tags:        []string{"firebase", "secret-leak", "app-check"},
			},
		})
	}

	// Security issue: RTDB auth token in URL
	if m := rtdbAuthTokenRe.FindStringSubmatch(body); len(m) > 1 {
		results = append(results, &output.ResultEvent{
			ModuleID: ModuleID,
			Host:     host,
			URL:      urlx.String(),
			Matched:  "RTDB auth token in URL",
			Info: output.Info{
				Name:        "Firebase RTDB Auth Token Leaked in URL",
				Description: "Realtime Database authentication token embedded in a URL — provides direct database access",
				Severity:    severity.High,
				Confidence:  severity.Firm,
				Tags:        []string{"firebase", "secret-leak", "rtdb"},
			},
		})
	}

	// Security issue: Storage download tokens leaked
	storageTokenMatches := storageTokenRe.FindAllStringSubmatch(body, 5)
	if len(storageTokenMatches) > 0 {
		results = append(results, &output.ResultEvent{
			ModuleID: ModuleID,
			Host:     host,
			URL:      urlx.String(),
			Matched:  fmt.Sprintf("%d Firebase Storage download token(s) found", len(storageTokenMatches)),
			Info: output.Info{
				Name:        "Firebase Storage Download Tokens Exposed",
				Description: "Long-lived Firebase Storage download tokens found in public content — files accessible via these URLs",
				Severity:    severity.Medium,
				Confidence:  severity.Firm,
				Tags:        []string{"firebase", "secret-leak", "storage"},
			},
		})
	}

	// Security issue: Staging/dev project
	if projectID != "" && devProjectRe.MatchString(projectID) {
		results = append(results, &output.ResultEvent{
			ModuleID: ModuleID,
			Host:     host,
			URL:      urlx.String(),
			Matched:  fmt.Sprintf("Non-production project ID: %s", projectID),
			Info: output.Info{
				Name:        "Firebase Non-Production Project in Use",
				Description: fmt.Sprintf("Production domain references Firebase project '%s' which appears to be a dev/staging/test project — likely has permissive security rules", projectID),
				Severity:    severity.Medium,
				Confidence:  severity.Firm,
				Tags:        []string{"firebase", "misconfiguration", "environment"},
			},
		})
	}

	return results, nil
}

func extractFirst(re *regexp.Regexp, body string) string {
	if m := re.FindStringSubmatch(body); len(m) > 1 {
		return m[1]
	}
	return ""
}

func uniqueMatches(re *regexp.Regexp, body string) []string {
	matches := re.FindAllStringSubmatch(body, -1)
	seen := make(map[string]struct{})
	var result []string
	for _, m := range matches {
		if len(m) > 1 {
			val := m[1]
			if _, ok := seen[val]; !ok {
				seen[val] = struct{}{}
				result = append(result, val)
			}
		}
	}
	return result
}
