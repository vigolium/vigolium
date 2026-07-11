package drupal_user_enum

import (
	"encoding/json"
	"fmt"
	nethttp "net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

var usernameRegex = regexp.MustCompile(`/users?/([a-zA-Z0-9_.-]+)`)

// baselineProbeUID is a user ID far beyond any plausible real account. The
// canonical /user/<uid> route must NOT resolve to a profile for it. We extract a
// candidate the same way as the real probes and use it as a control: any real
// probe that yields the same candidate is reading a generic page the site
// returns for every /user/N (SSO wall, access-denied, error), not a per-user
// leak, so it is dropped.
const baselineProbeUID = 2147483646

// reservedUserRoutes are Drupal's own /user/<name> sub-paths. A redirect to one
// of these is the site's auth flow, not a leaked username, so the usernameRegex
// capture for them must be rejected.
var reservedUserRoutes = map[string]bool{
	"login":    true,
	"logout":   true,
	"register": true,
	"password": true,
	"reset":    true,
	"edit":     true,
	"cancel":   true,
}

// errorTitleMarkers are substrings that appear in generic error / auth / status
// page titles, never in a real Drupal username. A 200 SSO or CDN error page
// returns the same <title> for every /user/N (the motivating false positive: a
// CloudFront-fronted host whose /user/N all returned 200 "404 Not Found", and
// the common Drupal "Access denied | Site" page anonymous users get). A title
// containing any of these is not treated as an enumerated username.
var errorTitleMarkers = []string{
	"not found", "404", "403", "401", "500", "502", "503",
	"forbidden", "access denied", "unauthorized", "bad request",
	"error", "sign in", "signin", "sign-in", "log in", "login", "logout",
	"register", "page not found", "service unavailable", "bad gateway",
	"gateway timeout", "maintenance", "redirecting", "loading",
	"just a moment", "attention required", "captcha", "are you a robot",
	"session expired", "please wait", "unavailable", "not authorized",
	"verify you are human", "checking your browser",
}

// drupalBodyMarkers are byte needles specific to a Drupal-rendered HTML page.
// The 200/title vector is weak on its own (any page has a <title>), so it is
// trusted only when the response actually looks like Drupal — otherwise a
// generic 200 page from a non-Drupal host (S3/SSO/SPA) would be mined for a
// "username".
var drupalBodyMarkers = []string{
	"drupal-settings-json",
	"data-drupal-",
	"/sites/default/files",
	"/sites/all/",
	"/core/misc/drupal",
	"/core/themes/",
	"Drupal.settings",
}

type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
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
		ds: dedup.LazyDiskSet("drupal_user_enum"),
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
	service := ctx.Service()
	if service == nil {
		return nil, nil
	}
	host := service.Host()

	if scanCtx != nil {
		diskSet := m.ds.Get(scanCtx.DedupMgr())
		if diskSet != nil && diskSet.IsSeen(host) {
			return nil, nil
		}
	}
	cleanRaw, err := modkit.StripCredentialHeaders(ctx.Request().Raw())
	if err != nil {
		return nil, nil
	}
	anonymousClient, err := httpClient.CloneWithoutCredentials()
	if err != nil {
		return nil, nil
	}
	anonymousCtx := httpmsg.NewHttpRequestResponse(
		httpmsg.NewHttpRequestWithService(service, cleanRaw),
		ctx.Response(),
	)

	var results []*output.ResultEvent

	// Vector 1: /user/N enumeration.
	//
	// Baseline control: a UID far beyond any real account must not resolve to a
	// profile. Whatever candidate it produces is the site's generic page for an
	// unknown user; any real probe matching it is reading that same page, not a
	// leak.
	baseline := m.probeUserPath(anonymousCtx, anonymousClient, fmt.Sprintf("/user/%d", baselineProbeUID), strconv.Itoa(baselineProbeUID))

	var rawMatches []string
	seen := map[string]bool{}
	var usernames []string
	for i := 1; i <= 5; i++ {
		path := fmt.Sprintf("/user/%d", i)
		username := m.probeUserPath(anonymousCtx, anonymousClient, path, strconv.Itoa(i))
		if username == "" || username == baseline {
			continue
		}
		rawMatches = append(rawMatches, username)
		if !seen[username] {
			seen[username] = true
			usernames = append(usernames, username)
		}
	}

	// Uniformity guard: genuine enumeration leaks a different username per UID.
	// Multiple UIDs collapsing to a single value means one generic page was
	// echoed for every path (a single existing account legitimately yields one
	// match from one probe, so this only trips on 2+ identical hits).
	if len(rawMatches) >= 2 && len(usernames) == 1 {
		usernames = nil
	}

	if len(usernames) > 0 {
		urlx, _ := anonymousCtx.URL()
		results = append(results, &output.ResultEvent{
			ModuleID:         ModuleID,
			RecordKind:       output.RecordKindObservation,
			EvidenceGrade:    output.EvidenceGradeObservation,
			URL:              urlx.Scheme + "://" + urlx.Host + "/user/1",
			Matched:          urlx.Scheme + "://" + urlx.Host + "/user/1",
			ExtractedResults: usernames,
			Info: output.Info{
				Name:        "Drupal Public Profile Names Observed",
				Description: fmt.Sprintf("Observed %d distinct Drupal profile name(s) through public numeric profile routes: %s. Public profiles are normal site behavior; no login-name mapping or authentication weakness was proven.", len(usernames), strings.Join(usernames, ", ")),
				Severity:    severity.Info,
				Confidence:  severity.Certain,
				Tags:        []string{"cms", "drupal", "user-enumeration"},
				Reference:   []string{"https://www.drupal.org/docs/security-in-drupal"},
			},
			Metadata: map[string]any{
				"usernames":                usernames,
				"vector":                   "user-profile-path",
				"credential_free":          true,
				"login_identity_confirmed": false,
			},
		})
	}

	// Vector 2: JSON:API user listing
	if result := m.probeJsonAPI(anonymousCtx, anonymousClient); result != nil {
		results = append(results, result)
	}

	return results, nil
}

// probeUserPath requests path and returns the username it leaks, or "" when the
// response is not a trustworthy per-user profile signal. It gates on
// block/SSO/challenge detection first, then accepts either a canonical redirect
// to /users/<name> (excluding Drupal's own auth routes) or a 200 profile page —
// the latter only when the response actually looks like Drupal and its <title>
// is not a generic error/auth title. uid is the numeric id requested in path; a
// redirect whose captured segment is just that id echoed back (bare or with an
// appended extension/selectors) is self-canonicalisation, not a leaked username.
func (m *Module) probeUserPath(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, path, uid string) string {
	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return ""
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, path)
	if err != nil {
		return ""
	}
	// modifiedRaw is well-formed raw, so wrap directly instead of re-parsing on this hot path.
	fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true, NoClustering: true})
	if err != nil {
		return ""
	}
	defer resp.Close()

	if resp.Response() == nil {
		return ""
	}

	// A WAF/CDN challenge, auth gate, rate-limit, or maintenance page is the
	// edge talking, not the application leaking a profile — skip it before
	// extracting anything (the SSO-wall / CloudFront false-positive class).
	if infra.IsBlockedResponse(resp) {
		return ""
	}

	status := resp.Response().StatusCode

	// Redirect vector: canonical /user/<uid> -> /users/<username>.
	if status == 301 || status == 302 || status == 303 {
		location := resp.Response().Header.Get("Location")
		if matches := usernameRegex.FindStringSubmatch(location); len(matches) > 1 {
			username := matches[1]
			// Drop UIDs echoed back (bare numeric, or the requested id with an
			// appended extension/selectors like AEM's /user/1 -> /user/1.html),
			// Drupal's own auth routes, and any error/status-shaped segment.
			if !isNumeric(username) && !isUIDEcho(username, uid) && !isReservedUserRoute(username) && looksLikeUsername(username) {
				return username
			}
		}
		return ""
	}

	// Title vector: a 200 profile page may show "username | Site Name". Trust it
	// only when the response is recognisably Drupal and the title is not a
	// generic error/auth page title.
	if status == 200 {
		body := resp.Body().String()
		if !looksLikeDrupal(resp.Response().Header, body) {
			return ""
		}
		candidate := extractTitleUsername(body)
		if candidate != "" && !isNumeric(candidate) && looksLikeUsername(candidate) {
			return candidate
		}
	}

	return ""
}

func (m *Module) probeJsonAPI(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester) *output.ResultEvent {
	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, "/jsonapi/user/user")
	if err != nil {
		return nil
	}
	// modifiedRaw is well-formed raw, so wrap directly instead of re-parsing on this hot path.
	fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true, NoClustering: true})
	if err != nil {
		return nil
	}
	defer resp.Close()

	if resp.Response() == nil || resp.Response().StatusCode != 200 {
		return nil
	}

	// An SSO/CDN gate can answer the JSON:API path with a 200 too — skip it.
	if infra.IsBlockedResponse(resp) {
		return nil
	}

	ct := strings.ToLower(resp.Response().Header.Get("Content-Type"))
	if !strings.Contains(ct, "json") {
		return nil
	}

	body := resp.Body().String()
	userCount, userLabels, ok := parseDrupalJSONAPIUsers(body)
	if !ok {
		return nil
	}

	urlx, _ := ctx.URL()
	return &output.ResultEvent{
		ModuleID:         ModuleID,
		RecordKind:       output.RecordKindObservation,
		EvidenceGrade:    output.EvidenceGradeObservation,
		URL:              urlx.Scheme + "://" + urlx.Host + "/jsonapi/user/user",
		Matched:          urlx.Scheme + "://" + urlx.Host + "/jsonapi/user/user",
		Request:          string(modifiedRaw),
		Response:         resp.FullResponseString(),
		ExtractedResults: userLabels,
		Info: output.Info{
			Name:        "Drupal Public JSON:API User Objects Observed",
			Description: fmt.Sprintf("Drupal JSON:API returned %d structurally valid user object(s) without credentials. Public profile data may be intentional; no private account or login weakness was proven.", userCount),
			Severity:    severity.Info,
			Confidence:  severity.Certain,
			Tags:        []string{"cms", "drupal", "user-enumeration", "api"},
			Reference:   []string{"https://www.drupal.org/docs/core-modules-and-themes/core-modules/jsonapi-module"},
		},
		Metadata: map[string]any{
			"vector":                  "jsonapi",
			"count":                   userCount,
			"credential_free":         true,
			"private_accounts_proven": false,
		},
	}
}

func parseDrupalJSONAPIUsers(body string) (int, []string, bool) {
	var document struct {
		Data []struct {
			Type       string         `json:"type"`
			ID         string         `json:"id"`
			Attributes map[string]any `json:"attributes"`
		} `json:"data"`
	}
	if json.Unmarshal([]byte(body), &document) != nil || len(document.Data) == 0 {
		return 0, nil, false
	}
	labels := make([]string, 0, len(document.Data))
	count := 0
	for _, resource := range document.Data {
		if resource.Type != "user--user" {
			continue
		}
		count++
		label := resource.ID
		for _, key := range []string{"name", "display_name", "label"} {
			if value, ok := resource.Attributes[key].(string); ok && strings.TrimSpace(value) != "" {
				label = value
				break
			}
		}
		if label != "" {
			labels = append(labels, label)
		}
	}
	return count, labels, count > 0
}

// extractTitleUsername returns the leading segment of the page <title>, which on
// a Drupal profile page is the username in "username | Site Name".
func extractTitleUsername(body string) string {
	titleStart := strings.Index(body, "<title>")
	if titleStart < 0 {
		return ""
	}
	rest := body[titleStart+len("<title>"):]
	titleEnd := strings.Index(rest, "</title>")
	if titleEnd < 0 {
		return ""
	}
	title := strings.TrimSpace(rest[:titleEnd])
	parts := strings.SplitN(title, " | ", 2)
	return strings.TrimSpace(parts[0])
}

// looksLikeDrupal reports whether the response is recognisably a Drupal page,
// used to corroborate the weak title vector before trusting its <title>.
func looksLikeDrupal(header nethttp.Header, body string) bool {
	if strings.Contains(strings.ToLower(header.Get("X-Generator")), "drupal") {
		return true
	}
	if header.Get("X-Drupal-Cache") != "" || header.Get("X-Drupal-Dynamic-Cache") != "" {
		return true
	}
	for _, marker := range drupalBodyMarkers {
		if strings.Contains(body, marker) {
			return true
		}
	}
	return false
}

// looksLikeUsername rejects candidates that are empty, implausibly long, or
// shaped like an error/auth/status title rather than a username.
func looksLikeUsername(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 60 {
		return false
	}
	lower := strings.ToLower(s)
	for _, marker := range errorTitleMarkers {
		if strings.Contains(lower, marker) {
			return false
		}
	}
	return true
}

func isReservedUserRoute(s string) bool {
	return reservedUserRoutes[strings.ToLower(s)]
}

// isUIDEcho reports whether the captured /user(s)/<segment> is just the
// requested numeric uid the site canonicalised back at us — bare, or with an
// appended file extension and/or selectors (e.g. AEM redirecting /user/1 to
// /user/1.html, or /user/1.profile.html). That is a self-redirect, not a leaked
// username, so it must not be mined for a name. A genuine Drupal enumeration
// leaks a different, non-numeric username token instead.
func isUIDEcho(captured, uid string) bool {
	if uid == "" {
		return false
	}
	return captured == uid || strings.HasPrefix(captured, uid+".")
}

func isNumeric(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}
