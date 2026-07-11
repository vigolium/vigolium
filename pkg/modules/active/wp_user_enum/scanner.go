package wp_user_enum

import (
	"encoding/json"
	"fmt"
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

// baselineAuthorID is an author id far beyond any plausible real account. A
// genuine WordPress /?author=N redirect must NOT resolve to a real author slug
// for it. Whatever slug it yields is the site's generic redirect for an unknown
// author (catch-all / canonicalisation / SSO wall); any real probe matching it
// is reading that same page, not a per-author leak, so it is dropped.
const baselineAuthorID = 2147483646

// reservedAuthorSlugs are WordPress' own routes / generic tokens that show up as
// the /author/<slug> segment when the site canonicalises or auth-walls the
// request rather than leaking a username. None is a real login slug.
var reservedAuthorSlugs = map[string]bool{
	"login":    true,
	"logout":   true,
	"register": true,
	"wp-login": true,
	"wp-admin": true,
	"password": true,
	"reset":    true,
}

// errorSlugMarkers are substrings that appear in error/auth/status redirect
// targets, never in a real author slug. A site that answers every /?author=N
// with a generic redirect (404/SSO/maintenance) echoes one of these, not a
// username.
var errorSlugMarkers = []string{
	"404", "403", "401", "500", "502", "503",
	"not-found", "notfound", "forbidden", "access-denied", "accessdenied",
	"unauthorized", "error", "sign-in", "signin", "sign_in",
	"maintenance", "unavailable", "captcha", "redirect",
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
		ds: dedup.LazyDiskSet("wp_user_enum"),
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

	urlx, err := anonymousCtx.URL()
	if err != nil {
		return nil, nil
	}

	baseURL := urlx.Scheme + "://" + urlx.Host
	var results []*output.ResultEvent

	// 1. Author archive enumeration: /?author=1..5
	//
	// Baseline control: an author id far beyond any real account must not resolve
	// to a real author slug. Whatever it yields is the site's generic redirect for
	// an unknown author; any real probe matching it is reading that same catch-all,
	// not a leak.
	baseline := m.probeAuthor(anonymousCtx, anonymousClient, baselineAuthorID)

	var rawSlugs []string
	seen := map[string]bool{}
	var authorUsers []string
	for i := 1; i <= 5; i++ {
		username := m.probeAuthor(anonymousCtx, anonymousClient, i)
		if username == "" || username == baseline {
			continue
		}
		rawSlugs = append(rawSlugs, username)
		if !seen[username] {
			seen[username] = true
			authorUsers = append(authorUsers, username)
		}
	}

	// Uniformity guard: genuine enumeration leaks a different slug per author id.
	// Multiple ids collapsing to a single value means one generic redirect was
	// echoed for every /?author=N (a single existing account legitimately yields
	// one match from one probe, so this only trips on 2+ identical hits).
	if len(rawSlugs) >= 2 && len(authorUsers) == 1 {
		authorUsers = nil
	}

	if len(authorUsers) > 0 {
		results = append(results, &output.ResultEvent{
			ModuleID:         ModuleID,
			RecordKind:       output.RecordKindObservation,
			EvidenceGrade:    output.EvidenceGradeObservation,
			URL:              baseURL + "/?author=1",
			Matched:          baseURL + "/?author=1",
			ExtractedResults: authorUsers,
			Info: output.Info{
				Name:        "WordPress Public Author Slugs Observed",
				Description: fmt.Sprintf("Observed %d distinct WordPress author slug(s) through public /?author=N canonical redirects: %s. Public author archives are normal CMS behavior; no login weakness was tested.", len(authorUsers), strings.Join(authorUsers, ", ")),
				Severity:    severity.Info,
				Confidence:  severity.Certain,
				Tags:        []string{"wordpress", "user-enumeration"},
			},
			Metadata: map[string]any{
				"users":                   authorUsers,
				"method":                  "author-archive",
				"credential_free":         true,
				"authentication_weakness": false,
			},
		})
	}

	// 2. REST API user enumeration: /wp-json/wp/v2/users
	restUsers := m.probeRESTUsers(anonymousCtx, anonymousClient)
	if len(restUsers) > 0 {
		results = append(results, &output.ResultEvent{
			ModuleID:         ModuleID,
			RecordKind:       output.RecordKindObservation,
			EvidenceGrade:    output.EvidenceGradeObservation,
			URL:              baseURL + "/wp-json/wp/v2/users",
			Matched:          baseURL + "/wp-json/wp/v2/users",
			ExtractedResults: restUsers,
			Info: output.Info{
				Name:        "WordPress Public REST Authors Observed",
				Description: fmt.Sprintf("Observed %d public WordPress author slug(s) in the REST users collection: %s. WordPress exposes authors for published content by design; no private account or authentication weakness was proven.", len(restUsers), strings.Join(restUsers, ", ")),
				Severity:    severity.Info,
				Confidence:  severity.Certain,
				Tags:        []string{"wordpress", "user-enumeration", "rest-api"},
			},
			Metadata: map[string]any{
				"users":                   restUsers,
				"method":                  "rest-api",
				"credential_free":         true,
				"private_accounts_proven": false,
			},
		})
	}

	return results, nil
}

func (m *Module) probeAuthor(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, authorID int) string {
	path := fmt.Sprintf("/?author=%d", authorID)
	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return ""
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, path)
	if err != nil {
		return ""
	}

	// SetMethod/SetPath produce well-formed raw, so wrap directly instead
	// of re-parsing on this hot path.
	fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true, NoClustering: true})
	if err != nil {
		return ""
	}
	defer resp.Close()

	if resp.Response() == nil {
		return ""
	}

	// A WAF/CDN challenge, auth gate, rate-limit, or maintenance page is the edge
	// talking, not WordPress leaking an author archive — skip it before extracting
	// anything.
	if infra.IsBlockedResponse(resp) {
		return ""
	}

	// Check for redirect to /author/<username>/
	status := resp.Response().StatusCode
	if status == 301 || status == 302 {
		location := resp.Response().Header.Get("Location")
		if idx := strings.Index(location, "/author/"); idx >= 0 {
			slug := location[idx+len("/author/"):]
			slug = strings.TrimSuffix(strings.TrimSpace(slug), "/")
			// A trailing query/fragment is canonicalisation noise, not the slug.
			if cut := strings.IndexAny(slug, "?#"); cut >= 0 {
				slug = slug[:cut]
			}
			if slug == "" || strings.Contains(slug, "/") {
				return ""
			}
			// Reject the author id echoed straight back (a bare number, or the id
			// canonicalised with an appended extension/selector like /author/1.html),
			// WordPress' own routes, and any error/auth/status-shaped token — none is
			// a leaked username. A genuine leak resolves to a distinct, real slug.
			if isNumeric(slug) || isAuthorIDEcho(slug, authorID) || isReservedAuthorSlug(slug) || !looksLikeUsername(slug) {
				return ""
			}
			return slug
		}
	}

	return ""
}

// isAuthorIDEcho reports whether the /author/<slug> segment is just the requested
// author id echoed back — bare, or canonicalised with an appended file extension
// or selectors (e.g. /author/1 -> /author/1.html). That is a self-redirect, not
// a username leak.
func isAuthorIDEcho(slug string, authorID int) bool {
	id := strconv.Itoa(authorID)
	return slug == id || strings.HasPrefix(slug, id+".")
}

// isReservedAuthorSlug reports whether the slug is one of WordPress' own routes
// rather than a username.
func isReservedAuthorSlug(s string) bool {
	return reservedAuthorSlugs[strings.ToLower(s)]
}

// looksLikeUsername rejects slugs that are empty, implausibly long, or shaped
// like an error/auth/status redirect target rather than a username.
func looksLikeUsername(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 60 {
		return false
	}
	lower := strings.ToLower(s)
	for _, marker := range errorSlugMarkers {
		if strings.Contains(lower, marker) {
			return false
		}
	}
	return true
}

// isNumeric reports whether s is a non-empty run of digits.
func isNumeric(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}

func (m *Module) probeRESTUsers(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester) []string {
	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, "/wp-json/wp/v2/users?per_page=100")
	if err != nil {
		return nil
	}

	// SetMethod/SetPath produce well-formed raw, so wrap directly instead
	// of re-parsing on this hot path.
	fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true, NoClustering: true})
	if err != nil {
		return nil
	}
	defer resp.Close()

	if resp.Response() == nil || resp.Response().StatusCode != 200 {
		return nil
	}

	// An SSO/CDN gate can answer the REST path with a 200 too — skip it.
	if infra.IsBlockedResponse(resp) {
		return nil
	}

	ct := strings.ToLower(resp.Response().Header.Get("Content-Type"))
	if !strings.Contains(ct, "application/json") {
		return nil
	}

	body := resp.Body().Bytes()

	var users []struct {
		Slug string `json:"slug"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal(body, &users); err != nil {
		return nil
	}

	var slugs []string
	for _, u := range users {
		if u.Slug != "" {
			slugs = append(slugs, u.Slug)
		}
	}
	return slugs
}
