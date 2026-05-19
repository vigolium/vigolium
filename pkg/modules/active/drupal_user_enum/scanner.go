package drupal_user_enum

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

var usernameRegex = regexp.MustCompile(`/users?/([a-zA-Z0-9_.-]+)`)

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

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(host) {
		return nil, nil
	}

	var results []*output.ResultEvent

	// Vector 1: /user/N enumeration
	var usernames []string
	for i := 1; i <= 5; i++ {
		path := fmt.Sprintf("/user/%d", i)
		username := m.probeUserPath(ctx, httpClient, path)
		if username != "" {
			usernames = append(usernames, username)
		}
	}

	if len(usernames) > 0 {
		urlx, _ := ctx.URL()
		results = append(results, &output.ResultEvent{
			URL:              urlx.Scheme + "://" + urlx.Host + "/user/1",
			Matched:          urlx.Scheme + "://" + urlx.Host + "/user/1",
			ExtractedResults: usernames,
			Info: output.Info{
				Name:        "Drupal User Enumeration via Profile Paths",
				Description: fmt.Sprintf("Drupal user profile paths expose %d username(s): %s", len(usernames), strings.Join(usernames, ", ")),
				Severity:    severity.Medium,
				Confidence:  severity.Certain,
				Tags:        []string{"cms", "drupal", "user-enumeration"},
				Reference:   []string{"https://www.drupal.org/docs/security-in-drupal"},
			},
			Metadata: map[string]any{
				"usernames": usernames,
				"vector":    "user-profile-path",
			},
		})
	}

	// Vector 2: JSON:API user listing
	if result := m.probeJsonAPI(ctx, httpClient); result != nil {
		results = append(results, result)
	}

	return results, nil
}

func (m *Module) probeUserPath(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, path string) string {
	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return ""
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, path)
	if err != nil {
		return ""
	}
	fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
	if err != nil {
		return ""
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return ""
	}
	defer resp.Close()

	if resp.Response() == nil {
		return ""
	}

	// Check for redirect to /users/<username> or /user/<uid>/<username>
	status := resp.Response().StatusCode
	if status == 301 || status == 302 || status == 303 {
		location := resp.Response().Header.Get("Location")
		if matches := usernameRegex.FindStringSubmatch(location); len(matches) > 1 {
			username := matches[1]
			// Filter out numeric-only (still UID, not username)
			if !isNumeric(username) {
				return username
			}
		}
	}

	// Also check 200 responses for username in page title or breadcrumb
	if status == 200 {
		body := resp.Body().String()
		// Drupal often shows username in <title> or <h1> on user profile pages
		if strings.Contains(body, "<title>") {
			// Extract title content
			titleStart := strings.Index(body, "<title>")
			titleEnd := strings.Index(body[titleStart:], "</title>")
			if titleEnd > 0 {
				title := body[titleStart+7 : titleStart+titleEnd]
				title = strings.TrimSpace(title)
				// Drupal title format: "username | Site Name"
				if parts := strings.SplitN(title, " | ", 2); len(parts) >= 1 {
					candidate := strings.TrimSpace(parts[0])
					if candidate != "" && !isNumeric(candidate) && len(candidate) < 64 {
						return candidate
					}
				}
			}
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
	fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
	if err != nil {
		return nil
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil
	}
	defer resp.Close()

	if resp.Response() == nil || resp.Response().StatusCode != 200 {
		return nil
	}

	ct := strings.ToLower(resp.Response().Header.Get("Content-Type"))
	if !strings.Contains(ct, "json") {
		return nil
	}

	body := resp.Body().String()
	// Check for JSON:API user data markers
	if !strings.Contains(body, `"type":"user--user"`) && !strings.Contains(body, `"type": "user--user"`) {
		return nil
	}

	urlx, _ := ctx.URL()
	return &output.ResultEvent{
		URL:      urlx.Scheme + "://" + urlx.Host + "/jsonapi/user/user",
		Matched:  urlx.Scheme + "://" + urlx.Host + "/jsonapi/user/user",
		Response: body,
		Info: output.Info{
			Name:        "Drupal User Enumeration via JSON:API",
			Description: "Drupal JSON:API exposes user objects anonymously at /jsonapi/user/user",
			Severity:    severity.Medium,
			Confidence:  severity.Certain,
			Tags:        []string{"cms", "drupal", "user-enumeration", "api"},
			Reference:   []string{"https://www.drupal.org/docs/core-modules-and-themes/core-modules/jsonapi-module"},
		},
		Metadata: map[string]any{
			"vector": "jsonapi",
		},
	}
}

func isNumeric(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}
