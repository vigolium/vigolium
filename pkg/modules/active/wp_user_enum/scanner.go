package wp_user_enum

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

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
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(host) {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}

	baseURL := urlx.Scheme + "://" + urlx.Host
	var results []*output.ResultEvent

	// 1. Author archive enumeration: /?author=1..5
	var authorUsers []string
	for i := 1; i <= 5; i++ {
		username := m.probeAuthor(ctx, httpClient, i)
		if username != "" {
			authorUsers = append(authorUsers, username)
		}
	}

	if len(authorUsers) > 0 {
		results = append(results, &output.ResultEvent{
			URL:              baseURL + "/?author=1",
			Matched:          baseURL + "/?author=1",
			ExtractedResults: authorUsers,
			Info: output.Info{
				Name:        "WordPress User Enumeration via Author Archives",
				Description: fmt.Sprintf("Discovered %d WordPress username(s) via /?author=N redirect enumeration: %s", len(authorUsers), strings.Join(authorUsers, ", ")),
				Severity:    severity.Medium,
				Confidence:  severity.Certain,
				Tags:        []string{"wordpress", "user-enumeration"},
			},
			Metadata: map[string]any{
				"users":  authorUsers,
				"method": "author-archive",
			},
		})
	}

	// 2. REST API user enumeration: /wp-json/wp/v2/users
	restUsers := m.probeRESTUsers(ctx, httpClient)
	if len(restUsers) > 0 {
		results = append(results, &output.ResultEvent{
			URL:              baseURL + "/wp-json/wp/v2/users",
			Matched:          baseURL + "/wp-json/wp/v2/users",
			ExtractedResults: restUsers,
			Info: output.Info{
				Name:        "WordPress User Enumeration via REST API",
				Description: fmt.Sprintf("Discovered %d WordPress username(s) via unauthenticated REST API access: %s", len(restUsers), strings.Join(restUsers, ", ")),
				Severity:    severity.Medium,
				Confidence:  severity.Certain,
				Tags:        []string{"wordpress", "user-enumeration", "rest-api"},
			},
			Metadata: map[string]any{
				"users":  restUsers,
				"method": "rest-api",
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

	// Check for redirect to /author/<username>/
	status := resp.Response().StatusCode
	if status == 301 || status == 302 {
		location := resp.Response().Header.Get("Location")
		if idx := strings.Index(location, "/author/"); idx >= 0 {
			slug := location[idx+len("/author/"):]
			slug = strings.TrimSuffix(slug, "/")
			slug = strings.TrimSpace(slug)
			if slug != "" && !strings.Contains(slug, "/") {
				return slug
			}
		}
	}

	return ""
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
