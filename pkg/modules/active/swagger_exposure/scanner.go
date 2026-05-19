package swagger_exposure

import (
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modkit/specutil"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
)

// probePaths are common Swagger/OpenAPI/Redoc UI and spec routes. The first
// positive hit per host is enough to report the exposure, so this list favours
// the most prevalent paths rather than exhaustiveness (api-spec-ingest owns the
// wide spec-discovery surface).
var probePaths = []string{
	// Interactive documentation UIs
	"swagger-ui.html",
	"swagger-ui/",
	"swagger/index.html",
	"swagger/",
	"swagger",
	"api/swagger-ui.html",
	"api/swagger/index.html",
	"api/docs",
	"docs",
	"redoc",
	"redoc/",
	"api-docs",
	// Machine-readable specifications
	"openapi.json",
	"swagger.json",
	"openapi.yaml",
	"swagger.yaml",
	"v2/api-docs",
	"v3/api-docs",
	"api/openapi.json",
	"api/swagger.json",
	"api-docs/swagger.json",
	"swagger-resources",
	".well-known/openapi.json",
}

// uiMarkers identify a rendered API documentation UI page. Kept specific to
// avoid false positives on generic HTML.
var uiMarkers = []string{
	"swagger-ui",
	"swaggeruibundle",
	"redoc",
	"rapidoc",
	"stoplight-elements",
	"swagger ui",
}

// Module is the active Swagger/OpenAPI exposure detection scanner.
type Module struct {
	modkit.BaseActiveModule
	hostDS dedup.Lazy[dedup.DiskSet] // per-host dedup: probe & report once per host
}

// New creates a new Swagger Exposure module.
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
		hostDS: dedup.LazyDiskSet("swagger_exposure_host"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// CanProcess requires a request with a valid URL.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	return ctx != nil && ctx.Request() != nil
}

// IncludesBaseCanProcess returns false because we override CanProcess entirely.
func (m *Module) IncludesBaseCanProcess() bool { return false }

func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	if utils.IsMediaAndJSURL(urlx.Path) {
		return nil, nil
	}

	// Host-level dedup: only probe once per host (IsSeen is test-and-set).
	hostKey := urlx.Scheme + "|" + urlx.Host
	hostDS := m.hostDS.Get(scanCtx.DedupMgr())
	if hostDS != nil && hostDS.IsSeen(hostKey) {
		return nil, nil
	}

	// Build a base GET request from the observed request.
	var rawHTTP []byte
	if ctx.Request().Method() != "GET" {
		rawHTTP, err = httpmsg.SetMethod(ctx.Request().Raw(), "GET")
		if err != nil {
			return nil, nil
		}
	} else {
		rawHTTP = ctx.Request().Raw()
	}

	baseURL := urlx.Scheme + "://" + urlx.Host

	for _, path := range probePaths {
		probePath := "/" + path

		modifiedRaw, err := httpmsg.SetPath(rawHTTP, probePath)
		if err != nil {
			continue
		}

		fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
		if err != nil {
			continue
		}
		fuzzedReq = fuzzedReq.WithService(ctx.Service())

		resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
		if err != nil {
			continue
		}

		statusCode := resp.Response().StatusCode
		body := resp.Body().Bytes()
		resp.Close()

		if statusCode != 200 || len(body) < 32 {
			continue
		}

		var kind string
		switch {
		case specutil.DetectSpecType(body) != specutil.Unknown:
			kind = "OpenAPI/Swagger specification document"
		case looksLikeSwaggerUI(body):
			kind = "interactive API documentation UI"
		default:
			continue
		}

		// First confirmed exposure is sufficient — stop probing this host.
		hit := baseURL + probePath
		return []*output.ResultEvent{
			{
				URL:     hit,
				Matched: hit,
				Info: output.Info{
					Name: ModuleName,
					Description: "Publicly accessible " + kind + " exposed at " + probePath +
						". This discloses the API attack surface (endpoints, parameters, " +
						"authentication scheme) to unauthenticated users.",
				},
			},
		}, nil
	}

	return nil, nil
}

// looksLikeSwaggerUI reports whether the response body looks like a rendered
// Swagger/Redoc/RapiDoc documentation page.
func looksLikeSwaggerUI(body []byte) bool {
	n := len(body)
	if n > 8192 {
		n = 8192
	}
	s := strings.ToLower(string(body[:n]))
	for _, marker := range uiMarkers {
		if strings.Contains(s, marker) {
			return true
		}
	}
	return false
}
