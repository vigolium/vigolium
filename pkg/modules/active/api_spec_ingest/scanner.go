package api_spec_ingest

import (
	"crypto/sha256"
	"fmt"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modkit/specutil"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
	"github.com/pkg/errors"
)

// Probe paths for API specification files.
var probePaths = []string{
	// OpenAPI / Swagger JSON
	"openapi.json",
	"swagger.json",
	"api-docs",
	"api/api-docs",
	"api/swagger.json",
	"api/doc.json",
	"v2/api-docs",
	"v3/api-docs",
	".well-known/openapi.json",
	"swagger/v1/swagger.json",
	"api/swagger-ui/swagger.json",
	"api/apidocs/swagger.json",
	"api-docs/swagger.json",
	"api/spec/swagger.json",
	"api/v1/swagger-ui/swagger.json",
	"swagger_doc.json",
	// OpenAPI / Swagger YAML
	"openapi.yaml",
	"openapi.yml",
	"swagger.yaml",
	"api/swagger.yaml",
	"api/swagger.yml",
	"api-docs/swagger.yaml",
	"api/apidocs/swagger.yaml",
	"api/swagger-ui/swagger.yaml",
	"api/spec/swagger.yaml",
	"swagger/v1/swagger.yaml",
	"api/v1/swagger-ui/swagger.yaml",
	// Postman Collections
	"postman_collection.json",
	"api/collection.json",
}

// Module is the active API spec ingest scanner.
type Module struct {
	modkit.BaseActiveModule
	hostDS dedup.Lazy[dedup.DiskSet] // per-host dedup (avoid re-probing)
	specDS dedup.Lazy[dedup.DiskSet] // per-content dedup (avoid re-parsing)
}

// New creates a new API Spec Ingest module.
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
		hostDS: dedup.LazyDiskSet("api_spec_ingest_host"),
		specDS: dedup.LazyDiskSet("api_spec_ingest_spec"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// CanProcess requires a response to be attached and a valid URL.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Request() == nil {
		return false
	}
	return true
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

	// Host-level dedup: only probe once per host
	hostKey := urlx.Scheme + "|" + urlx.Host
	hostDS := m.hostDS.Get(scanCtx.DedupMgr())
	if hostDS != nil && hostDS.IsSeen(hostKey) {
		return nil, nil
	}

	specDS := m.specDS.Get(scanCtx.DedupMgr())

	// Build base GET request
	var rawHttp []byte
	if ctx.Request().Method() != "GET" {
		rawHttp, err = httpmsg.SetMethod(ctx.Request().Raw(), "GET")
		if err != nil {
			return nil, nil
		}
	} else {
		rawHttp = ctx.Request().Raw()
	}

	baseURL := urlx.Scheme + "://" + urlx.Host
	var results []*output.ResultEvent

	for _, path := range probePaths {
		probePath := "/" + path

		modifiedRaw, err := httpmsg.SetPath(rawHttp, probePath)
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

		if statusCode != 200 || len(body) < 50 {
			continue
		}

		// Check if it's a recognizable spec
		st := specutil.DetectSpecType(body)
		if st == specutil.Unknown {
			continue
		}

		// Content dedup: skip if we've already parsed this exact spec
		contentHash := fmt.Sprintf("%x", sha256.Sum256(body))
		if specDS != nil && specDS.IsSeen(contentHash) {
			continue
		}

		// Parse endpoints using pre-detected type
		endpoints, parseErr := specutil.ParseSpecTyped(st, body, baseURL, ctx.Service())
		if parseErr != nil || len(endpoints) == 0 {
			continue
		}

		// Feed endpoints into the scanning pipeline
		feeder := scanCtx.Feeder()
		count := 0
		if feeder != nil {
			for _, rr := range endpoints {
				if feeder.Feed(rr) {
					count++
				}
			}
		}
		if parseErr != nil {
			continue
		}

		if count > 0 {
			results = append(results, &output.ResultEvent{
				URL:     baseURL + probePath,
				Matched: baseURL + probePath,
				Info: output.Info{
					Name:        ModuleName,
					Description: fmt.Sprintf("Discovered API spec at %s, ingested %d endpoints", probePath, count),
				},
			})
		}
	}

	return results, nil
}
