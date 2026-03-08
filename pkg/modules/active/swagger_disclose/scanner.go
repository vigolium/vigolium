package swagger_disclose

import (
	"crypto/md5"
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
	"github.com/pkg/errors"
	urlutil "github.com/projectdiscovery/utils/url"
)

type testCase struct {
	Payloads     []string
	matchstrings []string
}

func (c *testCase) Matches(content string) bool {
	for _, match := range c.matchstrings {
		if strings.Contains(content, match) {
			return true
		}
	}
	return false
}

type Module struct {
	modkit.BaseActiveModule
	ds        dedup.Lazy[dedup.DiskSet]
	testCases []*testCase
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
		ds:        dedup.LazyDiskSet("swagger_disclose"),
		testCases: initTestCases(),
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

	if utils.IsMediaAndJSURL(urlx.Path) {
		return results, nil
	}

	// Start with raw request, convert to GET if needed
	var rawHttp []byte
	if ctx.Request().Method() != "GET" {
		rawHttp = infra.SwapToGetMethodRequest(ctx.Request().Raw())
	} else {
		rawHttp = ctx.Request().Raw()
	}

	diskSet := m.ds.Get(scanCtx.DedupMgr())

	paths := utils.SplitPathRecursive(urlx.Path)
	if len(paths) == 0 {
		return results, nil
	}
	for _, path := range paths {
		if path == "/" || path == "" {
			continue
		}
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		path = strings.TrimSuffix(path, "/")

		checksum := getChecksum(urlx, path)
		if diskSet != nil && diskSet.IsSeen(checksum) {
			continue
		}

		for _, testCase := range m.testCases {
			for _, payload := range testCase.Payloads {
				// Build the new path with payload
				newPath := path + "/" + payload

				// Use httpmsg to modify the request path
				modifiedRaw, err := httpmsg.SetPath(rawHttp, newPath)
				if err != nil {
					continue
				}

				// Parse the modified raw request
				fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
				if err != nil {
					continue
				}

				// Copy HttpService from original request
				fuzzedReq = fuzzedReq.WithService(ctx.Service())

				content, success := m.check(testCase, fuzzedReq, httpClient)
				if success {
					results = append(results, &output.ResultEvent{
						URL:              urlx.Scheme + "://" + urlx.Host + newPath,
						Request:          string(modifiedRaw),
						Response:         content,
						FuzzingParameter: path,
					})
				}
			}
		}
	}

	return results, nil
}

func getChecksum(urlx *urlutil.URL, path string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(urlx.Scheme+"|"+urlx.Host+"|"+path)))
}

func (m *Module) check(testCase *testCase, req *httpmsg.HttpRequestResponse, httpClient *http.Requester) (string, bool) {
	resp, _, err := httpClient.Execute(req, http.Options{})
	if err != nil {
		return "", false
	}
	defer resp.Close()

	if resp.Response().StatusCode != 200 {
		return "", false
	}

	return resp.Body().String(), testCase.Matches(resp.Body().String())
}

func initTestCases() []*testCase {
	return []*testCase{
		{
			Payloads: []string{
				"swagger-ui/swagger-ui.js",
				"swagger/swagger-ui.js",
				"swagger-ui.js",
				"swagger/ui/swagger-ui.js",
				"swagger/ui/index",
				"swagger/index.html",
				"swagger-ui.html",
				"swagger/swagger-ui.html",
				"api/swagger-ui.html",
				"api-docs/swagger.json",
				"api-docs/swagger.yaml",
				"api_docs",
				"swagger.json",
				"swagger.yaml",
				"swagger/v1/swagger.json",
				"swagger/v1/swagger.yaml",
				"api/index.html",
				"api/doc",
				"api/docs/",
				"api/swagger.json",
				"api/swagger.yaml",
				"api/swagger.yml",
				"api/swagger/index.html",
				"api/swagger/swagger-ui.html",
				"api/api-docs/swagger.json",
				"api/api-docs/swagger.yaml",
				"api/swagger-ui/swagger.json",
				"api/swagger-ui/swagger.yaml",
				"api/apidocs/swagger.json",
				"api/apidocs/swagger.yaml",
				"api/swagger-ui/api-docs",
				"api/doc.json",
				"api/api-docs",
				"api/apidocs",
				"api/swagger",
				"api/swagger/static/index.html",
				"api/swagger-resources",
				"api/swagger-resources/restservices/v2/api-docs",
				"api/__swagger__/",
				"api/_swagger_/",
				"api/spec/swagger.json",
				"api/spec/swagger.yaml",
				"api/swagger/ui/index",
				"__swagger__/",
				"_swagger_/",
				"api/v1/swagger-ui/swagger.json",
				"api/v1/swagger-ui/swagger.yaml",
				"swagger-resources/restservices/v2/api-docs",
				"api/swagger_doc.json",
				"docu",
				"docs",
				"swagger",
				"apidocs",
				"apidoc",
				"api-doc",
				"doc/",
				"swagger-ui/springfox.js",
				"swagger-ui/swagger-ui-standalone-preset.js",
				"swagger-ui/swagger-ui/swagger-ui-bundle.js",
				"webjars/swagger-ui/swagger-ui-bundle.js",
				"webjars/swagger-ui/index.html",
			},
			matchstrings: []string{
				"swagger:",
				"Swagger 2.0",
				"\"swagger\":",
				"Swagger UI",
				"loadSwaggerUI",
				"**token**:",
				"id=\"swagger-ui",
			},
		},
	}
}
