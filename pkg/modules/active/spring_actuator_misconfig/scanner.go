package spring_actuator_misconfig

import (
	"crypto/md5"
	"fmt"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
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
	contentTypeRegex *regexp.Regexp
	ds               dedup.Lazy[dedup.DiskSet]
	testCases        []*testCase
}

// https://github.com/projectdiscovery/nuclei-templates/blob/main/http/misconfiguration/springboot/springboot-env.yaml
func New() *Module {
	contentTypeRegex := regexp.MustCompile(`(?mi)(application/vnd\.spring-boot\.actuator\.v[0-9]\+json|application/json|application/vnd\.spring-boot.actuator)`)
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
		contentTypeRegex: contentTypeRegex,
		ds:               dedup.LazyDiskSet("spring_actuator_misconfig"),
		testCases:        initTestCases(),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest scans the request for Spring Actuator misconfigurations.
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

	paths := utils.SplitPathRecursive(urlx.Path)
	if len(paths) == 0 {
		return results, nil
	}

	diskSet := m.ds.Get(scanCtx.DedupMgr())

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

				// Use httpmsg to modify the request path and method
				modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
				if err != nil {
					continue
				}
				modifiedRaw, err = httpmsg.SetPath(modifiedRaw, newPath)
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

	if resp.Response() == nil || resp.Response().StatusCode != 200 {
		return "", false
	}

	contentType := resp.Response().Header.Get("Content-Type")
	if !m.contentTypeRegex.MatchString(contentType) {
		return "", false
	}

	return resp.Body().String(), testCase.Matches(resp.Body().String())
}

func initTestCases() []*testCase {
	return []*testCase{
		{
			Payloads:     []string{"env", "..;/env", "..;xxx/env", "actuator/env", "..;/actuator/env", "..;xxx/actuator/env"},
			matchstrings: []string{"server.port", "local.server.port"},
		},
		{
			Payloads:     []string{"info", "..;/info", "..;xxx/info", "actuator/info", "..;/actuator/info", "..;xxx/actuator/info"},
			matchstrings: []string{`"build"`, `"artifact"`},
		},
		{
			Payloads:     []string{"health", "..;/health", "actuator/health", "..;/actuator/health"},
			matchstrings: []string{`"status"`, `"UP"`, `"DOWN"`},
		},
		{
			Payloads:     []string{"metrics", "..;/metrics", "actuator/metrics", "..;/actuator/metrics"},
			matchstrings: []string{`"names"`, `"jvm.memory"`, `"process.cpu"`},
		},
		{
			Payloads:     []string{"loggers", "..;/loggers", "actuator/loggers", "..;/actuator/loggers"},
			matchstrings: []string{`"levels"`, `"loggers"`, `"configuredLevel"`},
		},
		{
			Payloads:     []string{"beans", "..;/beans", "actuator/beans", "..;/actuator/beans"},
			matchstrings: []string{`"beans"`, `"scope"`, `"dependencies"`},
		},
		{
			Payloads:     []string{"mappings", "..;/mappings", "actuator/mappings", "..;/actuator/mappings"},
			matchstrings: []string{`"dispatcherServlets"`, `"requestMappingConditions"`, `"handler"`},
		},
	}
}
