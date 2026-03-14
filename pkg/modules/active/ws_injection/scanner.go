package ws_injection

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/pkg/errors"
)

// wsParamNames contains parameter names commonly associated with WebSocket message processing.
var wsParamNames = map[string]bool{
	"message":   true,
	"msg":       true,
	"data":      true,
	"text":      true,
	"chat":      true,
	"payload":   true,
	"content":   true,
	"body":      true,
	"input":     true,
	"cmd":       true,
	"command":   true,
	"query":     true,
	"ws":        true,
	"websocket": true,
}

type injectionTest struct {
	payload  string
	category string
	// patterns to look for in the response body (case-insensitive)
	patterns []string
}

var injectionTests = []injectionTest{
	// XSS payloads - check for unencoded reflection
	{
		payload:  `<img src=x onerror=alert(1)>`,
		category: "XSS",
		patterns: []string{`<img src=x onerror=alert(1)>`},
	},
	{
		payload:  `"><script>alert(1)</script>`,
		category: "XSS",
		patterns: []string{`"><script>alert(1)</script>`},
	},
	// SQLi payloads - check for SQL error messages
	{
		payload:  `' OR '1'='1`,
		category: "SQL Injection",
		patterns: []string{
			"syntax error",
			"mysql",
			"ora-",
			"postgresql",
			"sqlite",
			"unclosed quotation mark",
			"quoted string not properly terminated",
			"sql syntax",
			"microsoft sql",
		},
	},
	{
		payload:  `1; DROP TABLE--`,
		category: "SQL Injection",
		patterns: []string{
			"syntax error",
			"mysql",
			"ora-",
			"postgresql",
			"sqlite",
			"unclosed quotation mark",
			"sql syntax",
			"microsoft sql",
		},
	},
	{
		payload:  `' UNION SELECT NULL--`,
		category: "SQL Injection",
		patterns: []string{
			"syntax error",
			"mysql",
			"ora-",
			"postgresql",
			"sqlite",
			"union select",
			"sql syntax",
			"microsoft sql",
		},
	},
	// Command injection payloads
	{
		payload:  `; id`,
		category: "Command Injection",
		patterns: []string{"uid=", "gid="},
	},
	{
		payload:  `| cat /etc/passwd`,
		category: "Command Injection",
		patterns: []string{"root:", "/bin/bash", "/bin/sh"},
	},
	{
		payload:  "`id`",
		category: "Command Injection",
		patterns: []string{"uid=", "gid="},
	},
	// Template injection payloads
	{
		payload:  `{{7*7}}`,
		category: "Template Injection",
		patterns: []string{"49"},
	},
	{
		payload:  `${7*7}`,
		category: "Template Injection",
		patterns: []string{"49"},
	},
}

// Module implements an active scanner for WebSocket injection vulnerabilities.
type Module struct {
	modkit.BaseActiveModule
	ds  dedup.Lazy[dedup.DiskSet]
	rhm dedup.Lazy[dedup.RequestHashManager]
}

// New creates a new WebSocket Injection scanner module.
func New() *Module {
	m := &Module{
		BaseActiveModule: modkit.NewBaseActiveModule(
			ModuleID, ModuleName, ModuleDesc, ModuleShort, ModuleConfirmation,
			ModuleSeverity, ModuleConfidence,
			modkit.ScanScopeInsertionPoint,
			modkit.AllParamTypes,
		),
		ds:  dedup.LazyDiskSet("ws_injection"),
		rhm: dedup.LazyDefaultRHM("ws_injection"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerInsertionPoint tests each insertion point for injection vulnerabilities
// in parameters likely forwarded to WebSocket message processing.
func (m *Module) ScanPerInsertionPoint(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	// Only test parameters with WS-related names.
	paramName := strings.ToLower(ip.Name())
	if !wsParamNames[paramName] {
		return nil, nil
	}

	// Dedup by insertion point.
	rhm := m.rhm.Get(scanCtx.DedupMgr())
	if rhm != nil {
		paramType := fmt.Sprintf("%d", ip.Type())
		if !rhm.ShouldCheckInsertionPoint(urlx, ctx.Request(), ip.Name(), ip.BaseValue(), paramType) {
			return nil, nil
		}
	}

	var results []*output.ResultEvent

	for _, test := range injectionTests {
		fuzzedRaw := ip.BuildRequest([]byte(test.payload))
		fuzzedReq, parseErr := httpmsg.ParseRawRequest(string(fuzzedRaw))
		if parseErr != nil {
			continue
		}
		fuzzedReq = fuzzedReq.WithService(ctx.Service())

		resp, _, execErr := httpClient.Execute(fuzzedReq, http.Options{})
		if execErr != nil {
			if errors.Is(execErr, hosterrors.ErrUnresponsiveHost) {
				return nil, execErr
			}
			continue
		}

		body := resp.FullResponse().String()
		resp.Close()

		bodyLower := strings.ToLower(body)
		for _, pattern := range test.patterns {
			if strings.Contains(bodyLower, strings.ToLower(pattern)) {
				results = append(results, &output.ResultEvent{
					URL:     urlx.String(),
					Matched: urlx.String(),
					ExtractedResults: []string{
						fmt.Sprintf("Category: WebSocket %s", test.category),
						fmt.Sprintf("Parameter: %s", ip.Name()),
						fmt.Sprintf("Payload: %s", test.payload),
						fmt.Sprintf("Matched pattern: %s", pattern),
					},
					MatcherStatus: true,
				})
				// One match per test is enough; move to next test.
				break
			}
		}
	}

	return results, nil
}
