package python_debug_detect

import (
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

type debugPattern struct {
	name  string
	check func(body string) bool
	sev   severity.Severity
	desc  string
	tags  []string
}

var debugPatterns = []debugPattern{
	{
		name: "Werkzeug Debugger",
		check: func(body string) bool {
			return strings.Contains(body, "Werkzeug Debugger")
		},
		sev:  severity.Critical,
		desc: "Werkzeug Debugger is exposed in the response. This interactive debugger may allow remote code execution via the debug console",
		tags: []string{"python", "werkzeug", "debug", "rce"},
	},
	{
		name: "Python Traceback",
		check: func(body string) bool {
			return strings.Contains(body, "Traceback (most recent call last):")
		},
		sev:  severity.High,
		desc: "A full Python traceback is exposed in the response, potentially leaking source code paths, secrets, and internal application structure",
		tags: []string{"python", "traceback", "information-disclosure"},
	},
	{
		name: "Django Debug Page",
		check: func(body string) bool {
			return strings.Contains(body, "Request Method:") &&
				strings.Contains(body, "Request URL:") &&
				strings.Contains(body, "Django Version:")
		},
		sev:  severity.High,
		desc: "Django debug page (DEBUG=True) is exposed in production, leaking settings, environment variables, installed apps, and full stack trace",
		tags: []string{"python", "django", "debug", "information-disclosure"},
	},
	{
		name: "Python File Path Disclosure",
		check: func(body string) bool {
			return strings.Contains(body, `File "/`) || strings.Contains(body, `File "\\`)
		},
		sev:  severity.Medium,
		desc: "Python file paths with line numbers are disclosed in the response, revealing the application's filesystem layout",
		tags: []string{"python", "path-disclosure", "information-disclosure"},
	},
	{
		name: "Python Dependency Path Disclosure",
		check: func(body string) bool {
			return strings.Contains(body, "site-packages/")
		},
		sev:  severity.Medium,
		desc: "Python dependency paths (site-packages) are disclosed in the response, revealing installed packages and their versions",
		tags: []string{"python", "path-disclosure", "information-disclosure"},
	},
}

// Module implements the Python Debug Detect passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Python Debug Detect module.
func New() *Module {
	m := &Module{
		BasePassiveModule: modkit.NewBasePassiveModule(
			ModuleID, ModuleName, ModuleDesc, ModuleShort,
			ModuleConfirmation, ModuleSeverity, ModuleConfidence,
			modkit.ScanScopeRequest, modkit.PassiveScanScopeResponse,
		),
		ds: dedup.LazyDiskSet("python_debug_detect"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if !ctx.HasResponse() {
		return nil, nil
	}

	ct := strings.ToLower(ctx.Response().Header("Content-Type"))
	if !strings.Contains(ct, "text/html") && !strings.Contains(ct, "application/json") && !strings.Contains(ct, "text/plain") {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	body := ctx.Response().BodyToString()
	if len(body) == 0 {
		return nil, nil
	}

	host := urlx.Host
	diskSet := m.ds.Get(scanCtx.DedupMgr())

	var results []*output.ResultEvent

	for _, dp := range debugPatterns {
		if !dp.check(body) {
			continue
		}

		// Dedup by host + detection type
		dedupKey := host + "::" + dp.name
		if diskSet != nil && diskSet.IsSeen(dedupKey) {
			continue
		}

		results = append(results, &output.ResultEvent{
			ModuleID:         ModuleID,
			Host:             host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			ExtractedResults: []string{dp.name},
			Info: output.Info{
				Name:        "Python Debug: " + dp.name,
				Description: dp.desc,
				Severity:    dp.sev,
				Confidence:  severity.Firm,
				Tags:        dp.tags,
				Reference:   []string{"https://owasp.org/www-project-web-security-testing-guide/"},
			},
		})
	}

	return results, nil
}
