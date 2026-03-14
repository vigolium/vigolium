package verbose_error_stacktrace

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
	"github.com/pkg/errors"
)

// stackTracePattern defines a detection rule for a technology-specific stack trace.
type stackTracePattern struct {
	technology string
	severity   severity.Severity
	confidence severity.Confidence
	pattern    *regexp.Regexp
}

var stackTracePatterns = []stackTracePattern{
	// Go stack traces: goroutine N [running]:
	// main.handler(...)
	//     /app/server.go:42 +0x1a3
	{
		technology: "Go",
		severity:   severity.Medium,
		confidence: severity.Certain,
		pattern:    regexp.MustCompile(`goroutine \d+ \[.*\]:\n.*\n\t(/[^\s]+\.go:\d+)`),
	},
	// Java stack traces: at com.example.Class.method(File.java:123)
	{
		technology: "Java",
		severity:   severity.Medium,
		confidence: severity.Certain,
		pattern:    regexp.MustCompile(`(?:at\s+[\w.$]+\([\w]+\.java:\d+\)\s*\n){2,}`),
	},
	// Python stack traces: File "/app/views.py", line 42, in handler
	{
		technology: "Python",
		severity:   severity.Medium,
		confidence: severity.Certain,
		pattern:    regexp.MustCompile(`Traceback \(most recent call last\):[\s\S]*?File "([^"]+)", line \d+`),
	},
	// Node.js stack traces: at Object.<anonymous> (/app/server.js:15:3)
	{
		technology: "Node.js",
		severity:   severity.Medium,
		confidence: severity.Firm,
		pattern:    regexp.MustCompile(`(?:at\s+[\w.<>\[\] ]+\s+\((?:/[^\s)]+\.(?:js|ts|mjs|cjs):\d+:\d+)\)\s*\n){2,}`),
	},
	// .NET/C# stack traces: at Namespace.Class.Method() in /app/File.cs:line 42
	{
		technology: ".NET",
		severity:   severity.Medium,
		confidence: severity.Certain,
		pattern:    regexp.MustCompile(`(?:at\s+[\w.]+\(.*?\)\s+in\s+[A-Za-z]?:?[/\\][\w./\\]+:\s*line\s+\d+\s*\n){2,}`),
	},
	// Ruby stack traces: /app/controller.rb:42:in `index'
	{
		technology: "Ruby",
		severity:   severity.Medium,
		confidence: severity.Certain,
		pattern:    regexp.MustCompile(`(?:/[\w./]+\.rb:\d+:in ` + "`" + `[\w?!]+'\s*\n){2,}`),
	},
	// PHP stack traces: #0 /app/index.php(42): Class->method()
	{
		technology: "PHP",
		severity:   severity.Medium,
		confidence: severity.Certain,
		pattern:    regexp.MustCompile(`(?:#\d+\s+/[\w./]+\.php\(\d+\):\s+[\w\\]+->[\w]+\(\)\s*\n){2,}`),
	},
}

// Module implements the Verbose Error Stack Trace passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Verbose Error Stack Trace module.
func New() *Module {
	m := &Module{
		BasePassiveModule: modkit.NewBasePassiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.PassiveScanScopeResponse,
		),
		ds: dedup.LazyDiskSet("passive_verbose_error_stacktrace"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest analyzes response body for verbose stack traces.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	if utils.IsMediaAndJSURL(urlx.Path) {
		return nil, nil
	}

	if ctx.Response() == nil {
		return nil, nil
	}

	// Skip binary content
	ct := strings.ToLower(ctx.Response().Header("Content-Type"))
	if strings.Contains(ct, "image/") || strings.Contains(ct, "audio/") ||
		strings.Contains(ct, "video/") || strings.Contains(ct, "octet-stream") {
		return nil, nil
	}

	// Dedup by host+path
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	dedupKey := utils.Sha1(fmt.Sprintf("%s%s", urlx.Host, urlx.Path))
	if diskSet != nil && diskSet.IsSeen(dedupKey) {
		return nil, nil
	}

	body := ctx.Response().BodyToString()
	if body == "" {
		return nil, nil
	}

	var results []*output.ResultEvent

	for _, stp := range stackTracePatterns {
		match := stp.pattern.FindString(body)
		if match == "" {
			continue
		}

		results = append(results, &output.ResultEvent{
			ModuleID: ModuleID,
			Host:     urlx.Host,
			URL:      urlx.String(),
			Matched:  urlx.String(),
			Request:  string(ctx.Request().Raw()),
			ExtractedResults: []string{
				fmt.Sprintf("Technology: %s", stp.technology),
				fmt.Sprintf("Stack trace: %s", truncate(match, 200)),
			},
			Info: output.Info{
				Name:        fmt.Sprintf("%s Stack Trace Exposed", stp.technology),
				Description: fmt.Sprintf("Verbose %s stack trace with file paths detected at %s", stp.technology, urlx.String()),
				Severity:    stp.severity,
				Confidence:  stp.confidence,
				Tags:        []string{"passive", "stacktrace", strings.ToLower(stp.technology)},
			},
		})
	}

	return results, nil
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
