package dom_xss_taint

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/deparos/jstangle"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

// scanTimeout bounds a single jstangle subprocess invocation from this passive
// module (the scanner's own MaxScanTimeout is far longer and meant for large
// bundle deobfuscation, not passive per-response analysis).
const scanTimeout = 20 * time.Second

var (
	scriptBlockRe = regexp.MustCompile(`(?is)<script[^>]*>(.*?)</script>`)

	// Cheap presence gates: only spawn the (subprocess) taint analyzer when the
	// JS plausibly contains both a source and a sink. The analyzer then decides
	// whether they are actually connected.
	gateSourceRe = regexp.MustCompile(`(?i)(location\.(hash|search|href|pathname)|document\.(URL|documentURI|baseURI|cookie|referrer)|window\.name|(local|session)Storage|MessageEvent|addEventListener\s*\(\s*['"]message|\bpostMessage\b|\b[a-z_$][\w$]*\.data\b)`)
	gateSinkRe   = regexp.MustCompile(`(?i)(innerHTML|outerHTML|srcdoc|createContextualFragment|DOMParser|dangerouslySetInnerHTML|\.(append|prepend|before|after|replaceWith)\s*\(|\beval\b|\bsetTimeout\b|\bsetInterval\b|document\.write|insertAdjacentHTML|setAttribute\s*\(\s*['"]src|\.src\s*=|location\.(href|assign|replace)|\bFunction\b)`)
)

type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]

	scannerOnce sync.Once
	service     *jstangle.Service
}

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
		ds: dedup.LazyDiskSet("passive_dom_xss_taint"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// getScanner lazily resolves the process-wide jstangle service. A construction
// failure is non-fatal — the module simply produces no findings.
func (m *Module) getScanner() *jstangle.Service {
	m.scannerOnce.Do(func() {
		if service, err := jstangle.DefaultService(); err == nil {
			m.service = service
		}
	})
	return m.service
}

func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	return m.ScanPerRequestContext(context.Background(), ctx, scanCtx)
}

func (m *Module) ScanPerHost(_ *httpmsg.HttpRequestResponse, _ *modkit.ScanContext) ([]*output.ResultEvent, error) {
	return nil, nil
}

func (m *Module) ScanPerHostContext(_ context.Context, _ *httpmsg.HttpRequestResponse, _ *modkit.ScanContext) ([]*output.ResultEvent, error) {
	return nil, nil
}

// ScanPerRequestContext preserves executor cancellation while the shared
// service queues or analyzes a response.
func (m *Module) ScanPerRequestContext(runCtx context.Context, ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}
	if ctx.Response() == nil || ctx.Response().BodyToString() == "" {
		return nil, nil
	}

	var diskSet *dedup.DiskSet
	if scanCtx != nil {
		diskSet = m.ds.Get(scanCtx.DedupMgr())
	}
	hash := utils.Sha1(fmt.Sprintf("%s%s", urlx.Host, urlx.Path))
	if diskSet != nil && diskSet.IsSeen(hash) {
		return nil, nil
	}

	js := extractJS(ctx, urlx)
	if js == "" || !gateSourceRe.MatchString(js) || !gateSinkRe.MatchString(js) {
		return nil, nil
	}

	scanner := m.getScanner()
	if scanner == nil {
		return nil, nil
	}

	cctx, cancel := context.WithTimeout(runCtx, scanTimeout)
	defer cancel()

	res, err := scanner.ScanWithOptions(cctx, []byte(js), jstangle.ScanOptions{
		Profile: jstangle.ProfileDOMSecurity, SourceURL: urlx.String(),
	})
	if err != nil || res == nil || !res.HasDomFlows() {
		return nil, nil
	}

	var results []*output.ResultEvent
	seen := make(map[string]struct{}, len(res.DomFlows))
	for _, f := range res.DomFlows {
		// Protocol v1 and early v2 helpers omitted flow_type for DOM-XSS. Dynamic
		// execution and attacker-controlled script URLs are also executable DOM
		// injection. Redirect/network/exfiltration/prototype flows belong to their
		// own consumers and must not be mislabeled here.
		if f.FlowType != "" && f.FlowType != "domXss" &&
			f.FlowType != "dynamicExecution" && f.FlowType != "scriptUrlInjection" {
			continue
		}
		key := f.Source + "|" + f.Sink + "|" + f.Snippet
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}

		desc := fmt.Sprintf(
			"DOM XSS: source %s flows into sink %s (line %d).\n```js\n%s\n```",
			f.Source, f.Sink, f.Line, f.Snippet,
		)
		results = append(results, &output.ResultEvent{
			ModuleID:      ModuleID,
			RecordKind:    output.RecordKindCandidate,
			EvidenceGrade: output.EvidenceGradeCandidate,
			DedupKey:      fmt.Sprintf("dom-xss-flow|%s|%s", urlx.Host, urlx.Path),
			URL:           urlx.String(),
			Host:          urlx.Host,
			Matched:       urlx.String(),
			Request:       string(ctx.Request().Raw()),
			Response:      string(ctx.Response().Raw()),
			Info: output.Info{
				Name:        "DOM XSS Taint-Flow Candidate",
				Description: desc + "\nThe taint engine connected source to sink; browser execution and payload viability were not tested.",
				Severity:    ModuleSeverity,
				Confidence:  severity.Firm,
				Tags:        ModuleTags,
			},
			Metadata: map[string]any{"flow_engine": "jstangle", "connected_flow": true, "browser_execution_tested": false},
		})
	}

	return results, nil
}

// extractJS returns the JavaScript worth analyzing from the response: the body
// itself for a JS response, or the concatenated inline <script> contents for an
// HTML response. Returns "" for anything else (e.g. images, CSS, JSON).
func extractJS(ctx *httpmsg.HttpRequestResponse, urlx *urlutil.URL) string {
	resp := ctx.Response()
	body := resp.BodyToString()
	if body == "" {
		return ""
	}

	ct := strings.ToLower(resp.Header("Content-Type"))
	if strings.Contains(ct, "javascript") || strings.Contains(ct, "ecmascript") {
		return body
	}

	path := strings.ToLower(urlx.Path)
	if strings.HasSuffix(path, ".js") || strings.HasSuffix(path, ".mjs") {
		return body
	}

	if strings.Contains(ct, "html") || ct == "" {
		var sb strings.Builder
		for _, m := range scriptBlockRe.FindAllStringSubmatch(body, -1) {
			if len(m) > 1 && strings.TrimSpace(m[1]) != "" {
				sb.WriteString(m[1])
				sb.WriteString("\n;\n")
			}
		}
		return sb.String()
	}

	return ""
}
