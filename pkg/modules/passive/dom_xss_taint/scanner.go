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
	"github.com/vigolium/vigolium/pkg/deparos/jsscan"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
)

// scanTimeout bounds a single jsscan subprocess invocation from this passive
// module (the scanner's own MaxScanTimeout is far longer and meant for large
// bundle deobfuscation, not passive per-response analysis).
const scanTimeout = 20 * time.Second

var (
	scriptBlockRe = regexp.MustCompile(`(?is)<script[^>]*>(.*?)</script>`)

	// Cheap presence gates: only spawn the (subprocess) taint analyzer when the
	// JS plausibly contains both a source and a sink. The analyzer then decides
	// whether they are actually connected.
	gateSourceRe = regexp.MustCompile(`(?i)(location\.(hash|search|href|pathname)|document\.(URL|documentURI|baseURI|cookie|referrer)|window\.name|(local|session)Storage)`)
	gateSinkRe   = regexp.MustCompile(`(?i)(innerHTML|outerHTML|\beval\b|\bsetTimeout\b|\bsetInterval\b|document\.write|insertAdjacentHTML|\.src\s*=|location\.(href|assign|replace)|\bFunction\b)`)
)

type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]

	scannerOnce sync.Once
	scanner     *jsscan.Scanner
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

// getScanner lazily constructs the shared jsscan scanner. A construction
// failure is non-fatal — the module simply produces no findings.
func (m *Module) getScanner() *jsscan.Scanner {
	m.scannerOnce.Do(func() {
		if s, err := jsscan.NewScanner(jsscan.DefaultConfig()); err == nil {
			m.scanner = s
		}
	})
	return m.scanner
}

func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}
	if ctx.Response() == nil || ctx.Response().BodyToString() == "" {
		return nil, nil
	}

	diskSet := m.ds.Get(scanCtx.DedupMgr())
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

	cctx, cancel := context.WithTimeout(context.Background(), scanTimeout)
	defer cancel()

	res, err := scanner.Scan(cctx, []byte(js))
	if err != nil || res == nil || !res.HasDomFlows() {
		return nil, nil
	}

	var results []*output.ResultEvent
	seen := make(map[string]struct{}, len(res.DomFlows))
	for _, f := range res.DomFlows {
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
			URL:     urlx.String(),
			Host:    urlx.Host,
			Request: string(ctx.Request().Raw()),
			Info:    output.Info{Description: desc},
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
