// Package client_path_taint is a passive Client-Side Path Traversal (CSPT)
// candidate detector. It reuses the jstangle AST taint analyzer (the same engine
// behind dom_xss_taint) but consumes the network/request-path flow class
// (clientRequestInjection) instead of the DOM-XSS class: a URL-controlled source
// (location.hash/search, URLSearchParams, document.URL) that flows into a
// client-side request-path sink (fetch, XMLHttpRequest.open, axios).
//
// Findings are Low/Firm candidates — proof that the source reaches the request
// path, not proof that a `..` actually escapes the intended prefix. The active
// client_path_traversal_confirm module (gated on the cspt-candidate tech tag
// this module publishes) performs the browser confirmation. The shared
// flow-recognition primitives live in pkg/modules/infra/csptflow so the detector
// and the confirmer can never diverge.
package client_path_taint

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/deparos/jstangle"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra/csptflow"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
)

// TechTagCSPTCandidate is published to the per-host TechRegistry whenever this
// module finds a CSPT candidate; the active client_path_traversal_confirm module
// is fail-closed on it. Aliased from the shared package so the value has a single
// source of truth.
const TechTagCSPTCandidate = csptflow.TechTagCSPTCandidate

// Cheap raw-JS presence gates: only spawn the (subprocess) taint analyzer when
// the JS plausibly contains both a URL source and a request-path sink. The
// analyzer then decides whether they are actually connected. (Passive-only — the
// active confirmer works from the tech tag, not a raw-JS gate.)
var (
	gateSourceRe = regexp.MustCompile(`(?i)(location\.(search|hash|pathname|href)|URLSearchParams|document\.(URL|documentURI))`)
	gateSinkRe   = regexp.MustCompile(`(?i)(fetch\s*\(|XMLHttpRequest|\.open\s*\(|axios|\$\.ajax|\.ajax\s*\()`)
)

// Candidate is a selected CSPT request-path taint flow.
type Candidate struct {
	Source   string
	Sink     string
	Snippet  string
	Line     int
	FlowType string
	Prefix   string // constant request-path prefix parsed from the snippet, if any
	Method   string // inferred HTTP method (defaults to GET)
}

type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
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
		ds: dedup.LazyDiskSet("passive_client_path_taint"),
	}
	m.ModuleTags = ModuleTags
	return m
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

// ScanPerRequestContext preserves executor cancellation while the shared service
// queues or analyzes a response.
func (m *Module) ScanPerRequestContext(runCtx context.Context, ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
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

	js := csptflow.ExtractJS(ctx, urlx)
	if js == "" || !gateSourceRe.MatchString(js) || !gateSinkRe.MatchString(js) {
		return nil, nil
	}

	scanner := csptflow.Scanner()
	if scanner == nil {
		return nil, nil
	}

	cctx, cancel := context.WithTimeout(runCtx, csptflow.ScanTimeout)
	defer cancel()

	res, err := scanner.ScanWithOptions(cctx, []byte(js), jstangle.ScanOptions{
		Profile: jstangle.ProfileDOMSecurity, SourceURL: urlx.String(),
	})
	if err != nil || res == nil {
		return nil, nil
	}

	candidates := selectCandidates(res.DomFlows, res.BrowserFlows)
	if len(candidates) == 0 {
		return nil, nil
	}

	// Publish the tech tag once we have at least one candidate: the active
	// confirmer is fail-closed on it.
	scanCtx.MarkTech(urlx.Host, TechTagCSPTCandidate)

	results := make([]*output.ResultEvent, 0, len(candidates))
	for _, c := range candidates {
		results = append(results, &output.ResultEvent{
			URL:           urlx.String(),
			Host:          urlx.Host,
			Request:       string(ctx.Request().Raw()),
			RecordKind:    output.RecordKindCandidate,
			EvidenceGrade: output.EvidenceGradeCandidate,
			Info: output.Info{
				Description: describeCandidate(c),
			},
		})
	}
	return results, nil
}

// selectCandidates maps the shared CSPT flow-recognition output into this
// module's Candidate shape. The recognition/dedup logic lives in csptflow so it
// stays in lockstep with the active confirmer.
func selectCandidates(domFlows []jstangle.DomFlow, browserFlows []jstangle.BrowserSecurityFlowFact) []Candidate {
	flows := csptflow.NetworkPathFlows(domFlows, browserFlows)
	out := make([]Candidate, 0, len(flows))
	for _, f := range flows {
		out = append(out, Candidate{
			Source:   f.Source,
			Sink:     f.Sink,
			Snippet:  f.Snippet,
			Line:     f.Line,
			FlowType: f.FlowType,
			Prefix:   f.Prefix,
			Method:   f.Method,
		})
	}
	return out
}

func describeCandidate(c Candidate) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Client-Side Path Traversal candidate: URL source %s flows into request-path sink %s", c.Source, c.Sink)
	if c.Line > 0 {
		fmt.Fprintf(&b, " (line %d)", c.Line)
	}
	b.WriteString(".")
	if c.Prefix != "" {
		fmt.Fprintf(&b, " Constant path prefix %q, inferred method %s.", c.Prefix, c.Method)
	} else {
		fmt.Fprintf(&b, " Inferred method %s.", c.Method)
	}
	if c.Snippet != "" {
		fmt.Fprintf(&b, "\n```js\n%s\n```", c.Snippet)
	}
	return b.String()
}
