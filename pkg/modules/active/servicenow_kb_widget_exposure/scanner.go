package servicenow_kb_widget_exposure

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	sn "github.com/vigolium/vigolium/pkg/modules/infra/servicenow"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

const (
	// kbBruteCount is the number of sequential KB ids probed (KB0000001..N). Small
	// enough to prove the exposure without hammering the instance.
	kbBruteCount = 12
	// bogusKB is a high, unlikely-to-exist article id used as the negative control.
	bogusKB = "KB9990001"
	// confirmRounds is the number of additional independent reads (on top of the
	// initial detection) each KB article must survive — 3 total observations,
	// matching the other SaaS-exposure modules.
	confirmRounds = 2
)

type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
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
			modkit.ScanScopeHost,
			modkit.AllInsertionPointTypes,
		),
		ds: dedup.LazyDiskSet("servicenow_kb_widget_exposure"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) IncludesBaseCanProcess() bool { return false }

func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	return ctx != nil && ctx.Request() != nil
}

func (m *Module) ScanPerHost(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}
	host := urlx.Host

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if !modkit.BeginHostProbe(scanCtx, httpClient, diskSet, host) {
		return nil, nil
	}

	// Tech gate: obtaining a guest g_ck session IS the fail-closed presence check.
	session, ok := sn.AcquireSession(ctx, httpClient)
	if !ok {
		return nil, nil
	}
	sn.MarkServiceNow(scanCtx, host)

	// Negative control: a non-existent KB id must not return article content.
	neg := sn.PostKBArticle(ctx, httpClient, bogusKB, session)
	if neg.Status == 401 {
		return nil, nil // token failure, not evidence
	}
	if sn.KBExposed(neg.Data) {
		return nil, nil // catch-all → any positive would be a false positive
	}

	var exposed []string
	for i := 1; i <= kbBruteCount; i++ {
		kb := fmt.Sprintf("KB%07d", i)
		if m.confirmKB(ctx, httpClient, kb, session) {
			exposed = append(exposed, kb)
		}
	}
	if len(exposed) == 0 {
		return nil, nil
	}

	return []*output.ResultEvent{m.build(exposed, urlx.Scheme+"://"+urlx.Host, host)}, nil
}

// confirmKB reads one KB article across independent rounds and reports whether it
// is consistently exposed.
func (m *Module) confirmKB(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester, kb string, session sn.Session) bool {
	r := sn.PostKBArticle(ctx, httpClient, kb, session)
	if !r.OK || !sn.KBExposed(r.Data) {
		return false
	}
	for i := 0; i < confirmRounds; i++ {
		rr := sn.PostKBArticle(ctx, httpClient, kb, session)
		if !rr.OK || !sn.KBExposed(rr.Data) {
			return false
		}
	}
	return true
}

func (m *Module) build(exposed []string, baseURL, host string) *output.ResultEvent {
	matchedURL := baseURL + sn.WidgetBase + sn.KBArticlePageSysID
	evidence := []string{
		fmt.Sprintf("exposed knowledge articles: %d", len(exposed)),
		"KB ids: " + strings.Join(exposed, ", "),
	}
	desc := fmt.Sprintf(
		"The ServiceNow Knowledge Base is readable by unauthenticated (guest) users through the public KB Article Page widget. "+
			"%d sequential KB article id(s) returned article content (text/short_description) to a guest session: %s. Knowledge articles "+
			"are gated by User Criteria (not table ACLs), so the 2023 ACL hardening does not cover them. Each article was confirmed across "+
			"independent rounds; a non-existent KB id returned no content, ruling out a catch-all.",
		len(exposed), strings.Join(exposed, ", "),
	)

	return &output.ResultEvent{
		ModuleID:         ModuleID,
		Host:             host,
		URL:              matchedURL,
		Matched:          matchedURL,
		MatcherStatus:    true,
		ExtractedResults: evidence,
		Info: output.Info{
			Name:        "ServiceNow Knowledge Base Widget Exposure",
			Description: desc,
			Severity:    severity.High,
			Confidence:  severity.Certain,
			Tags:        ModuleTags,
			Reference:   moduleReferences,
		},
		Metadata: map[string]any{"platform": "servicenow", "exposed_kb_count": len(exposed)},
	}
}
