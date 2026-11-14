package aem_xss

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	aem "github.com/vigolium/vigolium/pkg/modules/infra/aem"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/spitolas"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

const (
	reflectRounds = 2
	navTimeout    = 25 * time.Second
	waitExtra     = 700 * time.Millisecond
	maxProbes     = 2
)

// ProbeFunc navigates a URL in a headless browser and returns any dialogs that
// fired. Injectable so tests never spawn a real browser. Default: spitolas.ProbeURL.
type ProbeFunc func(ctx context.Context, cfg spitolas.ProbeConfig) (*spitolas.ProbeResult, error)

// probeSem bounds concurrent headless browser probes across the package.
var probeSem = make(chan struct{}, maxProbes)

type Module struct {
	modkit.BaseActiveModule
	ds    dedup.Lazy[dedup.DiskSet]
	Probe ProbeFunc
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
		ds:    dedup.LazyDiskSet("aem_xss"),
		Probe: spitolas.ProbeURL,
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

	if !modkit.BeginHostProbeKey(scanCtx, httpClient, &m.ds, host) {
		return nil, nil
	}

	if !aem.ConfirmAEM(ctx, httpClient, scanCtx) {
		return nil, nil
	}

	baseURL := urlx.Scheme + "://" + urlx.Host
	var results []*output.ResultEvent
	for _, s := range sinks {
		if res := m.probeSink(ctx, httpClient, s, baseURL); res != nil {
			results = append(results, res)
		}
	}
	return results, nil
}

// probeSink first confirms the injected breakout reflects unencoded across
// several rounds (fresh marker each round, so a static page cannot match), then
// asks a headless browser to actually execute it. Reflection-only lands at
// Low/Tentative; a fired dialog escalates to High/Certain.
func (m *Module) probeSink(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	s sink,
	baseURL string,
) *output.ResultEvent {
	reflected, err := modkit.ConfirmReflectionWithValue(reflectRounds, modkit.FreshCanary, func(marker string) (bool, error) {
		res := aem.Get(ctx, httpClient, s.build(marker), nil)
		if !res.OK || !s.okStatus(res.Status) {
			return false, nil
		}
		if s.requireHTML && !strings.Contains(strings.ToLower(res.ContentType), "html") {
			return false, nil
		}
		return strings.Contains(res.Body, xssPayload(marker)), nil
	})
	if err != nil || !reflected {
		return nil
	}

	// Headless confirmation with a fresh marker.
	marker := modkit.FreshCanary()
	confirmed, dialogMsg := m.headlessConfirm(baseURL+s.build(marker), marker)
	return m.build(s, marker, baseURL, dialogMsg, confirmed)
}

// headlessConfirm navigates the attack URL in a headless browser and reports
// whether a dialog carrying our marker fired.
func (m *Module) headlessConfirm(fullURL, marker string) (bool, string) {
	if m.Probe == nil {
		return false, ""
	}
	bg, cancel := context.WithTimeout(context.Background(), navTimeout+5*time.Second)
	defer cancel()

	select {
	case probeSem <- struct{}{}:
		defer func() { <-probeSem }()
	case <-bg.Done():
		return false, ""
	}

	res, _ := m.Probe(bg, spitolas.ProbeConfig{
		URL:        fullURL,
		WaitExtra:  waitExtra,
		NavTimeout: navTimeout,
	})
	if res == nil {
		return false, ""
	}
	for i := range res.Dialogs {
		if strings.Contains(res.Dialogs[i].Message, marker) {
			return true, res.Dialogs[i].Message
		}
	}
	return false, ""
}

func (m *Module) build(s sink, marker, baseURL, dialogMsg string, confirmed bool) *output.ResultEvent {
	path := s.build(marker)
	matchedURL := baseURL + path

	sev := severity.Low
	conf := severity.Tentative
	label := "reflection-only: unencoded breakout survived across multiple rounds in a text/html response, but execution was not browser-confirmed (CSP or non-executing context possible)"
	if confirmed {
		sev = severity.High
		conf = severity.Certain
		label = fmt.Sprintf("browser-confirmed: alert() fired in a headless browser (dialog message: %q)", dialogMsg)
	}

	tags := append([]string{"aem", "adobe", "xss"}, s.tags...)
	desc := fmt.Sprintf("Reflected XSS in the AEM %s sink at %s. %s", s.id, path, label)

	return &output.ResultEvent{
		ModuleID:         ModuleID,
		Host:             aem.HostFromBase(baseURL),
		URL:              matchedURL,
		Matched:          matchedURL,
		MatcherStatus:    true,
		ExtractedResults: []string{"sink: " + s.id, "payload: " + xssPayload(marker), label},
		Info: output.Info{
			Name:        s.name,
			Description: desc,
			Severity:    sev,
			Confidence:  conf,
			Tags:        tags,
			Reference:   s.ref,
		},
	}
}
