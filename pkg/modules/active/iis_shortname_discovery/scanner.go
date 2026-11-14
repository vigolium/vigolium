package iis_shortname_discovery

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/iisgate"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"go.uber.org/zap"
)

const maxRequestsPerHost = 2000

// Module implements IIS short filename discovery via tilde enumeration.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new IIS Short Filename Discovery module.
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
		ds: dedup.LazyDiskSet("iis_shortname_discovery"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// IncludesBaseCanProcess returns false to use custom CanProcess logic.
func (m *Module) IncludesBaseCanProcess() bool { return false }

// CanProcess returns true only for IIS servers (detected via response headers).
// This is a fast pre-filter; ScanPerHost applies stronger gating.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Request() == nil || ctx.Response() == nil {
		return false
	}
	return iisgate.RespLooksIIS(ctx.Response())
}

// ScanPerHost scans the host for IIS 8.3 short filename disclosure.
func (m *Module) ScanPerHost(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	service := ctx.Service()
	if service == nil {
		return nil, nil
	}

	host := service.Host()

	// Passive gate: only run against hosts that present as IIS/ASP.NET. The
	// active behavioral proof for this module is the tilde-oracle detection
	// below (detectVulnerability), which no non-IIS host can pass.
	if !iisgate.LooksLikeIIS(ctx, scanCtx, host) {
		return nil, nil
	}

	// Dedup by host
	if !modkit.BeginHostProbeFor(scanCtx, httpClient, &m.ds, ctx) {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}

	basePath := "/"
	reqBudget := newRequestBudget(maxRequestsPerHost)

	// Phase 1: Behavioral confirmation + vulnerability detection. A positive
	// oracle here is itself strong proof the host behaves like IIS.
	o := detectVulnerability(ctx, httpClient, basePath, reqBudget)
	if o == nil {
		zap.L().Debug("IISShortname: not vulnerable or detection inconclusive",
			zap.String("host", host))
		return nil, nil
	}

	// Phase 2: Character discovery
	cm := discoverCharacters(ctx, httpClient, basePath, o, reqBudget)

	// Phase 3: Recursive enumeration of short-name fragments
	discovered := enumerate(ctx, httpClient, basePath, o, cm, reqBudget)
	if len(discovered) == 0 {
		zap.L().Debug("IISShortname: vulnerable but no files enumerated",
			zap.String("host", host))
		return nil, nil
	}

	// Phase 4: Full-name resolution (wordlist + checksum), multi-round
	// confirmation, and recursion into confirmed directories.
	targetURL := urlx.Scheme + "://" + urlx.Host
	res := newResolver(targetURL)
	resolved := res.resolveAll(ctx, httpClient, basePath, o, discovered, reqBudget, 0)

	zap.L().Info("IISShortname: enumeration complete",
		zap.String("host", host),
		zap.Int("fragments", len(discovered)),
		zap.Int("resolved", countResolved(resolved)),
		zap.Int("requests", reqBudget.count),
	)

	return m.buildResult(scanCtx, host, targetURL, o, resolved, reqBudget), nil
}

// buildResult feeds confirmed URLs back into the scan pipeline and assembles the
// finding, raising severity when any resolved file is security-sensitive.
func (m *Module) buildResult(
	scanCtx *modkit.ScanContext,
	host, targetURL string,
	o *oracle,
	resolved []resolvedName,
	reqBudget *requestBudget,
) []*output.ResultEvent {
	var (
		shortNames    []string
		resolvedNames []string
		extracted     []string
		sensitiveHits []string
		fedCount      int
		fed           = make(map[string]struct{})
	)

	sev := ModuleSeverity
	for _, rn := range resolved {
		shortNames = append(shortNames, rn.shortName)

		if rn.fullName != "" {
			resolvedNames = append(resolvedNames, fmt.Sprintf("%s → %s", rn.shortName, rn.fullName))
			extracted = append(extracted, rn.fullName)
		} else {
			extracted = append(extracted, rn.shortName)
		}

		if rn.sensitive {
			sev = severity.High
			sensitiveHits = append(sensitiveHits, fmt.Sprintf("%s (%s)", rn.fullName, rn.reason))
		}

		// Feed confirmed real URLs back into the pipeline for content discovery.
		if rn.url != "" {
			if _, seen := fed[rn.url]; !seen {
				fed[rn.url] = struct{}{}
				if feedURL(scanCtx, rn.url) {
					fedCount++
				}
			}
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "The IIS server at %s exposes 8.3 short filenames via tilde enumeration.\n\n"+
		"**Discovered fragments (%d):**\n", targetURL, len(shortNames))
	for _, name := range shortNames {
		fmt.Fprintf(&b, "- `%s`\n", name)
	}

	if len(resolvedNames) > 0 {
		fmt.Fprintf(&b, "\n**Resolved full filenames (%d):**\n", len(resolvedNames))
		for _, name := range resolvedNames {
			fmt.Fprintf(&b, "- `%s`\n", name)
		}
	}

	if len(sensitiveHits) > 0 {
		fmt.Fprintf(&b, "\n**Sensitive files disclosed (%d):**\n", len(sensitiveHits))
		for _, name := range sensitiveHits {
			fmt.Fprintf(&b, "- `%s`\n", name)
		}
	}

	if fedCount > 0 {
		fmt.Fprintf(&b, "\n**%d confirmed URL(s) queued for further scanning.**\n", fedCount)
	}

	fmt.Fprintf(&b, "\n**Detection method:** %s with suffix `%s` (status %d vs %d)\n",
		o.method, o.suffix, o.statusPos, o.statusNeg)
	fmt.Fprintf(&b, "**Requests sent:** %d", reqBudget.count)
	description := b.String()

	return []*output.ResultEvent{{
		ModuleID:         ModuleID,
		URL:              targetURL,
		Host:             host,
		Matched:          strings.Join(shortNames, ", "),
		ExtractedResults: extracted,
		Info: output.Info{
			Name:        "IIS Short Filename Disclosure",
			Description: description,
			Severity:    sev,
			Confidence:  ModuleConfidence,
			Tags:        []string{"iis", "shortname", "information-disclosure", "8.3"},
			Reference: []string{
				"https://soroush.me/blog/2023/07/thirteen-years-on-advancing-the-understanding-of-iis-short-file-name-sfn-disclosure/",
				"https://github.com/bitquark/shortscan",
			},
		},
	}}
}

// feedURL injects a confirmed URL into the scan pipeline. Returns true if accepted.
func feedURL(scanCtx *modkit.ScanContext, target string) bool {
	feeder := scanCtx.Feeder()
	if feeder == nil {
		return false
	}
	rr, err := httpmsg.GetRawRequestFromURL(target)
	if err != nil {
		return false
	}
	return feeder.Feed(rr)
}

func countResolved(resolved []resolvedName) int {
	n := 0
	for _, rn := range resolved {
		if rn.fullName != "" {
			n++
		}
	}
	return n
}
