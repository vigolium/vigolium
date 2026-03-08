package iis_shortname_discovery

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
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
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Request() == nil || ctx.Response() == nil {
		return false
	}
	return isIISServer(ctx.Response())
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

	// Dedup by host
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(host) {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}

	basePath := "/"
	reqBudget := newRequestBudget(maxRequestsPerHost)

	// Phase 1: Vulnerability detection
	o := detectVulnerability(ctx, httpClient, basePath, reqBudget)
	if o == nil {
		zap.L().Debug("IISShortname: not vulnerable or detection inconclusive",
			zap.String("host", host))
		return nil, nil
	}

	// Phase 2: Character discovery
	cm := discoverCharacters(ctx, httpClient, basePath, o, reqBudget)

	// Phase 3: Recursive enumeration
	discovered := enumerate(ctx, httpClient, basePath, o, cm, reqBudget)

	if len(discovered) == 0 {
		zap.L().Debug("IISShortname: vulnerable but no files enumerated",
			zap.String("host", host))
		return nil, nil
	}

	zap.L().Info("IISShortname: enumeration complete",
		zap.String("host", host),
		zap.Int("found", len(discovered)),
		zap.Int("requests", reqBudget.count),
	)

	// Build results
	var shortNames []string
	for _, sf := range discovered {
		shortNames = append(shortNames, sf.String())
	}

	targetURL := urlx.Scheme + "://" + urlx.Host

	description := fmt.Sprintf(
		"The IIS server at %s exposes 8.3 short filenames via tilde enumeration.\n\n"+
			"**Discovered short filenames (%d):**\n",
		targetURL, len(shortNames),
	)
	for _, name := range shortNames {
		description += fmt.Sprintf("- `%s`\n", name)
	}
	description += fmt.Sprintf("\n**Detection method:** %s with suffix `%s` (status %d vs %d)\n",
		o.method, o.suffix, o.statusPos, o.statusNeg)
	description += fmt.Sprintf("**Requests sent:** %d", reqBudget.count)

	return []*output.ResultEvent{{
		ModuleID: ModuleID,
		URL:      targetURL,
		Host:     host,
		Matched:  strings.Join(shortNames, ", "),
		ExtractedResults: shortNames,
		Info: output.Info{
			Name:        "IIS Short Filename Disclosure",
			Description: description,
			Severity:    ModuleSeverity,
			Confidence:  ModuleConfidence,
			Tags:        []string{"iis", "shortname", "information-disclosure", "8.3"},
			Reference: []string{
				"https://soroush.me/blog/2023/07/thirteen-years-on-advancing-the-understanding-of-iis-short-file-name-sfn-disclosure/",
				"https://github.com/bitquark/shortscan",
			},
		},
	}}, nil
}
