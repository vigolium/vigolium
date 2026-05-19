package graphql_fingerprint

import (
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

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
		ds: dedup.LazyDiskSet("graphql_fingerprint"),
	}
	m.ModuleTags = ModuleTags
	return m
}

var (
	pathRe   = regexp.MustCompile(`(?i)/(graphql|v\d+/graphql|api/graphql|graphiql|playground|altair)(/|$|\?)`)
	errorsRe = regexp.MustCompile(`"errors"\s*:\s*\[\s*\{[^}]*"locations"\s*:\s*\[`)
)

func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if !ctx.HasResponse() {
		return nil, nil
	}
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}
	host := urlx.Host
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(host) {
		return nil, nil
	}

	var evidence []string

	if pathRe.MatchString(urlx.Path) {
		evidence = append(evidence, "Path: "+urlx.Path)
	}

	ct := strings.ToLower(ctx.Response().Header("Content-Type"))
	if strings.Contains(ct, "application/json") || strings.Contains(ct, "application/graphql") {
		body := ctx.Response().BodyToString()
		if errorsRe.MatchString(body) {
			evidence = append(evidence, "Body: GraphQL errors[].locations shape")
		}
	}

	if len(evidence) == 0 {
		return nil, nil
	}

	scanCtx.MarkTech(host, "graphql")

	return []*output.ResultEvent{
		{
			ModuleID:         ModuleID,
			Host:             host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			ExtractedResults: evidence,
			Info: output.Info{
				Name:        "GraphQL Endpoint Detected",
				Description: "GraphQL endpoint detected via path or response shape",
				Severity:    severity.Info,
				Confidence:  severity.Certain,
				Tags:        []string{"graphql", "api", "fingerprint"},
			},
			Metadata: map[string]any{
				"platform": "graphql",
			},
		},
	}, nil
}
