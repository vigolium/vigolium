package api_spec_detect

import (
	"crypto/sha256"
	"fmt"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modkit/specutil"
	"github.com/vigolium/vigolium/pkg/output"
)

// Module is the passive API spec detect scanner.
type Module struct {
	modkit.BasePassiveModule
	specDS dedup.Lazy[dedup.DiskSet]
}

// New creates a new API Spec Detect module.
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
		specDS: dedup.LazyDiskSet("api_spec_detect"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	resp := ctx.Response()
	if resp == nil {
		return nil, nil
	}

	// Only process 2xx responses
	if resp.StatusCode() < 200 || resp.StatusCode() >= 300 {
		return nil, nil
	}

	// Content-type filter
	ct, _ := httpmsg.FindHttpHeader(resp.Headers(), "Content-Type")
	if !specutil.IsSpecContentType(ct) {
		return nil, nil
	}

	body := resp.Body()
	// Body size guard
	if len(body) < specutil.MinSpecBodySize || len(body) > specutil.MaxSpecBodySize {
		return nil, nil
	}

	// Check if it's a recognizable spec
	st := specutil.DetectSpecType(body)
	if st == specutil.Unknown {
		return nil, nil
	}

	// Content dedup
	contentHash := fmt.Sprintf("%x", sha256.Sum256(body))
	specDS := m.specDS.Get(scanCtx.DedupMgr())
	if specDS != nil && specDS.IsSeen(contentHash) {
		return nil, nil
	}

	// Derive base URL from request
	baseURL := ""
	if ctx.Service() != nil {
		baseURL = ctx.Service().Protocol() + "://" + ctx.Service().Host()
	}

	// Parse endpoints using pre-detected type
	endpoints, err := specutil.ParseSpecTyped(st, body, baseURL, ctx.Service())
	if err != nil || len(endpoints) == 0 {
		return nil, nil
	}

	// Feed endpoints into the scanning pipeline
	count := 0
	if feeder := scanCtx.Feeder(); feeder != nil {
		for _, rr := range endpoints {
			if feeder.Feed(rr) {
				count++
			}
		}
	}

	url := ctx.Target()
	return []*output.ResultEvent{
		{
			URL:     url,
			Matched: url,
			Info: output.Info{
				Name:        ModuleName,
				Description: fmt.Sprintf("Detected API spec in response, parsed %d endpoints (fed %d)", len(endpoints), count),
			},
		},
	}, nil
}
