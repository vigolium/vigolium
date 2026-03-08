package rails_active_storage_detect

import (
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/pkg/errors"
)

var activeStorageURLRe = regexp.MustCompile(`/rails/active_storage/(blobs|representations|disk)/[^\s"'<>]+`)

type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

func New() *Module {
	m := &Module{
		BasePassiveModule: modkit.NewBasePassiveModule(
			ModuleID, ModuleName, ModuleDesc, ModuleShort,
			ModuleConfirmation, ModuleSeverity, ModuleConfidence,
			modkit.ScanScopeRequest, modkit.PassiveScanScopeResponse,
		),
		ds: dedup.LazyDiskSet("rails_active_storage_detect"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if !ctx.HasResponse() {
		return nil, nil
	}

	ct := strings.ToLower(ctx.Response().Header("Content-Type"))
	if !strings.Contains(ct, "text/html") {
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

	body := ctx.Response().BodyToString()
	if len(body) == 0 {
		return nil, nil
	}

	detected := false
	var extracted []string

	// Check for Active Storage URLs in body
	matches := activeStorageURLRe.FindAllString(body, 10)
	if len(matches) > 0 {
		detected = true
		for _, match := range matches {
			if len(match) > 120 {
				match = match[:120] + "..."
			}
			extracted = append(extracted, "URL: "+match)
		}
	}

	// Check for direct upload attributes
	if strings.Contains(body, "data-direct-upload-url") {
		detected = true
		extracted = append(extracted, "Attribute: data-direct-upload-url")
	}

	// Check for Active Storage JavaScript
	if strings.Contains(body, "activestorage") || strings.Contains(body, "active_storage") {
		detected = true
		extracted = append(extracted, "JS: Active Storage JavaScript reference")
	}

	// Check for rails_direct_uploads_url
	if strings.Contains(body, "rails_direct_uploads_url") || strings.Contains(body, "direct_uploads_url") {
		detected = true
		extracted = append(extracted, "JS: rails_direct_uploads_url reference")
	}

	if !detected {
		return nil, nil
	}

	return []*output.ResultEvent{
		{
			ModuleID:         ModuleID,
			Host:             host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			ExtractedResults: extracted,
			Info: output.Info{
				Name:        "Rails Active Storage Detected",
				Description: "Active Storage is in use. Blob URLs may be publicly accessible without application-level authorization checks",
				Severity:    severity.Info,
				Confidence:  severity.Certain,
				Tags:        []string{"rails", "ruby", "active-storage", "file-upload"},
				Reference:   []string{"https://guides.rubyonrails.org/active_storage_overview.html"},
			},
		},
	}, nil
}
