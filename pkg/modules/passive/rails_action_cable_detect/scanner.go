package rails_action_cable_detect

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

var cableURLRe = regexp.MustCompile(`(?:action-cable-url|cable_url|cableUrl)[^"']*["']([^"']+)["']`)

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
		ds: dedup.LazyDiskSet("rails_action_cable_detect"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if !ctx.HasResponse() {
		return nil, nil
	}

	ct := strings.ToLower(ctx.Response().Header("Content-Type"))
	if !strings.Contains(ct, "text/html") && !strings.Contains(ct, "javascript") {
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

	// Check for Action Cable meta tag
	if strings.Contains(body, `name="action-cable-url"`) {
		detected = true
		extracted = append(extracted, "Meta: action-cable-url tag")
	}

	// Check for Action Cable JS references
	if strings.Contains(body, "actioncable") || strings.Contains(body, "action_cable") || strings.Contains(body, "ActionCable") {
		detected = true
		extracted = append(extracted, "JS: Action Cable reference")
	}

	// Check for channel subscription patterns
	if strings.Contains(body, "subscriptions.create") {
		detected = true
		extracted = append(extracted, "JS: Channel subscription pattern")
	}

	// Extract cable URL if present
	if matches := cableURLRe.FindStringSubmatch(body); len(matches) > 1 {
		detected = true
		extracted = append(extracted, "Cable URL: "+matches[1])
	}

	// Check for /cable or /websocket path references
	cablePaths := []string{`"/cable"`, `'/cable'`, `"/websocket"`, `'/websocket'`, `"/ws"`, `'/ws'`}
	for _, cp := range cablePaths {
		if strings.Contains(body, cp) {
			detected = true
			extracted = append(extracted, "Path: "+strings.Trim(cp, `"'`))
			break
		}
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
				Name:        "Rails Action Cable Detected",
				Description: "Action Cable WebSocket endpoint is in use. Verify origin restrictions and authentication are properly configured",
				Severity:    severity.Info,
				Confidence:  severity.Firm,
				Tags:        []string{"rails", "ruby", "action-cable", "websocket"},
				Reference:   []string{"https://guides.rubyonrails.org/action_cable_overview.html"},
			},
		},
	}, nil
}
