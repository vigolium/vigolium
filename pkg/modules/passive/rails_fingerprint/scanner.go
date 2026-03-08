package rails_fingerprint

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/pkg/errors"
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
		ds: dedup.LazyDiskSet("rails_fingerprint"),
	}
	m.ModuleTags = ModuleTags
	return m
}

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

	hdr := func(name string) string { return ctx.Response().Header(name) }
	body := ctx.Response().BodyToString()

	// Detection signals
	detected := false
	var extracted []string
	meta := map[string]any{
		"platform": "rails",
	}

	// Header signals: X-Request-Id + X-Runtime combination is a strong Rails indicator
	hasRequestId := hdr("X-Request-Id") != ""
	hasRuntime := hdr("X-Runtime") != ""
	if hasRequestId && hasRuntime {
		detected = true
		extracted = append(extracted, "X-Request-Id: present")
		extracted = append(extracted, "X-Runtime: "+hdr("X-Runtime"))
	}

	// Server header signals
	serverHdr := strings.ToLower(hdr("Server"))
	if strings.Contains(serverHdr, "puma") {
		detected = true
		extracted = append(extracted, "Server: Puma")
		meta["server"] = "puma"
	} else if strings.Contains(serverHdr, "unicorn") {
		detected = true
		extracted = append(extracted, "Server: Unicorn")
		meta["server"] = "unicorn"
	} else if strings.Contains(serverHdr, "passenger") {
		detected = true
		extracted = append(extracted, "Server: Passenger")
		meta["server"] = "passenger"
	}

	// Cookie signals: Rails session cookies typically named _<app>_session
	for _, h := range ctx.Response().Headers() {
		if !strings.EqualFold(h.Name, "Set-Cookie") {
			continue
		}
		cookieLower := strings.ToLower(h.Value)
		if strings.Contains(cookieLower, "_session=") && !strings.Contains(cookieLower, "asp") {
			detected = true
			// Extract cookie name
			parts := strings.SplitN(h.Value, "=", 2)
			if len(parts) > 0 {
				extracted = append(extracted, "Cookie: "+strings.TrimSpace(parts[0]))
			}
		}
	}

	// Body signals (only check HTML responses)
	ct := strings.ToLower(hdr("Content-Type"))
	if strings.Contains(ct, "text/html") {
		// Default Rails 404 page
		if strings.Contains(body, "The page you were looking for doesn't exist") {
			detected = true
			extracted = append(extracted, "Body: Default Rails 404 page")
		}
		// Default Rails 500 page
		if strings.Contains(body, "We're sorry, but something went wrong") {
			detected = true
			extracted = append(extracted, "Body: Default Rails 500 page")
		}
		// Rails CSRF meta tag
		if strings.Contains(body, `name="csrf-token"`) || strings.Contains(body, `name="csrf-param"`) {
			detected = true
			extracted = append(extracted, "Body: Rails CSRF meta tag")
		}
		// Turbo/Turbolinks
		if strings.Contains(body, "data-turbo-track") || strings.Contains(body, "data-turbolinks-track") {
			detected = true
			extracted = append(extracted, "Body: Turbo/Turbolinks")
			meta["turbo"] = true
		}
		// Action Cable meta tag
		if strings.Contains(body, `name="action-cable-url"`) {
			detected = true
			extracted = append(extracted, "Body: Action Cable meta tag")
			meta["actionCable"] = true
		}
	}

	if !detected {
		return nil, nil
	}

	desc := "Ruby on Rails application detected"
	if server, ok := meta["server"]; ok {
		desc += " running on " + server.(string)
	}

	return []*output.ResultEvent{
		{
			ModuleID:         ModuleID,
			Host:             host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			ExtractedResults: extracted,
			Info: output.Info{
				Name:        "Ruby on Rails Application Detected",
				Description: desc,
				Severity:    severity.Info,
				Confidence:  severity.Certain,
				Tags:        []string{"rails", "ruby", "fingerprint"},
			},
			Metadata: meta,
		},
	}, nil
}
