package rails_debug_detect

import (
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

type debugPattern struct {
	name    string
	markers []string // ALL markers must match
	sev     severity.Severity
	desc    string
	tags    []string
}

var debugPatterns = []debugPattern{
	{
		name:    "Rails Exception Page",
		markers: []string{"ActionController::RoutingError", "Backtrace"},
		sev:     severity.High,
		desc:    "Rails detailed exception page is exposed in production, leaking stack traces, environment details, and internal routes",
		tags:    []string{"rails", "debug", "exception", "information-disclosure"},
	},
	{
		name:    "Rails Exception Page (ActionView)",
		markers: []string{"ActionView::Template::Error"},
		sev:     severity.High,
		desc:    "Rails ActionView template error page is exposed, leaking template paths and stack traces",
		tags:    []string{"rails", "debug", "exception", "information-disclosure"},
	},
	{
		name:    "Better Errors",
		markers: []string{"Better Errors"},
		sev:     severity.Critical,
		desc:    "Better Errors development gem is active in production. This may expose an interactive console leading to remote code execution",
		tags:    []string{"rails", "debug", "better-errors", "rce"},
	},
	{
		name:    "Web Console",
		markers: []string{"Web Console", "__web_console"},
		sev:     severity.Critical,
		desc:    "Rails Web Console is active in production, potentially allowing remote code execution via interactive console",
		tags:    []string{"rails", "debug", "web-console", "rce"},
	},
	{
		name:    "ActiveRecord SQL Error (PostgreSQL)",
		markers: []string{"PG::SyntaxError"},
		sev:     severity.Medium,
		desc:    "ActiveRecord PostgreSQL error details are leaked in the response, exposing database structure information",
		tags:    []string{"rails", "database", "sql-error", "information-disclosure"},
	},
	{
		name:    "ActiveRecord SQL Error (MySQL)",
		markers: []string{"Mysql2::Error"},
		sev:     severity.Medium,
		desc:    "ActiveRecord MySQL error details are leaked in the response",
		tags:    []string{"rails", "database", "sql-error", "information-disclosure"},
	},
	{
		name:    "ActiveRecord SQL Error (SQLite)",
		markers: []string{"SQLite3::SQLException"},
		sev:     severity.Medium,
		desc:    "ActiveRecord SQLite error details are leaked in the response",
		tags:    []string{"rails", "database", "sql-error", "information-disclosure"},
	},
	{
		name:    "ActiveRecord Statement Invalid",
		markers: []string{"ActiveRecord::StatementInvalid"},
		sev:     severity.Medium,
		desc:    "ActiveRecord statement error is leaked, potentially exposing SQL query structure and table/column names",
		tags:    []string{"rails", "database", "sql-error", "information-disclosure"},
	},
}

// pathDisclosureMarkers detects absolute filesystem paths common in Rails deployments
var pathDisclosureMarkers = []string{
	"/app/app/controllers/",
	"/app/app/models/",
	"/app/app/views/",
	"/usr/local/bundle/gems/",
	"rb_sysopen",
	"No such file or directory",
	"Errno::ENOENT",
}

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
		ds: dedup.LazyDiskSet("rails_debug_detect"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if !ctx.HasResponse() {
		return nil, nil
	}

	ct := strings.ToLower(ctx.Response().Header("Content-Type"))
	if !strings.Contains(ct, "text/html") && !strings.Contains(ct, "application/json") && !strings.Contains(ct, "text/plain") {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	body := ctx.Response().BodyToString()
	if len(body) == 0 {
		return nil, nil
	}

	host := urlx.Host

	// Note: no host-level dedup here because debug errors can appear on any page
	// Use a per-URL dedup instead
	diskSet := m.ds.Get(scanCtx.DedupMgr())

	var results []*output.ResultEvent

	// Check debug patterns
	for _, dp := range debugPatterns {
		allMatch := true
		var matched []string
		for _, marker := range dp.markers {
			if strings.Contains(body, marker) {
				matched = append(matched, marker)
			} else {
				allMatch = false
				break
			}
		}
		if !allMatch {
			continue
		}

		dedupKey := host + "::" + dp.name
		if diskSet != nil && diskSet.IsSeen(dedupKey) {
			continue
		}

		results = append(results, &output.ResultEvent{
			ModuleID:         ModuleID,
			Host:             host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			ExtractedResults: matched,
			Info: output.Info{
				Name:        "Rails Debug: " + dp.name,
				Description: dp.desc,
				Severity:    dp.sev,
				Confidence:  severity.Firm,
				Tags:        dp.tags,
				Reference:   []string{"https://guides.rubyonrails.org/configuring.html"},
			},
		})
	}

	// Check for path disclosure
	var disclosedPaths []string
	for _, marker := range pathDisclosureMarkers {
		if strings.Contains(body, marker) {
			disclosedPaths = append(disclosedPaths, marker)
		}
	}
	if len(disclosedPaths) > 0 {
		dedupKey := host + "::path-disclosure"
		if diskSet == nil || !diskSet.IsSeen(dedupKey) {
			results = append(results, &output.ResultEvent{
				ModuleID:         ModuleID,
				Host:             host,
				URL:              urlx.String(),
				Matched:          urlx.String(),
				ExtractedResults: disclosedPaths,
				Info: output.Info{
					Name:        "Rails Debug: Source Path Disclosure",
					Description: "Absolute filesystem paths from a Rails deployment are disclosed in the response, revealing deployment layout and internal structure",
					Severity:    severity.Low,
					Confidence:  severity.Firm,
					Tags:        []string{"rails", "path-disclosure", "information-disclosure"},
					Reference:   []string{"https://owasp.org/www-community/Improper_Error_Handling"},
				},
			})
		}
	}

	return results, nil
}
