package content_type_mismatch

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
)

// mismatchCheck defines a content type mismatch test.
type mismatchCheck struct {
	declaredContains string   // substring the Content-Type should contain
	bodyPrefixes     []string // body prefixes that indicate different content
	detectedType     string   // what the body actually looks like
}

var checks = []mismatchCheck{
	{
		declaredContains: "text/html",
		bodyPrefixes:     []string{`{"`, `[{`, `["`},
		detectedType:     "application/json",
	},
	{
		declaredContains: "text/plain",
		bodyPrefixes:     []string{`{"`, `[{`, `["`},
		detectedType:     "application/json",
	},
	{
		declaredContains: "text/plain",
		bodyPrefixes:     []string{"<?xml", "<soap:", "<rss"},
		detectedType:     "application/xml",
	},
	{
		declaredContains: "text/plain",
		bodyPrefixes:     []string{"<!DOCTYPE html", "<html", "<!doctype html"},
		detectedType:     "text/html",
	},
	{
		declaredContains: "application/json",
		bodyPrefixes:     []string{"<!DOCTYPE html", "<html", "<!doctype html"},
		detectedType:     "text/html",
	},
	{
		declaredContains: "application/json",
		bodyPrefixes:     []string{"<?xml"},
		detectedType:     "application/xml",
	},
}

// Module implements the Content Type Mismatch passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Content Type Mismatch module.
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
		ds: dedup.LazyDiskSet("passive_content_type_mismatch"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest analyzes response for Content-Type mismatches.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	if utils.IsMediaAndJSURL(urlx.Path) {
		return nil, nil
	}

	if ctx.Response() == nil {
		return nil, nil
	}

	ct := strings.ToLower(ctx.Response().Header("Content-Type"))
	if ct == "" {
		return nil, nil
	}

	body := ctx.Response().BodyToString()
	if len(body) < 5 {
		return nil, nil
	}

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	hash := utils.Sha1(fmt.Sprintf("%s%s", urlx.Host, urlx.Path))
	if diskSet != nil && diskSet.IsSeen(hash) {
		return nil, nil
	}

	trimmedBody := strings.TrimSpace(body)

	for _, check := range checks {
		if !strings.Contains(ct, check.declaredContains) {
			continue
		}
		for _, prefix := range check.bodyPrefixes {
			if strings.HasPrefix(strings.ToLower(trimmedBody), strings.ToLower(prefix)) {
				// Check if X-Content-Type-Options is set
				xcto := ctx.Response().Header("X-Content-Type-Options")
				noSniff := strings.EqualFold(xcto, "nosniff")

				desc := fmt.Sprintf("Content-Type declares %q but body looks like %s", ct, check.detectedType)
				if !noSniff {
					desc += " (X-Content-Type-Options: nosniff is missing — MIME sniffing may occur)"
				}

				return []*output.ResultEvent{
					{
						Host:    urlx.Host,
						URL:     urlx.String(),
						Request: string(ctx.Request().Raw()),
						ExtractedResults: []string{
							fmt.Sprintf("Declared: %s", ct),
							fmt.Sprintf("Detected: %s", check.detectedType),
							fmt.Sprintf("X-Content-Type-Options: %s", xcto),
						},
						Info: output.Info{
							Description: desc,
						},
					},
				}, nil
			}
		}
	}

	return nil, nil
}
