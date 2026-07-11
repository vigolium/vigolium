package client_auth_guard

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/shared/jsframework"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

var (
	// Client-side auth redirect patterns using useEffect
	clientAuthRedirectRe = regexp.MustCompile(
		`useEffect\s*\(` +
			`[\s\S]{0,500}?` +
			`(?:` +
			`router\.(?:push|replace)\s*\(\s*['"]\/(?:login|signin|auth)` +
			`|` +
			`window\.location\s*=\s*['"]\/(?:login|signin|auth)` +
			`)`,
	)

	// Server-side auth indicators
	serverAuthRe = regexp.MustCompile(`getServerSession|getSession|auth\s*\(\)|cookies\(\)\.get`)
)

// Module implements the client auth guard passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Client Auth Guard Check module.
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
		ds: dedup.LazyDiskSet("client_auth_guard"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// CanProcess accepts JS/TS content types or URL paths ending in JS/TS extensions.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Response() == nil {
		return false
	}
	if len(ctx.Response().Body()) == 0 {
		return false
	}

	if modkit.IsJSOrTSContentType(ctx.Response().Header("Content-Type")) {
		return true
	}

	if u, err := ctx.URL(); err == nil {
		if modkit.HasJSExtension(strings.ToLower(u.Path)) {
			return true
		}
	}

	return false
}

// ScanPerRequest scans for client-only auth guards.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if !ctx.HasResponse() {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	// Dedup by host+path
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	dedupKey := utils.Sha1(fmt.Sprintf("%s%s", urlx.Host, urlx.Path))
	if diskSet != nil && diskSet.IsSeen(dedupKey) {
		return nil, nil
	}

	body := ctx.Response().BodyToString()

	// Step 1: Check for "use client" directive
	if !jsframework.UseClientDirectiveRe.MatchString(body) {
		return nil, nil
	}

	// Step 2: Check for client-side auth redirect pattern
	match := clientAuthRedirectRe.FindString(body)
	if match == "" {
		return nil, nil
	}

	// Step 3: Check for server-side auth - if present, no issue
	if serverAuthRe.MatchString(body) {
		return nil, nil
	}

	return []*output.ResultEvent{
		{
			ModuleID:      ModuleID,
			Host:          urlx.Host,
			URL:           urlx.String(),
			Matched:       urlx.String(),
			RecordKind:    output.RecordKindObservation,
			EvidenceGrade: output.EvidenceGradeObservation,
			ExtractedResults: []string{
				"Client component uses a useEffect-based authentication redirect",
				fmt.Sprintf("Redirect pattern: %s", modkit.Truncate(match, 150)),
			},
			Info: output.Info{
				Name:        "Client-Side Auth Redirect Observation",
				Description: fmt.Sprintf("Next.js client component at %s performs an authentication redirect in useEffect. A client bundle cannot reveal middleware, server-component, route-handler, or backend authorization, so this is not evidence of an auth bypass; verify the underlying page/data request anonymously.", urlx.Path),
				Severity:    severity.Info,
				Confidence:  severity.Tentative,
				Tags:        []string{"auth", "client-side", "nextjs", "source-analysis"},
				Reference:   []string{"https://cwe.mitre.org/data/definitions/862.html"},
			},
			Metadata: map[string]any{
				"cwe":                    "CWE-862",
				"requires_runtime_check": true,
			},
		},
	}, nil
}
