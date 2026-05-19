package server_action_auth

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

var (
	useServerRe = regexp.MustCompile(`(?:'use server'|"use server")`)
	mutationRe  = regexp.MustCompile(`\.(?:create|update|delete|insert|upsert|save|destroy|remove)\s*\(|prisma\.|db\.|\.execute\(`)
	authCheckRe = regexp.MustCompile(`getSession|getServerSession|auth\s*\(\)|currentUser|cookies\(\)\.get|verifyToken|requireAuth|checkAuth|validateSession|getUser`)
)

// Module implements the Server Action auth check passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Server Action Auth Check module.
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
		ds: dedup.LazyDiskSet("server_action_auth"),
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

// ScanPerRequest scans for Server Actions missing authorization.
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

	// Step 1: Check for "use server" directive
	if !useServerRe.MatchString(body) {
		return nil, nil
	}

	// Step 2: Check for state-changing mutation patterns
	mutations := mutationRe.FindAllString(body, 10)
	if len(mutations) == 0 {
		return nil, nil
	}

	// Step 3: Check for auth patterns - if present, no issue
	if authCheckRe.MatchString(body) {
		return nil, nil
	}

	// Mutations found but no auth patterns
	extracted := make([]string, 0, len(mutations)+1)
	extracted = append(extracted, "Server Action with 'use server' directive lacks authorization checks")
	seen := make(map[string]bool)
	for _, mut := range mutations {
		trimmed := strings.TrimSpace(mut)
		if !seen[trimmed] {
			extracted = append(extracted, fmt.Sprintf("Mutation pattern: %s", trimmed))
			seen[trimmed] = true
		}
	}

	return []*output.ResultEvent{
		{
			ModuleID:         ModuleID,
			Host:             urlx.Host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			ExtractedResults: extracted,
			Info: output.Info{
				Name:        "Server Action Missing Authorization",
				Description: fmt.Sprintf("Next.js Server Action at %s performs %d mutation(s) without authorization checks", urlx.Path, len(mutations)),
				Severity:    severity.High,
				Confidence:  severity.Tentative,
				Tags:        []string{"auth", "server-action", "nextjs", "source-analysis"},
				Reference:   []string{"https://cwe.mitre.org/data/definitions/862.html"},
			},
			Metadata: map[string]any{
				"cwe":           "CWE-862",
				"mutationCount": len(mutations),
			},
		},
	}, nil
}
