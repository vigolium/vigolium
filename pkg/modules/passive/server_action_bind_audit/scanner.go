package server_action_bind_audit

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
	"github.com/pkg/errors"
)

var (
	useServerRe = regexp.MustCompile(`(?:'use server'|"use server")`)

	// Detects .bind(null, identifier) patterns — the standard way to pass args to server actions
	bindCallRe = regexp.MustCompile(`\.bind\s*\(\s*null\s*,\s*(\w+(?:\.\w+)*)\s*\)`)

	// Identifier names that suggest resource references (IDOR risk)
	sensitiveIDRe = regexp.MustCompile(`(?i)(?:^|\.)(id|userId|user_id|postId|post_id|commentId|comment_id|orderId|order_id|accountId|account_id|resourceId|resource_id|slug|uuid|itemId|item_id|teamId|team_id|orgId|org_id|projectId|project_id|documentId|document_id)$`)

	// Authorization patterns that mitigate the risk
	authzCheckRe = regexp.MustCompile(`canAccess|isOwner|checkPermission|authorize|verifyOwnership|belongsTo|hasPermission|getSession|auth\s*\(\)|verifySession|requireAuth|checkAuth`)
)

// Module implements the Server Action bind audit passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Server Action Bind Audit module.
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
		ds: dedup.LazyDiskSet("server_action_bind_audit"),
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

// ScanPerRequest scans for .bind() with sensitive identifiers.
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

	// Must contain "use server" directive
	if !useServerRe.MatchString(body) {
		return nil, nil
	}

	// Find .bind(null, identifier) calls
	matches := bindCallRe.FindAllStringSubmatch(body, 20)
	if len(matches) == 0 {
		return nil, nil
	}

	// Filter for sensitive identifier names
	var sensitiveBinds []string
	seen := make(map[string]bool)
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		identifier := match[1]
		// Check the last segment of dotted identifiers (e.g., post.id → id)
		lastDot := strings.LastIndex(identifier, ".")
		checkPart := identifier
		if lastDot >= 0 {
			checkPart = identifier[lastDot+1:]
		}
		if sensitiveIDRe.MatchString(checkPart) && !seen[identifier] {
			sensitiveBinds = append(sensitiveBinds, identifier)
			seen[identifier] = true
		}
	}

	if len(sensitiveBinds) == 0 {
		return nil, nil
	}

	// Check for authorization patterns - if present, risk is mitigated
	if authzCheckRe.MatchString(body) {
		return nil, nil
	}

	extracted := []string{
		"Server Action uses .bind() with sensitive identifiers without authorization checks",
	}
	for _, bind := range sensitiveBinds {
		extracted = append(extracted, fmt.Sprintf("Bound identifier: %s", bind))
	}

	return []*output.ResultEvent{
		{
			ModuleID: ModuleID,
			Host:     urlx.Host,
			URL:      urlx.String(),
			Matched:  urlx.String(),
			ExtractedResults: extracted,
			Info: output.Info{
				Name:        "Server Action .bind() IDOR Risk",
				Description: fmt.Sprintf("Next.js Server Action at %s uses .bind() to pass %d sensitive identifier(s) without authorization checks, risking IDOR", urlx.Path, len(sensitiveBinds)),
				Severity:    severity.Medium,
				Confidence:  severity.Tentative,
				Tags:        []string{"idor", "server-action", "nextjs", "source-analysis"},
				Reference:   []string{"https://cwe.mitre.org/data/definitions/639.html"},
			},
			Metadata: map[string]any{
				"cwe":              "CWE-639",
				"boundIdentifiers": sensitiveBinds,
			},
		},
	}, nil
}
