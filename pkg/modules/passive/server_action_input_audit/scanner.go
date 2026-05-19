package server_action_input_audit

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

	// Patterns indicating the action processes user input
	formDataAccessRe = regexp.MustCompile(`formData\.get\s*\(|formData\.getAll\s*\(|formData\.entries\s*\(|formData\.has\s*\(`)
	// Patterns indicating user input is used in sensitive operations
	dbWriteRe = regexp.MustCompile(`\.create\s*\(|\.update\s*\(|\.delete\s*\(|\.insert\s*\(|\.upsert\s*\(|\.save\s*\(|\.execute\s*\(|prisma\.|db\.|\.query\s*\(|\.run\s*\(`)

	// Patterns indicating runtime validation is present
	validationRe = regexp.MustCompile(
		`z\.(?:parse|safeParse|object|string|number|array|enum|union|intersection|literal|nativeEnum|coerce)` +
			`|\.parse\s*\(|\.safeParse\s*\(|\.parseAsync\s*\(` +
			`|yup\.(?:object|string|number|array|mixed|reach)` +
			`|Joi\.(?:object|string|number|array|any|alternatives)` +
			`|joi\.(?:object|string|number|array|any|alternatives)` +
			`|\.validate\s*\(|\.validateSync\s*\(|\.validateAsync\s*\(` +
			`|valibot\.|v\.(?:parse|safeParse|object|string|number)` +
			`|superstruct|assert\s*\(|create\s*\(\s*\w+\s*,\s*\w+Schema`,
	)
)

// Module implements the Server Action input audit passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Server Action Input Audit module.
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
		ds: dedup.LazyDiskSet("server_action_input_audit"),
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

// ScanPerRequest scans for Server Actions missing input validation.
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

	// Step 1: Must contain "use server" directive
	if !useServerRe.MatchString(body) {
		return nil, nil
	}

	// Step 2: Must process user input (FormData access or DB writes with arguments)
	hasFormData := formDataAccessRe.MatchString(body)
	hasDBWrite := dbWriteRe.MatchString(body)

	if !hasFormData && !hasDBWrite {
		return nil, nil
	}

	// Step 3: Check for validation library patterns - if present, no issue
	if validationRe.MatchString(body) {
		return nil, nil
	}

	// Build findings
	extracted := []string{"Server Action with 'use server' directive lacks runtime input validation"}

	if hasFormData {
		matches := formDataAccessRe.FindAllString(body, 5)
		seen := make(map[string]bool)
		for _, match := range matches {
			trimmed := strings.TrimSpace(match)
			if !seen[trimmed] {
				extracted = append(extracted, fmt.Sprintf("Raw input access: %s", trimmed))
				seen[trimmed] = true
			}
		}
	}

	if hasDBWrite {
		matches := dbWriteRe.FindAllString(body, 5)
		seen := make(map[string]bool)
		for _, match := range matches {
			trimmed := strings.TrimSpace(match)
			if !seen[trimmed] {
				extracted = append(extracted, fmt.Sprintf("DB operation: %s", trimmed))
				seen[trimmed] = true
			}
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
				Name:        "Server Action Missing Input Validation",
				Description: fmt.Sprintf("Next.js Server Action at %s processes user input without runtime schema validation (zod/yup/joi/valibot)", urlx.Path),
				Severity:    severity.Medium,
				Confidence:  severity.Tentative,
				Tags:        []string{"input-validation", "server-action", "nextjs", "source-analysis"},
				Reference:   []string{"https://cwe.mitre.org/data/definitions/20.html"},
			},
			Metadata: map[string]any{
				"cwe":         "CWE-20",
				"hasFormData": hasFormData,
				"hasDBWrite":  hasDBWrite,
			},
		},
	}, nil
}
