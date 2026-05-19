package server_only_boundary_audit

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

// leakPattern defines a pattern indicating server-only code in client bundles.
type leakPattern struct {
	name     string
	re       *regexp.Regexp
	severity severity.Severity
	desc     string
}

var leakPatterns = []leakPattern{
	{
		name:     "Database Client (Prisma)",
		re:       regexp.MustCompile(`(?:new\s+PrismaClient|prismaClient|@prisma/client|from\s+['"]@prisma)`),
		severity: severity.High,
		desc:     "Prisma database client code found in client bundle, may expose database schema and connection details",
	},
	{
		name:     "Database Client (Drizzle)",
		re:       regexp.MustCompile(`(?:drizzle\s*\(|from\s+['"]drizzle-orm)`),
		severity: severity.High,
		desc:     "Drizzle ORM code found in client bundle, may expose database operations and schema",
	},
	{
		name:     "Database Client (Knex/Sequelize)",
		re:       regexp.MustCompile(`(?:knex\s*\(|from\s+['"]knex['"]|from\s+['"]sequelize['"]|new\s+Sequelize)`),
		severity: severity.High,
		desc:     "Database client code found in client bundle, may expose connection strings and queries",
	},
	{
		name:     "Internal API Endpoint",
		re:       regexp.MustCompile(`(?:https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|internal[.-]|\.internal[/'"]|\.local[/'"])[\w:/.?&=-]*)`),
		severity: severity.Medium,
		desc:     "Internal service URL found in client bundle, exposing internal infrastructure endpoints",
	},
	{
		name:     "Server Crypto Module",
		re:       regexp.MustCompile(`(?:from\s+['"](?:bcrypt|bcryptjs|argon2|scrypt)['"]|require\s*\(\s*['"](?:bcrypt|bcryptjs|argon2)['"])`),
		severity: severity.Medium,
		desc:     "Server-side cryptographic module found in client bundle, indicating improper boundary",
	},
	{
		name:     "JWT/Auth Library (Server)",
		re:       regexp.MustCompile(`(?:from\s+['"]jsonwebtoken['"]|jwt\.sign\s*\(|jwt\.verify\s*\(|from\s+['"]jose['"])`),
		severity: severity.High,
		desc:     "JWT signing/verification library found in client bundle, may expose signing keys",
	},
	{
		name:     "Node.js Filesystem Access",
		re:       regexp.MustCompile(`(?:require\s*\(\s*['"](?:fs|path|child_process)['"]|from\s+['"](?:node:fs|node:path|node:child_process)['"])`),
		severity: severity.High,
		desc:     "Node.js core module (fs/path/child_process) found in client bundle, indicating server code leak",
	},
	{
		name:     "Database Connection String",
		re:       regexp.MustCompile(`(?:(?:postgres|mysql|mongodb|redis)://[^\s'"]+@)`),
		severity: severity.Critical,
		desc:     "Database connection string with credentials found in client bundle",
	},
}

// Module implements the server-only boundary audit passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Server-Only Boundary Audit module.
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
		ds: dedup.LazyDiskSet("server_only_boundary_audit"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// CanProcess accepts JS responses under /_next/static/ paths (client bundles).
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Response() == nil {
		return false
	}
	if len(ctx.Response().Body()) == 0 {
		return false
	}

	u, err := ctx.URL()
	if err != nil {
		return false
	}

	pathLower := strings.ToLower(u.Path)

	// Only scan client-side bundles (/_next/static/)
	if !strings.Contains(pathLower, "/_next/static/") {
		return false
	}

	// Must be a JS file
	if !modkit.IsJSOrTSContentType(ctx.Response().Header("Content-Type")) && !modkit.HasJSExtension(pathLower) {
		return false
	}

	return true
}

// ScanPerRequest scans client bundles for server-only code leaks.
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

	var results []*output.ResultEvent

	for _, pat := range leakPatterns {
		match := pat.re.FindString(body)
		if match == "" {
			continue
		}

		results = append(results, &output.ResultEvent{
			ModuleID: ModuleID,
			Host:     urlx.Host,
			URL:      urlx.String(),
			Matched:  urlx.String(),
			ExtractedResults: []string{
				fmt.Sprintf("Leak: %s", pat.name),
				fmt.Sprintf("Matched: %s", modkit.Truncate(match, 120)),
			},
			Info: output.Info{
				Name:        fmt.Sprintf("Server Code Leak: %s", pat.name),
				Description: pat.desc,
				Severity:    pat.severity,
				Confidence:  severity.Tentative,
				Tags:        []string{"server-only", "boundary-violation", "nextjs", "information-disclosure"},
				Reference:   []string{"https://cwe.mitre.org/data/definitions/200.html"},
			},
			Metadata: map[string]any{
				"cwe":     "CWE-200",
				"pattern": pat.name,
			},
		})
	}

	return results, nil
}
