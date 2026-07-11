package server_only_boundary_audit

import (
	"fmt"
	"net/url"
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
		re:       regexp.MustCompile(`(?:(?:postgres|mysql|mongodb|redis)://[^:\s/'"]+:[^@\s/'"]+@[^\s'"]+)`),
		severity: severity.High,
		desc:     "Credential-shaped database connection URI found in a client bundle; provider validity was not tested",
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
	var diskSet *dedup.DiskSet
	if scanCtx != nil {
		diskSet = m.ds.Get(scanCtx.DedupMgr())
	}
	dedupKey := utils.Sha1(fmt.Sprintf("%s%s", urlx.Host, urlx.Path))
	if diskSet != nil && diskSet.IsSeen(dedupKey) {
		return nil, nil
	}

	body := ctx.Response().BodyToString()

	// Collect every matched server-only pattern first.
	type hit struct {
		pat   leakPattern
		match string
	}
	var hits []hit
	for _, pat := range leakPatterns {
		if match := pat.re.FindString(body); match != "" {
			if pat.name == "Database Connection String" && !connectionStringSubstantive(match) {
				continue
			}
			hits = append(hits, hit{pat: pat, match: match})
		}
	}
	if len(hits) == 0 {
		return nil, nil
	}

	// Strict drop-on-fail: a single weak pattern (a Prisma/Drizzle/knex import, a
	// localhost URL, a crypto-module reference) frequently appears as an incidental
	// string literal inside a minified vendor bundle and is not, on its own,
	// evidence of a server/client boundary violation. Require corroboration: at
	// least two DISTINCT server-only signals in the same bundle. The sole
	// exception is a database connection string with embedded credentials, which
	// is unambiguous on its own.
	corroborated := len(hits) >= 2

	var results []*output.ResultEvent
	for _, h := range hits {
		if !corroborated && !isSelfConfident(h.pat.name) {
			continue
		}
		results = append(results, &output.ResultEvent{
			ModuleID:      ModuleID,
			RecordKind:    output.RecordKindCandidate,
			EvidenceGrade: output.EvidenceGradeCandidate,
			Host:          urlx.Host,
			URL:           urlx.String(),
			Matched:       urlx.String(),
			ExtractedResults: []string{
				fmt.Sprintf("Leak: %s", h.pat.name),
				fmt.Sprintf("Matched: %s", modkit.Truncate(h.match, 120)),
			},
			Info: output.Info{
				Name:        fmt.Sprintf("Server-Boundary Candidate: %s", h.pat.name),
				Description: h.pat.desc + ". Module/import strings do not prove executable server code or secret use in the client runtime.",
				Severity:    h.pat.severity,
				Confidence:  severity.Tentative,
				Tags:        []string{"server-only", "boundary-violation", "nextjs", "information-disclosure"},
				Reference:   []string{"https://cwe.mitre.org/data/definitions/200.html"},
			},
			Metadata: map[string]any{
				"cwe":                  "CWE-200",
				"pattern":              h.pat.name,
				"runtime_reachability": false,
				"credential_validated": false,
			},
		})
	}

	return results, nil
}

// isSelfConfident reports whether a pattern is unambiguous enough to report on
// its own (without a second corroborating server-only signal in the bundle).
func isSelfConfident(name string) bool {
	return name == "Database Connection String"
}

func connectionStringSubstantive(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.User == nil || parsed.Host == "" {
		return false
	}
	username := strings.TrimSpace(parsed.User.Username())
	password, hasPassword := parsed.User.Password()
	password = strings.TrimSpace(password)
	if username == "" || !hasPassword || len(password) < 8 {
		return false
	}
	if modkit.IsPlaceholderValue(username) || modkit.IsPlaceholderValue(password) {
		return false
	}
	lower := strings.ToLower(username + ":" + password + "@" + parsed.Host)
	for _, placeholder := range []string{"example", "placeholder", "changeme", "your_", "your-", "dummy", "sample", "redacted"} {
		if strings.Contains(lower, placeholder) {
			return false
		}
	}
	return true
}
