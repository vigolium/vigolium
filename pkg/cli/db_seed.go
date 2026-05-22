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

func hashStr(data []byte) string {
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h[:16]) // 32 hex chars
}
