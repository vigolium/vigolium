package cli

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// `vigolium schema storage` describes the store, not a -j document: its tables,
// their columns, what each table holds, and which -j field a column surfaces
// as. A reader that drops to sqlite3 used to rediscover all of it with
// `.tables` and `.schema http_records` on every session.

var schemaStorageCmd = &cobra.Command{
	Use:   "storage [table]",
	Short: "Describe the database: tables, columns, and the -j field each column surfaces as",
	Long: "List the tables of the database this invocation would read (the project DB, --db, or " +
		"$VIGOLIUM_DB_PATH) with their columns and row counts, what each table holds, and the -j field " +
		"name a column appears under where they differ (http_records.hostname is `host` in `traffic -j`). " +
		"Pass a table name to describe one. Prefer the read commands over raw SQL; this is the map for when " +
		"SQL is the only way.",
	Example: "  vigolium schema storage\n" +
		"  vigolium schema storage http_records -j\n" +
		"  vigolium schema storage --db scan.sqlite host_observations",
	Args: cobra.MaximumNArgs(1),
	RunE: runSchemaStorage,
}

func init() {
	schemaCmd.AddCommand(schemaStorageCmd)
}

// storageTablePurpose says what each table holds, for the tables a reader is
// likely to query. Tables not listed are described by their columns alone.
var storageTablePurpose = map[string]string{
	"http_records":          "Stored HTTP exchanges: one row per request/response, project-scoped (read with `vigolium traffic`)",
	"findings":              "Findings: one row per distinct issue, deduplicated by finding_hash (read with `vigolium finding`)",
	"finding_records":       "Which http_records evidence each finding",
	"finding_observations":  "Each scan that observed a finding (first/last seen history)",
	"finding_status_events": "Verdict history written by `vigolium finding mark`",
	"finding_hash_aliases":  "Old finding hashes (pre-identity-v2, or merged duplicates) and the finding that absorbed each",
	"scans":                 "Native scan runs: status, plan, phase outcomes, liveness",
	"agentic_scans":         "Agent runs (autopilot, swarm, audit)",
	"host_observations":     "Per host:port facts a run observed: DNS answers, TLS handshake and certificate, fingerprint and not-found baseline (read with `vigolium hosts`)",
	"projects":              "Projects; every scan row and record carries a project_uuid",
	"oast_interactions":     "Out-of-band callbacks received",
	"oast_payloads":         "Out-of-band payloads issued, for attributing callbacks",
	"schema_meta":           "The store's schema version and the binary that wrote it",
}

// storageJSONField maps a column to the -j field name it surfaces as, where the
// two differ. A column absent here keeps its name in -j (or is not surfaced).
var storageJSONField = map[string]map[string]string{
	"http_records": {"hostname": "host"},
	"host_observations": {
		"dns_a": "a", "dns_aaaa": "aaaa", "dns_cname": "cname", "dns_mx": "mx", "dns_ns": "ns",
		"dns_txt": "txt", "dns_soa": "soa", "dns_caa": "caa",
	},
}

// storageColumn is one column of a storageTable.
type storageColumn struct {
	Name      string `json:"name"`
	Type      string `json:"type"`
	Nullable  string `json:"nullable"`
	Default   string `json:"default,omitempty"`
	JSONField string `json:"json_field,omitempty"`
}

// storageTable is one `schema storage -j` row.
type storageTable struct {
	Table   string          `json:"table"`
	Purpose string          `json:"purpose,omitempty"`
	Rows    int64           `json:"rows"`
	Columns []storageColumn `json:"columns"`
}

func runSchemaStorage(cmd *cobra.Command, args []string) error {
	defer closeDatabaseOnExit()
	db, err := openReadDB(globDBSkipSet{})
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	ctx := context.Background()
	tables, err := database.ListTablesWithCounts(ctx, db)
	if err != nil {
		return fmt.Errorf("list tables: %w", err)
	}
	sort.Slice(tables, func(i, j int) bool { return tables[i].Name < tables[j].Name })

	if len(args) == 1 {
		want := strings.TrimSpace(args[0])
		var picked []database.TableInfo
		for _, t := range tables {
			if t.Name == want {
				picked = append(picked, t)
			}
		}
		if len(picked) == 0 {
			names := make([]string, 0, len(tables))
			for _, t := range tables {
				names = append(names, t.Name)
			}
			return usageErrorf("no table %q in this database; tables: %s", want, strings.Join(names, ", "))
		}
		tables = picked
	}

	out := make([]storageTable, 0, len(tables))
	for _, t := range tables {
		cols, err := database.ListColumns(ctx, db, t.Name)
		if err != nil {
			return fmt.Errorf("list columns of %s: %w", t.Name, err)
		}
		row := storageTable{Table: t.Name, Purpose: storageTablePurpose[t.Name], Rows: t.RowCount, Columns: make([]storageColumn, 0, len(cols))}
		for _, c := range cols {
			row.Columns = append(row.Columns, storageColumn{
				Name: c.Name, Type: c.Type, Nullable: c.Nullable, Default: c.Default,
				JSONField: storageJSONField[t.Name][c.Name],
			})
		}
		out = append(out, row)
	}

	if globalJSON {
		return emitRead(cmd, "", out, int64(len(out)), 0, len(out), withDBPath(resolvedReadDBPath()))
	}
	for i, t := range out {
		if i > 0 {
			fmt.Println()
		}
		fmt.Printf("%s  %s\n", terminal.BoldCyan(t.Table), terminal.Gray(fmt.Sprintf("(%d rows)", t.Rows)))
		if t.Purpose != "" {
			fmt.Printf("  %s\n", t.Purpose)
		}
		for _, c := range t.Columns {
			line := fmt.Sprintf("  %-28s %s", c.Name, c.Type)
			if c.JSONField != "" {
				line += terminal.Gray("  (-j: " + c.JSONField + ")")
			}
			fmt.Println(line)
		}
	}
	return nil
}
