package database

import (
	"context"
	"testing"
)

// seedTwoHostSource writes a source holding the same shape of evidence about
// two hosts — app.example.com (stored with mixed case, to pin the
// case-insensitive match) and api.other.test — and returns its path.
//
// Per host: two http_records, one finding with its junction, observation,
// status event and hash alias, an OAST interaction on that finding, an
// oast_payload and an agentic_scans row targeting the host. Plus one finding
// with no hostname whose url is on app.example.com, one OAST interaction with
// no finding, and one scan.
func seedTwoHostSource(t *testing.T) string {
	t.Helper()
	const project = DefaultProjectUUID
	src, srcPath := newFileDB(t, "src.sqlite")
	mustExec(t, src, `INSERT INTO scans (uuid, project_uuid, status, target) VALUES ('scan-1', ?, 'completed', 'https://app.example.com')`, project)

	type hostSeed struct{ key, stored, scheme string }
	for _, h := range []hostSeed{
		{"a", "App.Example.com", "https"},
		{"b", "api.other.test", "http"},
	} {
		port := 443
		if h.scheme == "http" {
			port = 80
		}
		for _, n := range []string{"1", "2"} {
			uuid := "rec-" + h.key + n
			mustExec(t, src, `INSERT INTO http_records
				(uuid, project_uuid, scheme, hostname, port, method, path, url, http_version, request_hash)
				VALUES (?, ?, ?, ?, ?, 'GET', ?, ?, 'HTTP/1.1', ?)`,
				uuid, project, h.scheme, h.stored, port, "/"+uuid, h.scheme+"://"+h.stored+"/"+uuid, "rh-"+uuid)
		}
		res := mustExec(t, src, `INSERT INTO findings
			(project_uuid, http_record_uuids, url, hostname, module_id, module_name, severity, finding_hash)
			VALUES (?, ?, ?, ?, 'xss', 'XSS', 'high', ?)`,
			project, `["rec-`+h.key+`1"]`, h.scheme+"://"+h.stored+"/rec-"+h.key+"1", h.stored, "fh-"+h.key)
		fid, err := res.LastInsertId()
		if err != nil {
			t.Fatalf("LastInsertId: %v", err)
		}
		mustExec(t, src, `INSERT INTO finding_records (finding_id, record_uuid) VALUES (?, ?)`, fid, "rec-"+h.key+"1")
		mustExec(t, src, `INSERT INTO finding_observations (project_uuid, finding_id, finding_hash, scan_uuid) VALUES (?, ?, ?, 'scan-1')`, project, fid, "fh-"+h.key)
		mustExec(t, src, `INSERT INTO finding_status_events (finding_id, project_uuid, to_status) VALUES (?, ?, 'confirmed')`, fid, project)
		mustExec(t, src, `INSERT INTO finding_hash_aliases (project_uuid, alias_hash, finding_id) VALUES (?, ?, ?)`, project, "alias-"+h.key, fid)
		mustExec(t, src, `INSERT INTO oast_interactions
			(project_uuid, unique_id, full_id, protocol, interacted_at, finding_id)
			VALUES (?, ?, ?, 'dns', CURRENT_TIMESTAMP, ?)`, project, "uid-"+h.key, "uid-"+h.key+".oast", fid)
		mustExec(t, src, `INSERT INTO oast_payloads (nonce, project_uuid, target_url) VALUES (?, ?, ?)`,
			"nonce-"+h.key, project, h.scheme+"://"+h.stored+"/p")
		mustExec(t, src, `INSERT INTO agentic_scans (uuid, project_uuid, mode, agent_name, status, target_url) VALUES (?, ?, 'autopilot', 'olium', 'completed', ?)`,
			"run-"+h.key, project, h.scheme+"://"+h.stored)
	}
	// A finding with no hostname column value: decided by its url.
	mustExec(t, src, `INSERT INTO findings
		(project_uuid, http_record_uuids, url, module_id, module_name, severity, finding_hash)
		VALUES (?, '[]', 'https://app.example.com/nohost', 'sqli', 'SQLi', 'high', 'fh-nohost')`, project)
	// An interaction attributed to no finding names no host.
	mustExec(t, src, `INSERT INTO oast_interactions
		(project_uuid, unique_id, full_id, protocol, interacted_at)
		VALUES (?, 'uid-orphan', 'uid-orphan.oast', 'dns', CURRENT_TIMESTAMP)`, project)
	// A payload with no target_url names no host either.
	mustExec(t, src, `INSERT INTO oast_payloads (nonce, project_uuid) VALUES ('nonce-none', ?)`, project)
	if err := src.Close(); err != nil {
		t.Fatalf("close src: %v", err)
	}
	return srcPath
}

// TestMergeSQLiteFile_HostFilter pins MergeOptions.Hosts: only rows about a
// filtered host cross, the finding side tables follow their findings, and an
// empty filter copies exactly what an unfiltered merge does.
func TestMergeSQLiteFile_HostFilter(t *testing.T) {
	type want struct {
		records, findings, junction, observations, statusEvents, aliases int64
		oast, payloads, agentic                                          int64
		hostsIn                                                          []string // lower-cased hostnames that must be present
	}
	appOnly := want{
		records: 2, findings: 2, junction: 1, observations: 1, statusEvents: 1, aliases: 1,
		oast: 1, payloads: 1, agentic: 1,
		hostsIn: []string{"app.example.com"},
	}
	for _, tc := range []struct {
		name  string
		hosts []string
		want  want
	}{
		{"exact host", []string{"app.example.com"}, appOnly},
		{"case-insensitive", []string{"APP.EXAMPLE.COM"}, appOnly},
		{"wildcard", []string{"*.example.com"}, appOnly},
		{"origin with port", []string{"https://app.example.com:443"}, appOnly},
		{"port that matches nothing", []string{"app.example.com:8443"}, want{}},
		{"both hosts", []string{"app.example.com", "*.other.test"}, want{
			records: 4, findings: 3, junction: 2, observations: 2, statusEvents: 2, aliases: 2,
			oast: 2, payloads: 2, agentic: 2,
			hostsIn: []string{"app.example.com", "api.other.test"},
		}},
		{"no match", []string{"nowhere.invalid"}, want{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			srcPath := seedTwoHostSource(t)
			dest, _ := newFileDB(t, "dest.sqlite")
			stats, err := MergeSQLiteFileWithOptions(ctx, dest, srcPath, MergeOptions{Hosts: tc.hosts})
			if err != nil {
				t.Fatalf("merge: %v", err)
			}
			w := tc.want
			for _, c := range []struct {
				what string
				q    string
				want int64
			}{
				{"http_records", `SELECT COUNT(*) FROM http_records`, w.records},
				{"findings", `SELECT COUNT(*) FROM findings`, w.findings},
				{"finding_records", `SELECT COUNT(*) FROM finding_records`, w.junction},
				{"finding_observations", `SELECT COUNT(*) FROM finding_observations`, w.observations},
				{"finding_status_events", `SELECT COUNT(*) FROM finding_status_events`, w.statusEvents},
				{"finding_hash_aliases", `SELECT COUNT(*) FROM finding_hash_aliases`, w.aliases},
				{"oast_interactions", `SELECT COUNT(*) FROM oast_interactions`, w.oast},
				{"oast_payloads", `SELECT COUNT(*) FROM oast_payloads`, w.payloads},
				{"agentic_scans", `SELECT COUNT(*) FROM agentic_scans`, w.agentic},
				// Run metadata copies regardless of the filter.
				{"scans", `SELECT COUNT(*) FROM scans WHERE uuid = 'scan-1'`, 1},
			} {
				if got := scalarInt(t, dest, c.q); got != c.want {
					t.Errorf("%s = %d, want %d", c.what, got, c.want)
				}
			}
			if int64(stats.RecordsMerged) != w.records || int64(stats.FindingsMerged) != w.findings || int64(stats.OASTMerged) != w.oast {
				t.Errorf("stats disagree with the rows: %+v", stats)
			}
			for _, h := range w.hostsIn {
				if got := scalarInt(t, dest, `SELECT COUNT(*) FROM http_records WHERE LOWER(hostname) = ?`, h); got != 2 {
					t.Errorf("records for %s = %d, want 2", h, got)
				}
			}
			// Nothing about a host outside the filter crosses, in any table that
			// names one.
			if len(w.hostsIn) == 1 {
				if got := scalarInt(t, dest, `SELECT COUNT(*) FROM http_records WHERE hostname = 'api.other.test'`); got != 0 {
					t.Errorf("other host's records crossed: %d", got)
				}
				if got := scalarInt(t, dest, `SELECT COUNT(*) FROM findings WHERE hostname = 'api.other.test' OR finding_hash = 'fh-b'`); got != 0 {
					t.Errorf("other host's findings crossed: %d", got)
				}
				// The copied interaction is the one on the copied finding, relinked.
				if got := scalarInt(t, dest, `SELECT COUNT(*) FROM oast_interactions o JOIN findings f ON f.id = o.finding_id WHERE f.finding_hash = 'fh-a'`); got != 1 {
					t.Errorf("oast interaction not relinked to the copied finding: %d", got)
				}
			}
		})
	}
}

// TestMergeSQLiteFile_HostFilterEmptyIsUnfiltered pins that an empty Hosts
// copies exactly what an unfiltered merge does.
func TestMergeSQLiteFile_HostFilterEmptyIsUnfiltered(t *testing.T) {
	ctx := context.Background()
	counts := func(opts MergeOptions) MergeStats {
		srcPath := seedTwoHostSource(t)
		dest, _ := newFileDB(t, "dest.sqlite")
		stats, err := MergeSQLiteFileWithOptions(ctx, dest, srcPath, opts)
		if err != nil {
			t.Fatalf("merge: %v", err)
		}
		if got := scalarInt(t, dest, `SELECT COUNT(*) FROM oast_payloads`); got != 3 {
			t.Fatalf("oast_payloads = %d, want 3 (every row, the target-less one included)", got)
		}
		return *stats
	}
	plain, empty := counts(MergeOptions{}), counts(MergeOptions{Hosts: []string{}})
	if plain != empty {
		t.Fatalf("empty Hosts changed the merge:\n plain %+v\n empty %+v", plain, empty)
	}
	if plain.RecordsMerged != 4 || plain.FindingsMerged != 3 || plain.OASTMerged != 3 || plain.AgenticScansMerged != 2 {
		t.Fatalf("unfiltered merge copied %+v", plain)
	}
}

// TestMergeSQLiteFile_HostFilterWithSkipFindings pins the two options
// together: one host's records, and no finding corpus at all.
func TestMergeSQLiteFile_HostFilterWithSkipFindings(t *testing.T) {
	ctx := context.Background()
	srcPath := seedTwoHostSource(t)
	dest, _ := newFileDB(t, "dest.sqlite")
	stats, err := MergeSQLiteFileWithOptions(ctx, dest, srcPath, MergeOptions{
		Hosts:        []string{"*.example.com"},
		SkipFindings: true,
	})
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if stats.RecordsMerged != 2 || stats.FindingsMerged != 0 || stats.OASTMerged != 0 {
		t.Fatalf("stats = %+v, want 2 records and no findings/OAST", stats)
	}
	if got := scalarInt(t, dest, `SELECT COUNT(*) FROM http_records WHERE LOWER(hostname) = 'app.example.com'`); got != 2 {
		t.Fatalf("filtered host's records = %d, want 2", got)
	}
	for _, table := range []string{"findings", "finding_records", "finding_observations", "finding_status_events", "oast_interactions"} {
		if got := scalarInt(t, dest, `SELECT COUNT(*) FROM `+table); got != 0 {
			t.Errorf("%s = %d, want 0 under SkipFindings", table, got)
		}
	}
}

// TestMergeSQLiteFile_HostFilterRefusesEmptyEntry pins that an entry naming no
// host fails the merge instead of silently widening it to every host.
func TestMergeSQLiteFile_HostFilterRefusesEmptyEntry(t *testing.T) {
	ctx := context.Background()
	srcPath := seedTwoHostSource(t)
	dest, _ := newFileDB(t, "dest.sqlite")
	if _, err := MergeSQLiteFileWithOptions(ctx, dest, srcPath, MergeOptions{Hosts: []string{"  "}}); err == nil {
		t.Fatal("a blank host entry merged; want an error")
	}
	if got := scalarInt(t, dest, `SELECT COUNT(*) FROM http_records`); got != 0 {
		t.Fatalf("refused merge still copied %d records", got)
	}
}

func TestGlobMatch(t *testing.T) {
	for _, tc := range []struct {
		pattern, s string
		want       bool
	}{
		{"a.example.com", "a.example.com", true},
		{"a.example.com", "b.example.com", false},
		{"*.example.com", "a.b.example.com", true},
		{"*.example.com", "example.com", false},
		{"*.example.com", "a.example.com.evil", false},
		{"api*", "api.example.com", true},
		{"a*c*e", "abcde", true},
		{"a*c*e", "abde", false},
		{"*", "anything", true},
	} {
		if got := globMatch(tc.pattern, tc.s); got != tc.want {
			t.Errorf("globMatch(%q, %q) = %v, want %v", tc.pattern, tc.s, got, tc.want)
		}
	}
}
