package cli

import (
	"context"
	"io"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/database"
)

// harSample / openAPISample / etc. are the smallest inputs that trip each
// format's content signature.
const (
	harSample = `{"log":{"version":"1.2","entries":[` +
		`{"request":{"method":"GET","url":"https://acme.test/api/users"},` +
		`"response":{"status":200,"content":{"text":"[]"}}}]}}`

	openAPIJSONSample = `{"openapi":"3.0.0","info":{"title":"x","version":"1"},` +
		`"paths":{"/pets":{"get":{"responses":{"200":{"description":"ok"}}}}}}`

	openAPIYAMLSample = "openapi: 3.0.0\ninfo:\n  title: x\n  version: '1'\npaths:\n  /pets:\n    get:\n      responses: {}\n"

	postmanSample = `{"info":{"_postman_id":"abc","name":"c","schema":"https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},` +
		`"item":[{"name":"r","request":{"method":"GET","url":"https://acme.test/x"}}]}`

	burpXMLSample = `<?xml version="1.0"?>` + "\n" + `<items><item><request base64="false">GET / HTTP/1.1</request></item></items>`

	curlSample    = "curl 'https://acme.test/login' -X POST --data 'u=a&p=b'\n"
	rawHTTPSample = "GET /admin HTTP/1.1\r\nHost: acme.test\r\n\r\n"
	urlListSample = "https://acme.test/a\nhttps://acme.test/b\n# a comment\n"
	proseSample   = "# Auth model\n\nThree roles: guest, user, admin. Log in at /login.\n"
)

func TestKBTrafficFormat_Detection(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name     string
		rel      string
		content  string
		wantFmt  string
		wantIsTr bool
	}{
		{"har by ext", "flows.har", harSample, "har", true},
		{"har by content json ext", "capture.json", harSample, "har", true},
		{"openapi json", "api.json", openAPIJSONSample, "openapi", true},
		{"openapi yaml", "api.yaml", openAPIYAMLSample, "openapi", true},
		{"postman", "collection.json", postmanSample, "postman", true},
		{"burp xml", "session.xml", burpXMLSample, "burpxml", true},
		{"curl by ext", "login.curl", curlSample, "curl", true},
		{"curl by content in txt", "login.txt", curlSample, "curl", true},
		{"raw http by ext", "req.http", rawHTTPSample, "burpraw", true},
		{"raw http by content in txt", "req.txt", rawHTTPSample, "burpraw", true},
		{"url list by ext", "targets.urls", urlListSample, "urls", true},
		{"url list in txt", "targets.txt", urlListSample, "urls", true},
		// Prose must NOT be misread as traffic.
		{"prose md", "auth.md", proseSample, "", false},
		{"prose txt", "notes.txt", "Plain notes about the app, nothing structured here.\n", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := writeKBFile(t, dir, c.rel, c.content)
			gotFmt, gotOK := kbTrafficFormat(p)
			require.Equal(t, c.wantIsTr, gotOK, "detection mismatch for %s", c.rel)
			if c.wantIsTr {
				require.Equal(t, c.wantFmt, gotFmt)
			}
		})
	}
}

func TestKBTrafficFormat_BinaryAndEmpty(t *testing.T) {
	dir := t.TempDir()
	// A NUL-laden "har" is binary — not parseable traffic.
	bin := writeKBFile(t, dir, "blob.har", "\x00\x01\x02\"entries\"\x00")
	_, ok := kbTrafficFormat(bin)
	require.False(t, ok)

	empty := writeKBFile(t, dir, "empty.har", "")
	_, ok = kbTrafficFormat(empty)
	require.False(t, ok)
}

func TestGatherKnowledgeBaseTrafficFiles_MixedDir(t *testing.T) {
	dir := t.TempDir()
	writeKBFile(t, dir, "docs/auth.md", proseSample)           // prose — excluded
	writeKBFile(t, dir, "captures/flows.har", harSample)       // traffic
	writeKBFile(t, dir, "captures/login.curl", curlSample)     // traffic
	writeKBFile(t, dir, "api/openapi.yaml", openAPIYAMLSample) // traffic
	writeKBFile(t, dir, "notes.txt", "just prose here")        // prose — excluded
	writeKBFile(t, dir, "node_modules/x/skip.har", harSample)  // skipped dir

	root, files, err := gatherKnowledgeBaseTrafficFiles(dir)
	require.NoError(t, err)
	require.Equal(t, dir, root)

	got := make([]string, len(files))
	byRel := map[string]string{}
	for i, f := range files {
		got[i] = f.RelPath
		byRel[f.RelPath] = f.Format
		require.True(t, filepath.IsAbs(f.AbsPath))
	}
	sort.Strings(got)
	require.Equal(t, []string{"api/openapi.yaml", "captures/flows.har", "captures/login.curl"}, got)
	require.Equal(t, "har", byRel["captures/flows.har"])
	require.Equal(t, "curl", byRel["captures/login.curl"])
	require.Equal(t, "openapi", byRel["api/openapi.yaml"])
}

func TestGatherKnowledgeBaseTrafficFiles_SingleFile(t *testing.T) {
	dir := t.TempDir()
	p := writeKBFile(t, dir, "flows.har", harSample)
	root, files, err := gatherKnowledgeBaseTrafficFiles(p)
	require.NoError(t, err)
	require.Equal(t, p, root)
	require.Len(t, files, 1)
	require.Equal(t, "har", files[0].Format)

	// A single prose file yields no traffic files (and no error).
	pp := writeKBFile(t, dir, "auth.md", proseSample)
	_, files2, err := gatherKnowledgeBaseTrafficFiles(pp)
	require.NoError(t, err)
	require.Empty(t, files2)
}

// TestGatherKnowledgeBaseDocs_RouteTrafficExcludesCaptures verifies that when
// traffic routing is on, a curl/URL-list .txt is dropped from the prose corpus
// (it will be ingested as records instead), while a genuine prose .txt stays.
func TestGatherKnowledgeBaseDocs_RouteTrafficExcludesCaptures(t *testing.T) {
	dir := t.TempDir()
	writeKBFile(t, dir, "auth.md", proseSample)          // prose — kept
	writeKBFile(t, dir, "notes.txt", "Plain notes only") // prose — kept
	writeKBFile(t, dir, "login.txt", curlSample)         // traffic-shaped — dropped when routing
	writeKBFile(t, dir, "flows.har", harSample)          // non-text ext — never in prose either way

	// routeTraffic = true: curl.txt excluded.
	_, docs, _, err := gatherKnowledgeBaseDocs(dir, true)
	require.NoError(t, err)
	got := docPaths(docs)
	require.Equal(t, []string{"auth.md", "notes.txt"}, got)

	// routeTraffic = false (--knowledge-base-no-traffic): every text file stays,
	// including the curl-shaped .txt, so nothing is silently lost.
	_, docs2, _, err := gatherKnowledgeBaseDocs(dir, false)
	require.NoError(t, err)
	require.Equal(t, []string{"auth.md", "login.txt", "notes.txt"}, docPaths(docs2))
}

// TestIngestKnowledgeBaseTraffic_EndToEnd parses a mixed KB directory into the
// project DB and checks that (a) records land as source=knowledge-base and
// (b) the returned brief section carries the directive + a sample table.
func TestIngestKnowledgeBaseTraffic_EndToEnd(t *testing.T) {
	ctx := context.Background()
	const project = "proj-kb-traffic"
	db := newExportTestDB(t)
	repo := database.NewRepository(db)

	dir := t.TempDir()
	writeKBFile(t, dir, "docs/auth.md", proseSample)       // prose — not ingested
	writeKBFile(t, dir, "captures/flows.har", harSample)   // 1 record
	writeKBFile(t, dir, "captures/login.curl", curlSample) // 1 record

	section, saved := ingestKnowledgeBaseTraffic(ctx, repo, project, dir, io.Discard)
	require.Greater(t, saved, 0, "expected records to be saved")

	// Records persisted under the knowledge-base source.
	var count int
	require.NoError(t, repo.DB().NewSelect().
		Table("http_records").
		ColumnExpr("COUNT(*)").
		Where("project_uuid = ?", project).
		Where("source = ?", kbTrafficSource).
		Scan(ctx, &count))
	require.Equal(t, saved, count)

	// Section is actionable: directive + provenance + a sample table.
	require.Contains(t, section, "## Seed traffic from knowledge base")
	require.Contains(t, section, "source=knowledge-base")
	require.Contains(t, section, "query_records --source knowledge-base")
	require.Contains(t, section, "captures/flows.har")
	require.Contains(t, section, "captures/login.curl")
	require.Contains(t, section, "| Method | Status | URL |")

	// A KB directory with no traffic files ingests nothing and returns no section.
	proseOnly := t.TempDir()
	writeKBFile(t, proseOnly, "auth.md", proseSample)
	sec2, saved2 := ingestKnowledgeBaseTraffic(ctx, repo, project, proseOnly, io.Discard)
	require.Equal(t, 0, saved2)
	require.Empty(t, sec2)

	// A nil repo is a hard no-op (records would have nowhere to land).
	sec3, saved3 := ingestKnowledgeBaseTraffic(ctx, nil, project, dir, io.Discard)
	require.Equal(t, 0, saved3)
	require.Empty(t, sec3)
}

func docPaths(docs []kbDoc) []string {
	out := make([]string, len(docs))
	for i, d := range docs {
		out[i] = d.RelPath
	}
	sort.Strings(out)
	return out
}
