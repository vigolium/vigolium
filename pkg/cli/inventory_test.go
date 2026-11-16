package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/contract/contracttest"
	"github.com/vigolium/vigolium/pkg/database"
)

func newInventoryTestDB(t *testing.T) *database.DB {
	t.Helper()
	cfg := config.DefaultDatabaseConfig()
	cfg.SQLite.Path = filepath.Join(t.TempDir(), "inventory.sqlite")
	db, err := database.NewDB(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	require.NoError(t, db.CreateSchema(context.Background()))
	return db
}

func seedInventoryRecord(t *testing.T, db *database.DB, uuid, project, scan, method, path, raw string, params ...database.EmbeddedParam) *database.HTTPRecord {
	t.Helper()
	rec := &database.HTTPRecord{
		UUID: uuid, ProjectUUID: project, ScanUUID: scan,
		Scheme: "https", Hostname: "shop.test", Port: 8443,
		Method: method, Path: path, URL: "https://shop.test:8443" + path,
		HTTPVersion: "HTTP/1.1", RequestHash: uuid, StatusCode: 200, HasResponse: true,
		RawRequest: []byte(raw), Parameters: params,
		CreatedAt: time.Now(), SentAt: time.Now(),
	}
	_, err := db.NewInsert().Model(rec).Exec(context.Background())
	require.NoError(t, err)
	return rec
}

// withJSON turns -j on for one test.
func withJSON(t *testing.T) {
	t.Helper()
	prev := globalJSON
	globalJSON = true
	t.Cleanup(func() { globalJSON = prev })
}

type testEnvelope struct {
	Command string            `json:"command"`
	Kind    string            `json:"kind"`
	OK      bool              `json:"ok"`
	Total   int64             `json:"total"`
	Items   []json.RawMessage `json:"items"`
	Query   string            `json:"query"`

	Provenance string `json:"provenance_warning"`
	Records    int64  `json:"records_scanned"`
}

func decodeEnvelope(t *testing.T, out string) testEnvelope {
	t.Helper()
	var env testEnvelope
	require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(out)), &env), out)
	return env
}

func TestEndpointsJSONEnvelope(t *testing.T) {
	db := newInventoryTestDB(t)
	for i := 1; i <= 3; i++ {
		seedInventoryRecord(t, db, fmt.Sprintf("r%d", i), "p1", "scan-1", "GET", fmt.Sprintf("/users/%d?tab=x", i),
			fmt.Sprintf("GET /users/%d?tab=x HTTP/1.1\r\nHost: shop.test:8443\r\n\r\n", i),
			database.EmbeddedParam{Name: "tab", Value: "x", Type: "url"})
	}
	seedInventoryRecord(t, db, "other", "p2", "", "GET", "/secret", "GET /secret HTTP/1.1\r\n\r\n")
	withJSON(t)
	endpointsFlags.limit = 100

	out := captureStdout(t, func() {
		require.NoError(t, renderEndpoints(context.Background(), endpointsCmd, db, database.QueryFilters{ProjectUUID: "p1"}, "console"))
	})
	env := decodeEnvelope(t, out)
	contracttest.Validate(t, "endpoints", []byte(out))
	require.Equal(t, "endpoints", env.Command)
	require.Equal(t, "read", env.Kind)
	require.True(t, env.OK)
	require.EqualValues(t, 1, env.Total, "the other project's record must not appear")
	require.EqualValues(t, 3, env.Records)
	var ep database.EndpointView
	require.NoError(t, json.Unmarshal(env.Items[0], &ep))
	require.Equal(t, "https://shop.test:8443", ep.Origin)
	require.Equal(t, "/users/{int}", ep.Template)
	require.Contains(t, env.Query, "traffic --host shop.test --path '/users/*'")
}

func TestEndpointsScanProvenanceWarning(t *testing.T) {
	db := newInventoryTestDB(t)
	repo := database.NewRepository(db)
	ctx := context.Background()
	require.NoError(t, repo.CreateScan(ctx, &database.Scan{UUID: "old-scan", ProjectUUID: "p1", Status: "completed", StartedAt: time.Now().Add(-time.Hour)}))
	seedInventoryRecord(t, db, "r1", "p1", "", "GET", "/a", "GET /a HTTP/1.1\r\n\r\n") // unstamped
	withJSON(t)

	out := captureStdout(t, func() {
		require.NoError(t, renderEndpoints(ctx, endpointsCmd, db, database.QueryFilters{ProjectUUID: "p1", ScanUUID: "old-scan"}, "console"))
	})
	require.Equal(t, provenanceScanNotStamped, decodeEnvelope(t, out).Provenance)
	contracttest.Validate(t, "endpoints", []byte(out))

	code, _ := scanProvenanceWarning(ctx, db, "p1", "missing-scan")
	require.Equal(t, provenanceScanNotFound, code)

	// A scan that stamped records: an empty filtered read is not a provenance gap.
	require.NoError(t, repo.CreateScan(ctx, &database.Scan{UUID: "new-scan", ProjectUUID: "p1", Status: "completed", StartedAt: time.Now()}))
	seedInventoryRecord(t, db, "r2", "p1", "new-scan", "GET", "/b", "GET /b HTTP/1.1\r\n\r\n")
	code, _ = scanProvenanceWarning(ctx, db, "p1", "new-scan")
	require.Empty(t, code)
}

func TestParamsJSONRedactsByDefault(t *testing.T) {
	db := newInventoryTestDB(t)
	seedInventoryRecord(t, db, "r1", "p1", "", "POST", "/login", "POST /login HTTP/1.1\r\n\r\n",
		database.EmbeddedParam{Name: "password", Value: "hunter2", Type: "body"},
		database.EmbeddedParam{Name: "user", Value: "alice", Type: "body"})
	withJSON(t)
	paramsFlags.limit = 100
	prevShow := paramsShowValues
	t.Cleanup(func() { paramsShowValues = prevShow })
	paramsShowValues = false

	out := captureStdout(t, func() {
		require.NoError(t, renderParams(context.Background(), paramsCmd, db, database.QueryFilters{ProjectUUID: "p1"}, "console"))
	})
	require.NotContains(t, out, "hunter2")
	env := decodeEnvelope(t, out)
	contracttest.Validate(t, "params", []byte(out))
	require.Equal(t, "params", env.Command)
	require.EqualValues(t, 2, env.Total)
	require.Contains(t, out, `"alice"`)
}

func TestInventoryFlagValidation(t *testing.T) {
	var ue usageError
	prevSort, prevCollapse := endpointsSort, endpointsCollapse
	t.Cleanup(func() { endpointsSort, endpointsCollapse = prevSort, prevCollapse })

	endpointsSort, endpointsCollapse = "nope", 0
	require.True(t, errors.As(validateEndpointsFlags(), &ue), "unknown --sort is a usage error")
	endpointsSort, endpointsCollapse = "records", 1
	require.True(t, errors.As(validateEndpointsFlags(), &ue), "--collapse 1 is a usage error")
	endpointsCollapse = 3
	require.NoError(t, validateEndpointsFlags())

	prevLoc, prevTypes := paramsLocations, paramsTypes
	t.Cleanup(func() { paramsLocations, paramsTypes = prevLoc, prevTypes })
	paramsLocations, paramsTypes = []string{"querystring"}, nil
	require.True(t, errors.As(validateParamsFlags(), &ue))
	paramsLocations, paramsTypes = []string{"query"}, []string{"int"}
	require.True(t, errors.As(validateParamsFlags(), &ue), "--type must name a mutation value type")
	paramsTypes = []string{"integer", "uuid"}
	require.NoError(t, validateParamsFlags())
}

func TestTemplatePathGlob(t *testing.T) {
	require.Equal(t, "/users/*/orders/*", templatePathGlob("/users/{int}/orders/{uuid}", false))
	require.Equal(t, "/blog/*", templatePathGlob("/blog/{var}", false))
	require.Equal(t, "/about*", templatePathGlob("/about", true))
	require.Equal(t, "shop.test", hostOfOrigin("https://shop.test:8443"))
	require.Equal(t, "::1", hostOfOrigin("http://[::1]:8080"))
}

func TestTrafficCurlRendering(t *testing.T) {
	db := newInventoryTestDB(t)
	rec := seedInventoryRecord(t, db, "r1", "p1", "", "POST", "/api",
		"POST /api HTTP/1.1\r\nHost: shop.test:8443\r\nAuthorization: Bearer s3cret\r\nContent-Type: application/json\r\n\r\n{\"a\":1}")
	withJSON(t)
	prevRedact := trafficRedactAuth
	t.Cleanup(func() { trafficRedactAuth = prevRedact })
	trafficRedactAuth = true

	out := captureStdout(t, func() {
		require.NoError(t, renderTrafficCurl(trafficCmd, []*database.HTTPRecord{rec}, 1, nil))
	})
	require.NotContains(t, out, "s3cret")
	env := decodeEnvelope(t, out)
	contracttest.Validate(t, "traffic", []byte(out))
	require.Equal(t, "traffic", env.Command)
	var it struct {
		UUID string   `json:"uuid"`
		URL  string   `json:"url"`
		Curl string   `json:"curl"`
		Argv []string `json:"argv"`
	}
	require.NoError(t, json.Unmarshal(env.Items[0], &it))
	require.Equal(t, "r1", it.UUID)
	require.Equal(t, "https://shop.test:8443/api", it.Argv[len(it.Argv)-1], "URL comes from the stored scheme/host/port")
	require.Contains(t, it.Curl, "Authorization: <redacted>")

	// More than 20 commands need -a.
	many := make([]*database.HTTPRecord, curlRenderLimit+1)
	for i := range many {
		many[i] = rec
	}
	var ue usageError
	require.True(t, errors.As(renderTrafficCurl(trafficCmd, many, int64(len(many)), nil), &ue))
}

func TestFindingEvidenceCurl(t *testing.T) {
	prev := findingRedactAuth
	t.Cleanup(func() { findingRedactAuth = prev })
	findingRedactAuth = false
	f := &database.Finding{
		ID: 7, URL: "https://shop.test/search?q=x",
		Request: "GET /search?q=%27%22 HTTP/1.1\r\nHost: shop.test\r\nCookie: sid=1\r\n\r\n",
	}
	it, ok := findingEvidenceCurl(f)
	require.True(t, ok)
	require.Equal(t, "GET", it.Method)
	require.Equal(t, "https://shop.test/search?q=%27%22", it.URL)
	require.Contains(t, it.Curl, "Cookie: sid=1")

	none, ok := findingEvidenceCurl(&database.Finding{ID: 8, URL: "https://shop.test/"})
	require.False(t, ok, none.Curl)
}

// params --paths prints JSON body key paths with types and counts, never a
// value, in a document the registered --paths variant describes.
func TestParamsPathsJSON(t *testing.T) {
	db := newInventoryTestDB(t)
	seedInventoryRecord(t, db, "r1", "p1", "", "POST", "/api/users/7", "POST /api/users/7 HTTP/1.1\r\n\r\n",
		database.EmbeddedParam{Name: "name", Value: "alice-secret", Type: "json", Metadata: "user.name", JSONType: "string"},
		database.EmbeddedParam{Name: "q", Value: "x", Type: "url"})
	seedInventoryRecord(t, db, "r2", "p1", "", "POST", "/api/users/8", "POST /api/users/8 HTTP/1.1\r\n\r\n",
		database.EmbeddedParam{Name: "name", Value: "legacy", Type: "json"})
	withJSON(t)
	paramsFlags.limit = 100
	swapGlobal(t, &paramsPaths, true)

	out := captureStdout(t, func() {
		require.NoError(t, renderParams(context.Background(), paramsCmd, db, database.QueryFilters{ProjectUUID: "p1"}, "console"))
	})
	require.NotContains(t, out, "alice-secret")
	contracttest.Validate(t, "params", []byte(out))
	env := decodeEnvelope(t, out)
	require.EqualValues(t, 1, env.Total)
	require.Contains(t, out, `"key_path":"user.name"`)
	require.Contains(t, out, `"json_type":"string"`)
	require.Contains(t, out, `"sample_count":1`)
	require.Contains(t, out, `"records_without_paths":1`)
}

func TestParamsPathsRejectsValueFilters(t *testing.T) {
	swapGlobal(t, &paramsPaths, true)
	swapGlobal(t, &paramsLocations, []string{"json"})
	var ue usageError
	require.ErrorAs(t, validateParamsFlags(), &ue)
	swapGlobal(t, &paramsLocations, nil)
	swapGlobal(t, &paramsShowValues, true)
	require.ErrorAs(t, validateParamsFlags(), &ue)
	swapGlobal(t, &paramsShowValues, false)
	require.NoError(t, validateParamsFlags())
}
