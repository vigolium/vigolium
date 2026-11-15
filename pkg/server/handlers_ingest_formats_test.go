package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/input/source"
)

// ingestFixtures are the detector fixtures shared with pkg/input/source, one
// per registry format.
const ingestFixtures = "../input/source/testdata/detect"

func newIngestApp(t *testing.T) *fiber.App {
	t.Helper()
	db, repo := newPinnedTestDB(t)
	h := newBasicHandlers(t, ServerConfig{DisableFetchResponse: true}, &fakeQueue{}, db, repo, nil)
	app := fiber.New()
	app.Post("/api/ingest-http", h.HandleIngestHTTP)
	return app
}

func postIngest(t *testing.T, app *fiber.App, body map[string]any) (int, IngestHTTPResponse, ErrorResponse, string) {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	status, out := doReq(t, app, http.MethodPost, "/api/ingest-http", string(raw), nil)
	var ok IngestHTTPResponse
	var bad ErrorResponse
	if status == http.StatusOK {
		require.NoError(t, json.Unmarshal(out, &ok), string(out))
	} else {
		require.NoError(t, json.Unmarshal(out, &bad), string(out))
	}
	return status, ok, bad, string(out)
}

func fixtureB64(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(ingestFixtures, name))
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(data)
}

// TestIngestHTTP_EveryRegistryFormat posts one fixture per formatRegistry row
// under its canonical name: REST ingest accepts exactly the formats -I does.
func TestIngestHTTP_EveryRegistryFormat(t *testing.T) {
	fixtures := map[string]struct {
		file string
		url  string
	}{
		"urls":      {file: "targets.txt"},
		"nuclei":    {file: "nuclei.jsonl"},
		"openapi":   {file: "openapi.json"},
		"wsdl":      {file: "service.wsdl", url: "https://example.test/soap"},
		"postman":   {file: "collection.json"},
		"curl":      {file: "login.curl"},
		"burpraw":   {file: "request.req"},
		"burpxml":   {file: "burp.xml"},
		"burpscope": {file: "scope.json"},
		"har":       {file: "capture.har"},
		"deparos":   {file: "deparos.jsonl"},
	}
	for _, f := range source.Formats() {
		fx, ok := fixtures[f.Name]
		require.True(t, ok, "no REST ingest fixture for registry format %q", f.Name)
		t.Run(f.Name, func(t *testing.T) {
			app := newIngestApp(t)
			body := map[string]any{"input_mode": f.Name, "content_base64": fixtureB64(t, fx.file)}
			if fx.url != "" {
				body["url"] = fx.url
			}
			status, resp, _, raw := postIngest(t, app, body)
			require.Equal(t, http.StatusOK, status, raw)
			assert.GreaterOrEqual(t, resp.Imported, 1, raw)
			if f.Name != "curl" { // REST "curl" is the single-command mode
				assert.Equal(t, f.Name, resp.Format, raw)
			}
			assert.Empty(t, resp.DetectedFormat, "detected_format is only set for auto")
		})
	}
}

// TestIngestHTTP_LegacyModeNames: the historical REST names still work, now as
// registry aliases.
func TestIngestHTTP_LegacyModeNames(t *testing.T) {
	cases := map[string]string{
		"postman_collection": "collection.json",
		"http_archive":       "capture.har",
		"url_file":           "targets.txt",
		"swagger":            "swagger.json",
	}
	for mode, file := range cases {
		t.Run(mode, func(t *testing.T) {
			app := newIngestApp(t)
			status, resp, _, raw := postIngest(t, app, map[string]any{"input_mode": mode, "content_base64": fixtureB64(t, file)})
			require.Equal(t, http.StatusOK, status, raw)
			assert.GreaterOrEqual(t, resp.Imported, 1, raw)
		})
	}
}

// TestIngestHTTP_Auto detects the format from content.
func TestIngestHTTP_Auto(t *testing.T) {
	for file, want := range map[string]string{
		"har_as.json":     "har",
		"collection.json": "postman",
		"openapi.yaml":    "openapi",
		"burp_as.json":    "burpxml",
		"nuclei_as.json":  "nuclei",
		"pair.txt":        "burpraw",
		"targets.txt":     "urls",
	} {
		t.Run(file, func(t *testing.T) {
			app := newIngestApp(t)
			status, resp, _, raw := postIngest(t, app, map[string]any{"input_mode": "auto", "content_base64": fixtureB64(t, file)})
			require.Equal(t, http.StatusOK, status, raw)
			assert.Equal(t, want, resp.DetectedFormat, raw)
			assert.Equal(t, want, resp.Format, raw)
			assert.GreaterOrEqual(t, resp.Imported, 1, raw)
		})
	}

	app := newIngestApp(t)
	status, _, bad, raw := postIngest(t, app, map[string]any{"input_mode": "auto", "content_base64": fixtureB64(t, "unknown.json")})
	require.Equal(t, http.StatusBadRequest, status, raw)
	assert.Contains(t, bad.Error, "input_unparsed")
}

// TestIngestHTTP_UnknownModeListsSupported: an unknown mode is a 400 naming
// every accepted value.
func TestIngestHTTP_UnknownModeListsSupported(t *testing.T) {
	app := newIngestApp(t)
	status, _, bad, raw := postIngest(t, app, map[string]any{"input_mode": "postamn", "content": "x"})
	require.Equal(t, http.StatusBadRequest, status, raw)
	assert.Contains(t, bad.Error, "unsupported_input_mode")
	assert.Contains(t, bad.Error, "postamn")
	for _, want := range []string{"auto", "url", "burp_base64", "curl", "postman", "postman_collection", "har", "http_archive", "url_file", "wsdl", "deparos"} {
		assert.Contains(t, strings.Split(strings.TrimPrefix(bad.Details, "supported input_mode values: "), ", "), want)
	}
}

// TestIngestHTTP_URLFileRejectsOtherFormats is the never-silent rule: a HAR
// posted as url_file is refused naming har, not answered 200 with a line of
// errors per JSON brace.
func TestIngestHTTP_URLFileRejectsOtherFormats(t *testing.T) {
	app := newIngestApp(t)
	status, _, bad, raw := postIngest(t, app, map[string]any{"input_mode": "url_file", "content_base64": fixtureB64(t, "capture.har")})
	require.Equal(t, http.StatusBadRequest, status, raw)
	assert.Contains(t, bad.Error, "input_unparsed")
	assert.Contains(t, bad.Error, "har")
}

// TestIngestHTTP_URLFileSkippedReasons reports unparseable lines by reason.
func TestIngestHTTP_URLFileSkippedReasons(t *testing.T) {
	app := newIngestApp(t)
	content := "# hosts\nhttps://example.test/a\nhttps://example.test/b\nhttps://example.test/c\nnot a url\n"
	status, resp, _, raw := postIngest(t, app, map[string]any{"input_mode": "url_file", "content": content})
	require.Equal(t, http.StatusOK, status, raw)
	assert.Equal(t, 3, resp.Imported)
	assert.Equal(t, 1, resp.SkippedReasons["unparsed_line"], raw)
}

// TestIngestHTTP_PostmanVariables: a collection written against {{baseUrl}}
// imports nothing without the variable (and says which one is missing), and
// imports once it is passed in `variables`.
func TestIngestHTTP_PostmanVariables(t *testing.T) {
	collection := `{"info":{"_postman_id":"x","name":"c","schema":"https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
	 "item":[{"name":"me","request":{"method":"GET","url":{"raw":"{{baseUrl}}/me"}}}]}`

	app := newIngestApp(t)
	status, resp, _, raw := postIngest(t, app, map[string]any{"input_mode": "postman", "content": collection})
	require.Equal(t, http.StatusOK, status, raw)
	assert.Zero(t, resp.Imported, raw)
	assert.Equal(t, 1, resp.SkippedReasons["skipped_request"], raw)
	assert.Contains(t, strings.Join(resp.Errors, "\n"), "baseUrl")

	app = newIngestApp(t)
	status, resp, _, raw = postIngest(t, app, map[string]any{
		"input_mode": "postman", "content": collection,
		"variables": map[string]string{"baseUrl": "https://api.example.test"},
	})
	require.Equal(t, http.StatusOK, status, raw)
	assert.Equal(t, 1, resp.Imported, raw)
	assert.Nil(t, resp.SkippedReasons, raw)
}

// TestIngestHTTP_OpenAPIVariablesBearer: `variables` reach the OpenAPI parser,
// so a bearer scheme gets its Authorization header over REST too.
func TestIngestHTTP_OpenAPIVariablesBearer(t *testing.T) {
	db, repo := newPinnedTestDB(t)
	h := newBasicHandlers(t, ServerConfig{DisableFetchResponse: true}, &fakeQueue{}, db, repo, nil)
	app := fiber.New()
	app.Post("/api/ingest-http", h.HandleIngestHTTP)

	spec := `{"openapi":"3.0.0","info":{"title":"t","version":"1"},
	 "components":{"securitySchemes":{"jwt":{"type":"http","scheme":"bearer"}}},"security":[{"jwt":[]}],
	 "paths":{"/me":{"get":{"responses":{"200":{"description":"ok"}}}}}}`
	status, resp, _, raw := postIngest(t, app, map[string]any{
		"input_mode": "openapi", "url": "https://api.example.test", "content": spec,
		"variables": map[string]string{"bearer": "tok"},
	})
	require.Equal(t, http.StatusOK, status, raw)
	require.Equal(t, 1, resp.Imported, raw)

	var raws []string
	require.NoError(t, db.NewSelect().Table("http_records").Column("raw_request").Scan(t.Context(), &raws))
	require.Len(t, raws, 1)
	assert.Contains(t, raws[0], "Authorization: Bearer tok")
}

// SRV: input_mode url takes the URL from `url` when content is empty; an
// unknown mode is error_code unsupported_input_mode even with no content;
// a v2 caller gets the mutation envelope.
func TestIngestHTTP_URLModeAndCodes(t *testing.T) {
	app := newIngestApp(t)
	status, resp, _, raw := postIngest(t, app, map[string]any{"input_mode": "url", "url": "https://url-field.example/path?a=1"})
	require.Equal(t, http.StatusOK, status, raw)
	assert.Equal(t, 1, resp.Imported, raw)

	status, _, bad, raw := postIngest(t, app, map[string]any{"input_mode": "nope"})
	require.Equal(t, http.StatusBadRequest, status, raw)
	assert.Equal(t, "unsupported_input_mode", bad.ErrorCode, raw)

	status, _, bad, raw = postIngest(t, app, map[string]any{"input_mode": "auto", "content_base64": fixtureB64(t, "unknown.json")})
	require.Equal(t, http.StatusBadRequest, status, raw)
	assert.Equal(t, "input_unparsed", bad.ErrorCode, raw)

	db, repo := newPinnedTestDB(t)
	h := newBasicHandlers(t, ServerConfig{DisableFetchResponse: true}, &fakeQueue{}, db, repo, nil)
	v2 := fiber.New()
	v2.Use(apiVersionMiddleware(2))
	v2.Post("/api/ingest-http", h.HandleIngestHTTP)
	body, _ := json.Marshal(map[string]any{"input_mode": "url", "content": "https://v2.example/"})
	status, out := doReq(t, v2, http.MethodPost, "/api/ingest-http", string(body), nil)
	require.Equal(t, http.StatusOK, status, string(out))
	var env map[string]any
	require.NoError(t, json.Unmarshal(out, &env), string(out))
	assert.Equal(t, true, env["ok"], string(out))
	assert.Equal(t, "mutation", env["kind"], string(out))
	assert.Equal(t, float64(1), env["imported"], string(out))
	items, _ := env["items"].([]any)
	assert.Len(t, items, 1, string(out))
}
