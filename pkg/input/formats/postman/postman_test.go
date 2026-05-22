package postman

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// testCollection is a minimal Postman v2.1 collection: a collection-level
// {{baseUrl}} variable, a GET inside a folder, and a POST with a raw JSON body
// that references {{baseUrl}} and a user variable.
const testCollection = `{
  "info": {"name": "demo", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
  "variable": [
    {"key": "baseUrl", "value": "https://api.example.com"}
  ],
  "item": [
    {
      "name": "Users",
      "item": [
        {
          "name": "List users",
          "request": {
            "method": "GET",
            "header": [{"key": "Accept", "value": "application/json"}],
            "url": {"raw": "{{baseUrl}}/api/users?limit=10"}
          }
        }
      ]
    },
    {
      "name": "Create user",
      "request": {
        "method": "POST",
        "header": [{"key": "Content-Type", "value": "application/json"}],
        "body": {"mode": "raw", "raw": "{\"name\":\"{{userName}}\"}"},
        "url": {"raw": "{{baseUrl}}/api/users"}
      }
    }
  ]
}`

// writeTestFile writes content to a temp .json file and returns its path.
func writeTestFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "collection.json")
	require.NoError(t, os.WriteFile(path, []byte(content), 0644))
	return path
}

func TestName(t *testing.T) {
	assert.Equal(t, "postman", New().Name())
}

func TestParse_VariableSubstitution(t *testing.T) {
	tmpFile := writeTestFile(t, testCollection)

	f := New()
	f.SetPostmanOptions(Options{Variables: map[string]string{"userName": "alice"}})

	var results []*httpmsg.HttpRequestResponse
	err := f.Parse(tmpFile, func(rr *httpmsg.HttpRequestResponse) bool {
		results = append(results, rr)
		return true
	})

	require.NoError(t, err)
	require.Len(t, results, 2)

	// GET from the folder: {{baseUrl}} resolved via collection variable.
	get := results[0]
	assert.Equal(t, "GET", get.Request().Method())
	assert.Equal(t, "api.example.com", get.Service().Host())
	getRaw := string(get.Request().Raw())
	assert.Contains(t, getRaw, "/api/users")
	assert.Contains(t, getRaw, "limit=10")
	assert.Contains(t, getRaw, "Accept: application/json")

	// POST with body: {{userName}} resolved via user-provided variable.
	post := results[1]
	assert.Equal(t, "POST", post.Request().Method())
	postRaw := string(post.Request().Raw())
	assert.Contains(t, postRaw, `{"name":"alice"}`)
	assert.Contains(t, postRaw, "Content-Type: application/json")
}

func TestParse_BaseURLOverride(t *testing.T) {
	tmpFile := writeTestFile(t, testCollection)

	f := New()
	// BaseURL option overrides the collection-level baseUrl variable.
	f.SetPostmanOptions(Options{BaseURL: "http://localhost:9090", Variables: map[string]string{"userName": "bob"}})

	var first *httpmsg.HttpRequestResponse
	err := f.Parse(tmpFile, func(rr *httpmsg.HttpRequestResponse) bool {
		first = rr
		return false // only need the first
	})

	require.NoError(t, err)
	require.NotNil(t, first)
	assert.Equal(t, "localhost", first.Service().Host())
	assert.Equal(t, 9090, first.Service().Port())
}

func TestParseFromData_Wrapped(t *testing.T) {
	// Wrapped format: {collection: {item: [...]}}.
	data := []byte(`{
		"collection": {
			"variable": [{"key": "baseUrl", "value": "https://wrapped.example.com"}],
			"item": [
				{"name": "ping", "request": {"method": "GET", "url": {"raw": "{{baseUrl}}/ping"}}}
			]
		}
	}`)

	f := New()
	var results []*httpmsg.HttpRequestResponse
	err := f.ParseFromData(data, func(rr *httpmsg.HttpRequestResponse) bool {
		results = append(results, rr)
		return true
	})

	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "wrapped.example.com", results[0].Service().Host())
	assert.Contains(t, string(results[0].Request().Raw()), "/ping")
}

func TestParse_URLEncodedBody(t *testing.T) {
	data := []byte(`{
		"item": [{
			"name": "form",
			"request": {
				"method": "POST",
				"body": {"mode": "urlencoded", "urlencoded": [
					{"key": "user", "value": "a b"},
					{"key": "skip", "value": "x", "disabled": true}
				]},
				"url": {"raw": "https://example.com/form"}
			}
		}]
	}`)

	f := New()
	var rr *httpmsg.HttpRequestResponse
	err := f.ParseFromData(data, func(item *httpmsg.HttpRequestResponse) bool {
		rr = item
		return true
	})

	require.NoError(t, err)
	require.NotNil(t, rr)
	raw := string(rr.Request().Raw())
	assert.Contains(t, raw, "user=a+b")
	assert.NotContains(t, raw, "skip")
}

func TestParse_PathVariables(t *testing.T) {
	// :userId path variable resolved from url.variable entries.
	data := []byte(`{
		"item": [{
			"name": "get-user",
			"request": {
				"method": "GET",
				"url": {
					"raw": "https://example.com/users/:userId",
					"variable": [{"key": "userId", "value": "42"}]
				}
			}
		}]
	}`)

	f := New()
	var rr *httpmsg.HttpRequestResponse
	err := f.ParseFromData(data, func(item *httpmsg.HttpRequestResponse) bool {
		rr = item
		return true
	})

	require.NoError(t, err)
	require.NotNil(t, rr)
	assert.Contains(t, string(rr.Request().Raw()), "/users/42")
}

func TestParseFromData_InvalidJSON(t *testing.T) {
	f := New()
	err := f.ParseFromData([]byte("not json"), func(rr *httpmsg.HttpRequestResponse) bool {
		return true
	})
	assert.Error(t, err)
}

func TestParse_MissingFile(t *testing.T) {
	f := New()
	err := f.Parse(filepath.Join(t.TempDir(), "nope.json"), func(rr *httpmsg.HttpRequestResponse) bool {
		return true
	})
	assert.Error(t, err)
}

func TestCount(t *testing.T) {
	tmpFile := writeTestFile(t, testCollection)

	count, err := New().Count(tmpFile)
	require.NoError(t, err)
	assert.Equal(t, int64(2), count)
}
