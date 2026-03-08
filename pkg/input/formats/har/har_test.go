package har

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/formats"
)

const testHAR = `{
  "log": {
    "version": "1.2",
    "entries": [
      {
        "request": {
          "method": "GET",
          "url": "https://example.com/api/users?page=1",
          "httpVersion": "HTTP/1.1",
          "headers": [
            {"name": "Host", "value": "example.com"},
            {"name": "Accept", "value": "application/json"}
          ],
          "queryString": [
            {"name": "page", "value": "1"}
          ]
        },
        "response": {
          "status": 200,
          "statusText": "OK",
          "httpVersion": "HTTP/1.1",
          "headers": [
            {"name": "Content-Type", "value": "application/json"}
          ],
          "content": {
            "size": 27,
            "mimeType": "application/json",
            "text": "{\"users\": [{\"id\": 1}]}"
          }
        }
      },
      {
        "request": {
          "method": "POST",
          "url": "https://example.com/api/users",
          "httpVersion": "HTTP/1.1",
          "headers": [
            {"name": "Host", "value": "example.com"},
            {"name": "Content-Type", "value": "application/json"}
          ],
          "postData": {
            "mimeType": "application/json",
            "text": "{\"name\": \"test\"}"
          }
        },
        "response": {
          "status": 201,
          "statusText": "Created",
          "httpVersion": "HTTP/1.1",
          "headers": [
            {"name": "Content-Type", "value": "application/json"}
          ],
          "content": {
            "size": 15,
            "mimeType": "application/json",
            "text": "{\"id\": 2}"
          }
        }
      }
    ]
  }
}`

func TestParse_MultipleEntries(t *testing.T) {
	tmpFile := writeTestFile(t, testHAR)

	f := New()
	var results []*httpmsg.HttpRequestResponse

	err := f.Parse(tmpFile, func(rr *httpmsg.HttpRequestResponse) bool {
		results = append(results, rr)
		return true
	})

	require.NoError(t, err)
	require.Len(t, results, 2)

	// First entry: GET
	req0 := results[0].Request()
	assert.Equal(t, "GET", req0.Method())
	assert.Equal(t, "example.com", results[0].Service().Host())
	assert.True(t, results[0].HasResponse())

	// Second entry: POST
	req1 := results[1].Request()
	assert.Equal(t, "POST", req1.Method())
	assert.True(t, results[1].HasResponse())
}

func TestParse_CallbackStopsEarly(t *testing.T) {
	tmpFile := writeTestFile(t, testHAR)

	f := New()
	var count int

	err := f.Parse(tmpFile, func(rr *httpmsg.HttpRequestResponse) bool {
		count++
		return false // stop after first
	})

	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestCount(t *testing.T) {
	tmpFile := writeTestFile(t, testHAR)

	f := New()
	count, err := f.Count(tmpFile)

	require.NoError(t, err)
	assert.Equal(t, int64(2), count)
}

func TestParseFromData_RequestOnly(t *testing.T) {
	data := []byte(`{
		"log": {
			"entries": [{
				"request": {
					"method": "GET",
					"url": "http://localhost:8080/health",
					"httpVersion": "HTTP/1.1",
					"headers": []
				},
				"response": {
					"status": 0,
					"headers": [],
					"content": {}
				}
			}]
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
	assert.Equal(t, "GET", results[0].Request().Method())
	assert.Equal(t, "localhost", results[0].Service().Host())
}

func TestParseFromData_InvalidJSON(t *testing.T) {
	f := New()
	err := f.ParseFromData([]byte("not json"), func(rr *httpmsg.HttpRequestResponse) bool {
		return true
	})
	assert.Error(t, err)
}

func TestParseFromData_EmptyEntries(t *testing.T) {
	data := []byte(`{"log": {"entries": []}}`)

	f := New()
	var count int

	err := f.ParseFromData(data, func(rr *httpmsg.HttpRequestResponse) bool {
		count++
		return true
	})

	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

func TestParse_SkipsInvalidEntries(t *testing.T) {
	data := []byte(`{
		"log": {
			"entries": [
				{
					"request": {"method": "", "url": ""},
					"response": {"status": 0, "headers": [], "content": {}}
				},
				{
					"request": {
						"method": "GET",
						"url": "http://example.com/valid",
						"httpVersion": "HTTP/1.1",
						"headers": [{"name": "Host", "value": "example.com"}]
					},
					"response": {"status": 200, "statusText": "OK", "headers": [], "content": {}}
				}
			]
		}
	}`)

	tmpFile := writeTestFile(t, string(data))
	f := New()
	var results []*httpmsg.HttpRequestResponse

	err := f.Parse(tmpFile, func(rr *httpmsg.HttpRequestResponse) bool {
		results = append(results, rr)
		return true
	})

	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "GET", results[0].Request().Method())
}

func TestName(t *testing.T) {
	f := New()
	assert.Equal(t, "har", f.Name())
}

func TestSetOptions(t *testing.T) {
	f := New()
	opts := formats.InputFormatOptions{SkipFormatValidation: true}
	f.SetOptions(opts)
	assert.True(t, f.formatOpts.SkipFormatValidation)
}

func writeTestFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.har")
	err := os.WriteFile(path, []byte(content), 0644)
	require.NoError(t, err)
	return path
}
