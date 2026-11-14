package openapi

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func parseAll(t *testing.T, spec string, opts Options) map[string]string {
	t.Helper()
	opts.UseSpecServers = true
	got := map[string]string{}
	err := ParseOpenAPI([]byte(spec), opts, func(rr *httpmsg.HttpRequestResponse) bool {
		path, _, _ := strings.Cut(rr.Request().Path(), "?")
		got[rr.Request().Method()+" "+path] = string(rr.Request().Raw())
		return true
	})
	require.NoError(t, err)
	return got
}

func TestMISS40_PathIDValues(t *testing.T) {
	spec := `
openapi: "3.0.0"
info: {title: t, version: "1"}
servers: [{url: "https://api.example.test"}]
paths:
  /orders/{orderId}:
    get:
      parameters:
        - {name: orderId, in: path, required: true, schema: {type: integer}}
      responses: {"200": {description: ok}}
  /pages/{n}:
    get:
      parameters:
        - {name: n, in: path, required: true, schema: {type: integer, minimum: 10}}
      responses: {"200": {description: ok}}
  /users/{userId}:
    get:
      parameters:
        - {name: userId, in: path, required: true, schema: {type: string}}
      responses: {"200": {description: ok}}
`
	got := parseAll(t, spec, Options{})
	keys := strings.Join(mapKeys(got), ",")
	assert.Contains(t, keys, "GET /orders/1", "integer path id must be max(1,minimum)")
	assert.Contains(t, keys, "GET /pages/10", "minimum raises the floor")
	assert.Contains(t, keys, "GET /users/1", "string *id becomes 1")
}

func TestMISS40_MediaTypes(t *testing.T) {
	cases := []struct {
		ct, wantBody, wantCT string
	}{
		{"application/vnd.api+json", `{"name":"string"}`, "application/vnd.api+json"},
		{"application/json; charset=utf-8", `{"name":"string"}`, "application/json; charset=utf-8"},
		{"Application/JSON", `{"name":"string"}`, "Application/JSON"},
		{"application/soap+xml", `<name>string</name>`, "application/soap+xml"},
	}
	for _, tc := range cases {
		t.Run(tc.ct, func(t *testing.T) {
			spec := `
openapi: "3.0.0"
info: {title: t, version: "1"}
servers: [{url: "https://api.example.test"}]
paths:
  /things:
    post:
      requestBody:
        content:
          "` + tc.ct + `":
            schema: {type: object, properties: {name: {type: string}}}
      responses: {"200": {description: ok}}
`
			got := parseAll(t, spec, Options{})
			raw := got["POST /things"]
			require.NotEmpty(t, raw)
			assert.Contains(t, raw, tc.wantBody)
			assert.Contains(t, raw, "Content-Type: "+tc.wantCT)
			assert.NotContains(t, raw, "map[")
		})
	}
}

func TestMISS40_MultiTypeAndUntyped(t *testing.T) {
	spec := `
openapi: "3.1.0"
info: {title: t, version: "1"}
servers: [{url: "https://api.example.test"}]
paths:
  /a:
    post:
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                nick: {type: ["null", "string"]}
                anything: {}
                tags: {items: {type: integer}}
      responses: {"200": {description: ok}}
`
	got := parseAll(t, spec, Options{})
	raw := got["POST /a"]
	require.NotEmpty(t, raw, "a 3.1 multi-type / untyped property must not drop the operation")
	assert.Contains(t, raw, `"nick":"string"`)
	assert.Contains(t, raw, `"anything":"1"`)
	assert.Contains(t, raw, `"tags":[0]`)
}

func TestMISS40_RequiredOnly(t *testing.T) {
	spec := `
openapi: "3.0.0"
info: {title: t, version: "1"}
servers: [{url: "https://api.example.test"}]
paths:
  /s:
    post:
      parameters:
        - {name: page, in: query, schema: {type: integer}}
        - {name: q, in: query, required: true, schema: {type: string}}
      requestBody:
        content:
          application/json:
            schema:
              type: object
              required: [must]
              properties:
                must: {type: string}
                maybe: {type: string}
      responses: {"200": {description: ok}}
`
	got := parseAll(t, spec, Options{RequiredOnly: true})
	raw := got["POST /s"]
	require.NotEmpty(t, raw)
	assert.Contains(t, raw, "q=string")
	assert.NotContains(t, raw, "page=")
	assert.Contains(t, raw, `"must"`)
	assert.NotContains(t, raw, `"maybe"`)

	all := parseAll(t, spec, Options{})
	assert.Contains(t, all["POST /s"], "page=")
	assert.Contains(t, all["POST /s"], `"maybe"`)
}

func mapKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
