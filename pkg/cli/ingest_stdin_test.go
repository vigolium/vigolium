package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

// runWithStdin is b5Env.run with stdin piped in.
func (e *b5Env) runWithStdin(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	argv := append([]string{"--db", e.db}, args...)
	cmd := exec.Command(os.Args[0], "-test.run=^TestMachineMutationsChild$", "-test.v=false")
	env := []string{b5ChildEnv + "=" + strings.Join(argv, "\x1f"), "HOME=" + e.home, "VIGOLIUM_DISABLE_UPDATE_CHECK=1"}
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		if name == "HOME" || strings.HasPrefix(name, "VIGOLIUM_") || strings.Contains(strings.ToLower(name), "proxy") {
			continue
		}
		env = append(env, kv)
	}
	cmd.Env = env
	cmd.Stdin = strings.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return code, out.String(), errb.String()
}

func trafficTotal(t *testing.T, e *b5Env) int {
	t.Helper()
	code, stdout, stderr := e.run(t, nil, "traffic", "-j")
	require.Equal(t, 0, code, stderr)
	var doc struct {
		Total int `json:"total"`
	}
	require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(stdout)), &doc), stdout)
	return doc.Total
}

// A HAR piped on stdin is ingested like the same file passed with -i: with
// -I har, and by detection without it. An OpenAPI document on stdin is not
// read as a URL list.
func TestIngestStdinHonoursFormat(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	har := `{"log":{"version":"1.2","creator":{"name":"t","version":"1"},"entries":[{"startedDateTime":"2026-01-01T00:00:00Z","time":1,` +
		`"request":{"method":"GET","url":"` + srv.URL + `/from-har","httpVersion":"HTTP/1.1","headers":[],"queryString":[],"cookies":[],"headersSize":-1,"bodySize":0},` +
		`"response":{"status":200,"statusText":"OK","httpVersion":"HTTP/1.1","headers":[{"name":"Content-Type","value":"text/plain"}],"cookies":[],"content":{"size":2,"mimeType":"text/plain","text":"ok"},"redirectURL":"","headersSize":-1,"bodySize":2},` +
		`"cache":{},"timings":{"send":0,"wait":1,"receive":0}}]}}`

	for _, args := range [][]string{{"ingest", "-I", "har"}, {"ingest"}} {
		e := newB5Env(t)
		code, _, stderr := e.runWithStdin(t, har, args...)
		require.Equal(t, 0, code, "%v: %s", args, stderr)
		require.Equal(t, 1, trafficTotal(t, e), "%v stored the wrong number of records", args)
	}

	openapi := `{"openapi":"3.0.0","info":{"title":"t","version":"1"},"servers":[{"url":"` + srv.URL + `"}],` +
		`"paths":{"/pets":{"get":{"responses":{"200":{"description":"ok"}}}}}}`
	e := newB5Env(t)
	code, _, stderr := e.runWithStdin(t, openapi, "ingest")
	require.Equal(t, 0, code, stderr)
	require.NotContains(t, stderr, "http://servers")
	code, stdout, _ := e.run(t, nil, "traffic", "-j")
	require.Equal(t, 0, code)
	require.NotContains(t, stdout, "//servers/")
	require.NotContains(t, stdout, "//paths/")
}
