package cli

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runA3Stdin is runA3 with content on the child's stdin.
func runA3Stdin(t *testing.T, home, content string, args ...string) (int, string, string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestScopeAdmissionChild$", "-test.v=false")
	env := []string{a3ChildEnv + "=" + strings.Join(args, "\x1f"), "HOME=" + home, "NO_COLOR=1"}
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "HOME=") || strings.HasPrefix(kv, "VIGOLIUM_") {
			continue
		}
		env = append(env, kv)
	}
	cmd.Env = env
	cmd.Stdin = strings.NewReader(content)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0, out.String(), errb.String()
	case errors.As(err, &ee):
		return ee.ExitCode(), out.String(), errb.String()
	}
	t.Fatalf("run child: %v", err)
	return -1, "", ""
}

// fetchItem GETs url and renders the answer as a match-not-found stdin line.
func fetchItem(t *testing.T, id, url string) string {
	t.Helper()
	resp, err := http.Get(url) //nolint:gosec,noctx // loopback test server
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	headers := map[string]any{}
	for k, v := range resp.Header {
		if len(v) == 1 {
			headers[k] = v[0]
		} else {
			headers[k] = v
		}
	}
	line, err := json.Marshal(map[string]any{"id": id, "url": url, "status": resp.StatusCode,
		"headers": headers, "body_b64": base64.StdEncoding.EncodeToString(body)})
	require.NoError(t, err)
	return string(line)
}

// match-not-found answers a caller's responses against the stored baseline
// exactly as traffic's matches_not_found answers the same responses once
// recorded: the soft-404 template and a 404 are not-found, a real page is not.
// Without a baseline or a body there is no answer, and a bad line is listed
// in failures without stopping the rest.
func TestMatchNotFoundAgainstStoredBaseline(t *testing.T) {
	if testing.Short() {
		t.Skip("re-execs the CLI")
	}
	f := newFingerprintFixture(t)
	home := a3Home(t, "*")
	code, stdout, stderr := runA3(t, home, "fingerprint", "-t", f.srv.URL, "--depth", "light", "-j")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)

	lines := []string{
		fetchItem(t, "soft", f.srv.URL+"/no-such-page-xyz"),
		fetchItem(t, "real", f.srv.URL+"/about"),
		fetchItem(t, "gone", f.srv.URL+"/missing.txt"),
		`{"id":"nobody","url":"` + f.srv.URL + `/x","status":200,"headers":{"Content-Type":"text/html"}}`,
		`{"id":"elsewhere","url":"http://127.0.0.1:1/x","status":200,"headers":{},"body_b64":""}`,
		`{"id":"broken","url":"` + f.srv.URL + `/x","status":200,"body_b64":"%%%"}`,
		`not json`,
	}
	code, stdout, stderr = runA3Stdin(t, home, strings.Join(lines, "\n")+"\n", "match-not-found", "-j")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	doc := oneDoc(t, stdout, stderr)
	validateRegisteredMap(t, doc)
	assert.Equal(t, "match-not-found", doc["command"])
	got := map[string]map[string]any{}
	var order []string
	for _, it := range doc["items"].([]any) {
		row := it.(map[string]any)
		got[row["id"].(string)] = row
		order = append(order, row["id"].(string))
	}
	assert.Equal(t, []string{"soft", "real", "gone", "nobody", "elsewhere"}, order, "one item per answered line, in order")
	want := map[string][3]any{
		"soft":      {true, true, "signature"},
		"real":      {false, true, "signature"},
		"gone":      {true, true, "status-404"},
		"nobody":    {false, false, "no-body"},
		"elsewhere": {false, false, "no-baseline"},
	}
	for id, w := range want {
		row := got[id]
		require.NotNil(t, row, id)
		assert.Equal(t, w[0], row["matches"], "%s matches", id)
		assert.Equal(t, w[1], row["known"], "%s known", id)
		assert.Equal(t, w[2], row["reason"], "%s reason", id)
	}
	assert.EqualValues(t, 2, doc["failed"])
	failures := doc["failures"].([]any)
	require.Len(t, failures, 2)
	assert.Equal(t, "broken", failures[0].(map[string]any)["id"])
	assert.EqualValues(t, 7, failures[1].(map[string]any)["line"])

	// --fields projects the rows; --format tsv prints one line per answer.
	code, stdout, stderr = runA3Stdin(t, home, lines[2]+"\n", "match-not-found", "-j", "--fields", "id,reason")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	assert.Equal(t, map[string]any{"id": "gone", "reason": "status-404"}, oneDoc(t, stdout, stderr)["items"].([]any)[0])
	code, stdout, stderr = runA3Stdin(t, home, lines[2]+"\n", "match-not-found", "--format", "tsv", "--no-header")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	assert.Equal(t, "gone\ttrue\ttrue\tstatus-404\t"+f.srv.URL+"/missing.txt", strings.TrimSpace(stdout))

	// The stored-record path agrees on the same responses.
	list := t.TempDir() + "/urls.txt"
	require.NoError(t, writeFile(list, f.srv.URL+"/no-such-page-xyz\n"+f.srv.URL+"/about\n"+f.srv.URL+"/missing.txt\n"))
	code, stdout, stderr = runA3(t, home, "ingest", "-i", list, "--fetch-responses", "-j")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	code, stdout, stderr = runA3(t, home, "traffic", "-j", "--fields", "url,matches_not_found",
		"--url", f.srv.URL+"/no-such-page-xyz", "--url", f.srv.URL+"/about", "--url", f.srv.URL+"/missing.txt")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	byPath := map[string]string{"/no-such-page-xyz": "soft", "/about": "real", "/missing.txt": "gone"}
	for _, it := range oneDoc(t, stdout, stderr)["items"].([]any) {
		row := it.(map[string]any)
		u := row["url"].(string)
		id := byPath[u[strings.LastIndex(u, "/"):]]
		assert.Equal(t, got[id]["matches"], row["matches_not_found"], "%s: stored and stdin paths disagree", u)
	}
}

// Empty stdin answers an empty document, not an error.
func TestMatchNotFoundEmptyInput(t *testing.T) {
	if testing.Short() {
		t.Skip("re-execs the CLI")
	}
	home := a3Home(t, "*")
	code, stdout, stderr := runA3Stdin(t, home, "", "match-not-found", "-j")
	require.Equal(t, 0, code, "stdout:\n%s\nstderr:\n%s", stdout, stderr)
	doc := oneDoc(t, stdout, stderr)
	assert.Empty(t, doc["items"])
	assert.EqualValues(t, 0, doc["total"])
}

// One stdin line becomes the response classify reads: the port from the URL or
// its scheme, headers as a string or a list, a body cut at the transport's cap,
// and no response at all when body_b64 is absent.
func TestMatchNotFoundRequestParsing(t *testing.T) {
	var in matchNotFoundInput
	require.NoError(t, json.Unmarshal([]byte(`{"id":"a","url":"https://App.Example/x","status":200,
		"headers":{"Set-Cookie":["a=1","b=2"],"Content-Type":"text/html"}}`), &in))
	r, err := matchNotFoundRequest(in)
	require.NoError(t, err)
	assert.Equal(t, "app.example", r.hostname)
	assert.Equal(t, 443, r.port)
	assert.False(t, r.hasResponse, "no body_b64 is no response to compare")
	assert.Equal(t, []string{"a=1", "b=2"}, r.headers.Values("Set-Cookie"))
	assert.Equal(t, "text/html", r.headers.Get("Content-Type"))

	big := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("x"), matchNotFoundMaxBody+10))
	require.NoError(t, json.Unmarshal([]byte(`{"id":"b","url":"http://h:8080/","status":200,"body_b64":"`+big+`"}`), &in))
	r, err = matchNotFoundRequest(in)
	require.NoError(t, err)
	assert.Equal(t, 8080, r.port)
	assert.True(t, r.hasResponse)
	assert.Len(t, r.body, matchNotFoundMaxBody, "a body over the cap is cut to it")

	for _, bad := range []string{
		`{"url":"/relative","status":200}`,
		`{"url":"ftp://h/x","status":200}`,
		`{"url":"http://h/x"}`,
		`{"url":"http://h/x","status":200,"body_b64":"!!"}`,
	} {
		var in matchNotFoundInput
		require.NoError(t, json.Unmarshal([]byte(bad), &in))
		_, err := matchNotFoundRequest(in)
		assert.Error(t, err, bad)
	}
	var hdr matchNotFoundInput
	assert.Error(t, json.Unmarshal([]byte(`{"headers":{"X":1}}`), &hdr), "a header that is neither a string nor a list")
}
