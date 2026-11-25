package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestKitParamMine_JSON mines a local endpoint whose hidden parameter is only
// in a -w wordlist and checks the -j envelope: the parameter as an item, the
// run's counters at the top level.
func TestKitParamMine_JSON(t *testing.T) {
	page := strings.Repeat("<div>plain listing row</div>\n", 30)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := page
		if r.URL.Query().Has("zzhiddenknob") {
			body += strings.Repeat("<pre>verbose diagnostics enabled</pre>\n", 20)
		}
		_, _ = io.WriteString(w, body)
	}))
	defer srv.Close()

	wl := filepath.Join(t.TempDir(), "names.txt")
	if err := os.WriteFile(wl, []byte("# custom\nalpha\nzzhiddenknob\nbeta\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	saved := struct {
		target, method, data, loc string
		wordlists                 []string
		noBuiltin, json           bool
		maxReq, rate              int
	}{kitParamMineTarget, kitParamMineMethod, kitParamMineData, kitParamMineLocation, kitParamMineWordlists,
		kitParamMineNoBuiltin, globalJSON, kitParamMineMaxRequests, kitParamMineRateLimit}
	t.Cleanup(func() {
		kitParamMineTarget, kitParamMineMethod, kitParamMineData, kitParamMineLocation = saved.target, saved.method, saved.data, saved.loc
		kitParamMineWordlists, kitParamMineNoBuiltin, globalJSON = saved.wordlists, saved.noBuiltin, saved.json
		kitParamMineMaxRequests, kitParamMineRateLimit = saved.maxReq, saved.rate
		jsonResultEmitted = false
	})
	kitParamMineTarget = srv.URL + "/list?page=2"
	kitParamMineMethod, kitParamMineData, kitParamMineLocation = "GET", "", "auto"
	kitParamMineWordlists, kitParamMineNoBuiltin = []string{wl}, true
	kitParamMineMaxRequests, kitParamMineRateLimit = 60, 0
	globalJSON = true

	var runErr error
	out := captureStdout(t, func() { runErr = runKitParamMine(kitParamMineCmd, nil) })
	if runErr != nil {
		t.Fatalf("runKitParamMine: %v", runErr)
	}
	var doc struct {
		Kind     string             `json:"kind"`
		Items    []kitParamMineItem `json:"items"`
		Location string             `json:"location"`
		Tested   int                `json:"names_tested"`
		Requests int                `json:"requests"`
		Aborted  string             `json:"aborted"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}
	if doc.Kind != "read" || doc.Location != "query" || doc.Tested != 3 || doc.Aborted != "" {
		t.Errorf("envelope = %+v", doc)
	}
	if len(doc.Items) != 1 || doc.Items[0].Name != "zzhiddenknob" || doc.Items[0].Signal != "length" {
		t.Fatalf("items = %+v, want zzhiddenknob by length", doc.Items)
	}
	if !strings.Contains(doc.Items[0].URL, "page=2") || doc.Items[0].Status != 200 {
		t.Errorf("item = %+v", doc.Items[0])
	}
}

func TestKitParamMine_UsageErrors(t *testing.T) {
	saved := kitParamMineTarget
	t.Cleanup(func() { kitParamMineTarget = saved })
	kitParamMineTarget = ""
	if err := runKitParamMine(kitParamMineCmd, nil); err == nil || !strings.Contains(err.Error(), "target URL is required") {
		t.Errorf("missing target: err = %v", err)
	}
	kitParamMineTarget = "ftp://x"
	if err := runKitParamMine(kitParamMineCmd, nil); err == nil || !strings.Contains(err.Error(), "http://") {
		t.Errorf("bad scheme: err = %v", err)
	}
}

// --location header mines request header names from a -w list: the hidden
// header is an item with location "header", and a -H header on a bodiless GET
// reaches every request and is never mined.
func TestKitParamMine_HeaderLocation(t *testing.T) {
	page := strings.Repeat("<div>plain listing row</div>\n", 30)
	var missingToken bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Session") != "abc" {
			missingToken = true
		}
		body := page
		if r.Header.Get("X-Zz-Debug") != "" {
			body += strings.Repeat("<pre>verbose diagnostics enabled</pre>\n", 20)
		}
		_, _ = io.WriteString(w, body)
	}))
	defer srv.Close()

	wl := filepath.Join(t.TempDir(), "headers.txt")
	if err := os.WriteFile(wl, []byte("X-Alpha\nX-Session\nX-Zz-Debug\nHost\nX-Beta\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	saved := struct {
		target, method, data, loc string
		headers, wordlists        []string
		noBuiltin, json           bool
		maxReq, rate              int
	}{kitParamMineTarget, kitParamMineMethod, kitParamMineData, kitParamMineLocation, kitParamMineHeaders,
		kitParamMineWordlists, kitParamMineNoBuiltin, globalJSON, kitParamMineMaxRequests, kitParamMineRateLimit}
	t.Cleanup(func() {
		kitParamMineTarget, kitParamMineMethod, kitParamMineData, kitParamMineLocation = saved.target, saved.method, saved.data, saved.loc
		kitParamMineHeaders, kitParamMineWordlists, kitParamMineNoBuiltin, globalJSON = saved.headers, saved.wordlists, saved.noBuiltin, saved.json
		kitParamMineMaxRequests, kitParamMineRateLimit = saved.maxReq, saved.rate
		jsonResultEmitted = false
	})
	kitParamMineTarget = srv.URL + "/list"
	kitParamMineMethod, kitParamMineData, kitParamMineLocation = "GET", "", "header"
	kitParamMineHeaders = []string{"X-Session: abc"}
	kitParamMineWordlists, kitParamMineNoBuiltin = []string{wl}, true
	kitParamMineMaxRequests, kitParamMineRateLimit = 60, 0
	globalJSON = true

	var runErr error
	out := captureStdout(t, func() { runErr = runKitParamMine(kitParamMineCmd, nil) })
	if runErr != nil {
		t.Fatalf("runKitParamMine: %v", runErr)
	}
	var doc struct {
		Items    []kitParamMineItem `json:"items"`
		Location string             `json:"location"`
		Tested   int                `json:"names_tested"`
		Aborted  string             `json:"aborted"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}
	if doc.Location != "header" || doc.Aborted != "" || doc.Tested != 3 {
		t.Errorf("envelope = %+v (Host and the -H header are not mined)", doc)
	}
	if len(doc.Items) != 1 || doc.Items[0].Name != "X-Zz-Debug" || doc.Items[0].Location != "header" {
		t.Fatalf("items = %+v, want X-Zz-Debug in the header location", doc.Items)
	}
	if missingToken {
		t.Error("a request went out without the -H header")
	}
}
