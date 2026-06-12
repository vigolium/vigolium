package runner

import (
	"fmt"
	"testing"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// htmlRow builds a candidate row with a parseable raw HTML response.
func htmlRow(source, host, url string, status int, body string) database.ReSpiderCandidate {
	raw := httpmsg.BuildRawResponse(status, map[string]string{"Content-Type": "text/html"}, body)
	return database.ReSpiderCandidate{
		URL:                 url,
		Hostname:            host,
		Source:              source,
		ResponseContentType: "text/html",
		RawResponse:         raw,
	}
}

// Two distinct SPA shells (different bundle script sets).
const shellOne = `<div id="root"></div>` +
	`<script src="/static/js/app.aaaaaa.js"></script>` +
	`<script src="/static/js/vendor.bbbbbb.js"></script>`

const shellTwo = `<div id="root"></div>` +
	`<script src="/build/main.cccccc.js"></script>` +
	`<script src="/build/chunk.dddddd.js"></script>`

func chosenURLs(seeds []respiderSeed) map[string]bool {
	m := make(map[string]bool, len(seeds))
	for _, s := range seeds {
		m[s.url] = true
	}
	return m
}

func TestSelectReSpiderSeeds_DedupAndKeep(t *testing.T) {
	rows := []database.ReSpiderCandidate{
		// Shell one was already browser-crawled by the spider at the root.
		htmlRow("spidering", "app.x.com", "https://app.x.com/", 200, shellOne),
		// Discovery re-found the same shell at /console/ — must be deduped out.
		htmlRow("deparos", "app.x.com", "https://app.x.com/console/", 200, shellOne),
		// Discovery found a NEW shell at /admin/ — must be selected.
		htmlRow("deparos", "app.x.com", "https://app.x.com/admin/", 200, shellTwo),
		// A plain static page — dropped.
		htmlRow("deparos", "app.x.com", "https://app.x.com/about/", 200, `<h1>About</h1><p>lots of words here</p>`),
		// A login page — dropped.
		htmlRow("deparos", "app.x.com", "https://app.x.com/portal/", 200, `<form><input type="password"></form>`),
	}

	chosen, skips, kept := selectReSpiderSeeds(rows, 3, 10)

	if kept != 1 {
		t.Fatalf("kept = %d, want 1 (only the new /admin/ shell)", kept)
	}
	urls := chosenURLs(chosen)
	if !urls["https://app.x.com/admin/"] {
		t.Errorf("expected /admin/ to be selected, got %v", urls)
	}
	if urls["https://app.x.com/console/"] {
		t.Errorf("/console/ shares the already-spidered shell and must be deduped, got %v", urls)
	}
	if skips["dup-shell"] != 1 {
		t.Errorf("dup-shell = %d, want 1", skips["dup-shell"])
	}
	if skips["static"] != 1 {
		t.Errorf("static = %d, want 1", skips["static"])
	}
	if skips["login"] != 1 {
		t.Errorf("login = %d, want 1", skips["login"])
	}
}

func TestSelectReSpiderSeeds_PerHostCap(t *testing.T) {
	// Five distinct shells on one host, per-host cap of 2 → only 2 chosen.
	rows := make([]database.ReSpiderCandidate, 0, 5)
	for i := 0; i < 5; i++ {
		body := fmt.Sprintf(`<div id="root"></div>`+
			`<script src="/b/app%d.aaaaaa.js"></script>`+
			`<script src="/b/vendor%d.bbbbbb.js"></script>`, i, i)
		rows = append(rows, htmlRow("deparos", "app.x.com", fmt.Sprintf("https://app.x.com/area%d/", i), 200, body))
	}

	chosen, _, kept := selectReSpiderSeeds(rows, 2, 10)
	if kept != 5 {
		t.Fatalf("kept = %d, want 5 (all distinct shells pass the gate)", kept)
	}
	if len(chosen) != 2 {
		t.Fatalf("chosen = %d, want 2 (per-host cap)", len(chosen))
	}
}

func TestSelectReSpiderSeeds_TotalCap(t *testing.T) {
	// Distinct shells across many hosts, total cap of 3.
	rows := make([]database.ReSpiderCandidate, 0, 6)
	for i := 0; i < 6; i++ {
		host := fmt.Sprintf("h%d.x.com", i)
		body := fmt.Sprintf(`<div id="root"></div>`+
			`<script src="/b/app%d.aaaaaa.js"></script>`+
			`<script src="/b/vendor%d.bbbbbb.js"></script>`, i, i)
		rows = append(rows, htmlRow("deparos", host, fmt.Sprintf("https://%s/ui/", host), 200, body))
	}

	chosen, _, _ := selectReSpiderSeeds(rows, 3, 3)
	if len(chosen) != 3 {
		t.Fatalf("chosen = %d, want 3 (total cap)", len(chosen))
	}
}
