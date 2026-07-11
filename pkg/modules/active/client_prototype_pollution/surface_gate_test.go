package client_prototype_pollution

import (
	"strings"
	"testing"
)

// fired reports whether a source pattern with the given name fires on content after the
// URL-source proximity gate is applied (i.e. what the scanner actually reports).
func fired(content, name string) bool {
	for _, hit := range firingSourcePatterns(content) {
		if hit.Pattern.Name == name {
			return true
		}
	}
	return false
}

// rawMatches reports whether the named pattern's regex matches at all, ignoring the gate.
func rawMatches(content, name string) bool {
	for _, sp := range ppSourcePatterns {
		if sp.Name == name {
			return sp.Pattern.MatchString(content)
		}
	}
	return false
}

// TestSinkOnlyPatternsGatedByURLSource locks in the two real-world false positives this
// module produced against chope.co: a Google Analytics hit serializer and the LABjs
// script loader. Both trip the broad "Custom recursive assign" shape but neither feeds
// attacker-controlled URL input into the sink, so neither should be reported.
func TestSinkOnlyPatternsGatedByURLSource(t *testing.T) {
	// Google Analytics inline snippet: builds a tracking query string from an internal
	// hits object `h` (nested bracket write t[k][h[k][l]]=...). No URL source anywhere.
	ga := `(function(i,s,o,g,r,a,m){i['GoogleAnalyticsObject']=r;var t={},f={},h={};` +
		`for(k in f){t[f[k]]=q(f[k])}` +
		`for(k in h)for(l in h[k]){null==t[k]&&(t[k]={}),t[k][h[k][l]]=q(k+"."+h[k][l])}` +
		`a=s.createElement(o);m=s.getElementsByTagName(o)[0];a.async=1;a.src=g;` +
		`m.parentNode.insertBefore(a,m)})(window,document,'script','//www.google-analytics.com/analytics.js','ga');`

	if !rawMatches(ga, "Custom recursive assign") {
		t.Fatal("test setup: GA snippet should still match the raw Custom recursive assign regex")
	}
	if fired(ga, "Custom recursive assign") {
		t.Error("GA hit serializer must NOT fire: no URL source feeds the loop")
	}

	// LABjs loader: a shallow, hasOwnProperty-guarded config clone. Its only URL source
	// (location.href, for BasePath) sits far from the clone loop — outside the window.
	labjs := `(function(o){var K=o.$LAB,y="UseLocalXHR",z="AlwaysPreserveOrder",u="AllowDuplicates",` +
		`A="CacheBust",B="BasePath",C=/^[^?#]*\//.exec(location.href)[0],` +
		`D=/^\w+\:\/\/\/?[^\/]+/.exec(C)[0],i=document.head||document.getElementsByTagName("head");` +
		strings.Repeat("var noop=function(x){return x};", 24) + // push the clone loop >window past location.href
		`function clone(a){var c={};for(var b in a){if(a.hasOwnProperty(b)){c[b]=a[b]}}return c}})(window);`

	if !rawMatches(labjs, "Custom recursive assign") {
		t.Fatal("test setup: LABjs snippet should still match the raw Custom recursive assign regex")
	}
	if fired(labjs, "Custom recursive assign") {
		t.Error("LABjs config clone must NOT fire: its only URL source is outside the proximity window")
	}
}

// TestSinkOnlyPatternFiresWithNearbyURLSource keeps the gate FN-safe: a genuine URL
// parameter parser that recursively assigns location.search-derived keys must still fire.
func TestSinkOnlyPatternFiresWithNearbyURLSource(t *testing.T) {
	vuln := `var params={};location.search.slice(1).split('&').forEach(function(pair){` +
		`var k=pair.split('=')[0];params[k]=decodeURIComponent(pair.split('=')[1])});`

	if !fired(vuln, "Custom recursive assign") {
		t.Error("genuine location.search-fed parser must still fire (URL source is adjacent)")
	}
}

// TestSelfContainedPatternsNotGated confirms patterns that embed their own URL source
// fire on the regex alone, with no extra proximity requirement.
func TestSelfContainedPatternsNotGated(t *testing.T) {
	cases := []struct {
		name string
		js   string
		want string
	}{
		{"location.hash parser", `out[k]=location.hash.split("&").map(x=>x)[k]=v`, "location.hash parser"},
		{"location.search split parser", `location.search.split("&").forEach(function(p){m[p]=1})`, "location.search split parser"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !fired(tc.js, tc.want) {
				t.Errorf("self-contained pattern %q must fire without a separate URL source", tc.want)
			}
		})
	}
}

// TestURLSourceNearby exercises the proximity window boundary directly.
func TestURLSourceNearby(t *testing.T) {
	pad := strings.Repeat("x", urlSourceWindow+50)
	// source far before the sink position
	far := "location.search" + pad + "SINK"
	sinkPos := strings.Index(far, "SINK")
	if urlSourceNearby(far, sinkPos) {
		t.Error("URL source beyond the window must not count as nearby")
	}
	// source just inside the window
	near := strings.Repeat("y", urlSourceWindow-20) + "location.search;SINK"
	sinkPos = strings.Index(near, "SINK")
	if !urlSourceNearby(near, sinkPos) {
		t.Error("URL source within the window must count as nearby")
	}
}

func TestObjectAssignGenericParamsRequiresRealURLSource(t *testing.T) {
	t.Parallel()
	if fired(`const params={theme:"dark"}; Object.assign(config, params);`, "Object.assign from params") {
		t.Fatal("an internal params object is not an attacker-controlled URL source")
	}
	if !fired(`const params=new URLSearchParams(location.search); Object.assign(config, params);`, "Object.assign from params") {
		t.Fatal("Object.assign fed by URLSearchParams should remain a candidate")
	}
}

func TestSameOriginScript(t *testing.T) {
	t.Parallel()
	if !sameOriginScript("https://app.example/page", "https://app.example/assets/app.js") {
		t.Fatal("same-origin script should be analyzed")
	}
	if sameOriginScript("https://app.example/page", "https://cdn.example/app.js") {
		t.Fatal("cross-origin script must not be attributed to the application")
	}
}
