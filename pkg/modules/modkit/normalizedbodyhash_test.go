package modkit

import "testing"

// The canonical motivating case: a Jetty/nginx error page that mirrors the
// requested URI into the body. Probing N path variants yields N bodies that
// differ ONLY by the reflected URI, defeating exact response-hash dedup.
func TestNormalizedBodyHash_CollapsesReflectedURL(t *testing.T) {
	t.Parallel()

	// Two probes against the same echoing error page differing only by extension.
	pathA, urlA := "/axis2//axis2-web/HappyAxis.jsp.TMP", "https://h.example/axis2//axis2-web/HappyAxis.jsp.TMP"
	pathB, urlB := "/axis2//axis2-web/HappyAxis.jsp.OLD", "https://h.example/axis2//axis2-web/HappyAxis.jsp.OLD"
	bodyA := sprintfURI(pathA)
	bodyB := sprintfURI(pathB)

	// Sanity: the raw bodies genuinely differ (so plain hashing would not collapse).
	if bodyA == bodyB {
		t.Fatal("test bodies should differ before normalization")
	}

	hA := NormalizedBodyHash(bodyA, pathA, urlA)
	hB := NormalizedBodyHash(bodyB, pathB, urlB)
	if hA == "" || hB == "" {
		t.Fatal("expected non-empty hashes for non-empty bodies")
	}
	if hA != hB {
		t.Errorf("expected reflected-URL-only difference to collapse to one hash:\n  A=%s\n  B=%s", hA, hB)
	}
}

func TestNormalizedBodyHash_KeepsGenuineDifference(t *testing.T) {
	t.Parallel()

	p1 := "/a"
	p2 := "/b"
	h1 := NormalizedBodyHash("<h1>welcome to the admin console</h1> path /a", p1)
	h2 := NormalizedBodyHash("<h1>internal server error</h1> path /b", p2)
	if h1 == h2 {
		t.Error("expected genuinely different bodies to hash differently")
	}
}

func TestNormalizedBodyHash_CollapsesDynamicRuns(t *testing.T) {
	t.Parallel()

	// Same template, differing only by a long dynamic token (request id / timestamp).
	h1 := NormalizedBodyHash(`{"error":"not found","trace":"a1b2c3d4e5f6a7b8"}`)
	h2 := NormalizedBodyHash(`{"error":"not found","trace":"99887766554433221"}`)
	if h1 != h2 {
		t.Errorf("expected dynamic-run difference to collapse:\n  1=%s\n  2=%s", h1, h2)
	}
}

func TestNormalizedBodyHash_EmptyBody(t *testing.T) {
	t.Parallel()

	if got := NormalizedBodyHash("", "/a"); got != "" {
		t.Errorf("empty body should yield empty hash, got %q", got)
	}
	if got := NormalizedBodyHash("   \n\t ", "/a"); got != "" {
		t.Errorf("whitespace-only body should yield empty hash, got %q", got)
	}
}

func sprintfURI(suffix string) string {
	// Build the error page with the given path appended to the mirrored URI,
	// without importing fmt at file scope just for one call site.
	return `<html><head><title>error 400 ambiguous uri empty segment</title></head>
<body><h2>http error 400 ambiguous uri empty segment</h2>
<table><tr><th>uri:</th><td>http://h.example` + suffix + `</td></tr>
<tr><th>status:</th><td>400</td></tr></table></body></html>`
}
