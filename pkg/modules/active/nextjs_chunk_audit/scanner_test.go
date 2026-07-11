package nextjs_chunk_audit

import (
	"strings"
	"testing"
)

func TestNew(t *testing.T) {
	m := New()
	if m == nil {
		t.Fatal("New() returned nil")
	}
	if m.ID() != ModuleID {
		t.Errorf("ID = %q, want %q", m.ID(), ModuleID)
	}
	if m.Name() != ModuleName {
		t.Errorf("Name = %q, want %q", m.Name(), ModuleName)
	}
}

func TestExtractChunkPaths(t *testing.T) {
	html := `<html><head>
<script src="/_next/static/chunks/4bd1b696-215e5051988c3dde.js?dpl=dpl_abc" async=""></script>
<script src="/_next/static/chunks/main-app-f497b9c0ad4a7a62.js?dpl=dpl_abc" async=""></script>
<script src="/_next/static/chunks/app/layout-bd1298c82c529a6d.js?dpl=dpl_abc" async=""></script>
<script src="/_next/static/chunks/app/page-97a07e31fccbefee.js?dpl=dpl_abc" async=""></script>
<script src="/_next/static/chunks/webpack-44d8aec3c26a0cdc.js?dpl=dpl_abc" id="_R_" async=""></script>
<script src="/_next/static/chunks/4bd1b696-215e5051988c3dde.js" async=""></script>
</head></html>`

	got := ExtractChunkPaths([]byte(html))

	want := []string{
		"/_next/static/chunks/4bd1b696-215e5051988c3dde.js",
		"/_next/static/chunks/app/layout-bd1298c82c529a6d.js",
		"/_next/static/chunks/app/page-97a07e31fccbefee.js",
		"/_next/static/chunks/main-app-f497b9c0ad4a7a62.js",
		"/_next/static/chunks/webpack-44d8aec3c26a0cdc.js",
	}

	if len(got) != len(want) {
		t.Fatalf("got %d chunks (%v), want %d (%v)", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("chunk[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestExtractChunkPathsEmpty(t *testing.T) {
	if got := ExtractChunkPaths(nil); got != nil {
		t.Errorf("nil input: got %v, want nil", got)
	}
	if got := ExtractChunkPaths([]byte("<html>nothing relevant</html>")); got != nil {
		t.Errorf("no markers: got %v, want nil", got)
	}
}

func TestExtractAbsoluteURLs(t *testing.T) {
	js := `const cfg={api:"https://happy-otter-123.convex.cloud/api/v1",cdn:'https://cdn.example.com/assets/'};
fetch("https://api.stripe.com/v1/charges").then(r=>r.json());
const x = "http://localhost:3000/health";
const y = "https://api.example.com/users?id=42",z=42;`

	got := ExtractAbsoluteURLs([]byte(js))
	must := []string{
		"https://happy-otter-123.convex.cloud/api/v1",
		"https://cdn.example.com/assets/",
		"https://api.stripe.com/v1/charges",
		"http://localhost:3000/health",
		"https://api.example.com/users?id=42",
	}
	gotSet := make(map[string]bool, len(got))
	for _, u := range got {
		gotSet[u] = true
	}
	for _, u := range must {
		if !gotSet[u] {
			t.Errorf("missing URL %q (got %v)", u, got)
		}
	}
}

func TestExtractAbsoluteURLsTrimsPunctuation(t *testing.T) {
	js := `var u = "https://api.example.com/v1/users",next=1;`
	got := ExtractAbsoluteURLs([]byte(js))
	if len(got) != 1 {
		t.Fatalf("got %v, want exactly one URL", got)
	}
	if got[0] != "https://api.example.com/v1/users" {
		t.Errorf("URL = %q, want %q", got[0], "https://api.example.com/v1/users")
	}
}

func TestExtractSourceMapRefs(t *testing.T) {
	js := `(()=>{})();
//# sourceMappingURL=main-app.js.map
`
	got := ExtractSourceMapRefs([]byte(js))
	if len(got) != 1 || got[0] != "main-app.js.map" {
		t.Errorf("got %v, want [main-app.js.map]", got)
	}
}

func TestFindSecretsBasic(t *testing.T) {
	body := []byte(`
const AWS_KEY = "AKIA1234AB` + `CD5678EFGH";
const GOOGLE = "AIzaSyA-1234567890abcdefghijklmnopqrstuv";
config.apiKey = "abcdef0123456789abcdef0123456789";
`)
	got := FindSecrets(body, 0)
	if len(got) < 2 {
		t.Fatalf("expected at least 2 matches, got %d (%v)", len(got), got)
	}
	patterns := map[string]bool{}
	for _, m := range got {
		patterns[m.Pattern] = true
	}
	for _, want := range []string{"aws-access-key-id", "google-api-key"} {
		if !patterns[want] {
			t.Errorf("missing pattern %q (got patterns: %v)", want, patterns)
		}
	}
}

func TestFindSecretsDedupes(t *testing.T) {
	body := []byte(`AKIA1234AB` + `CD5678EFGH` + " " + `AKIA1234AB` + `CD5678EFGH`)
	got := FindSecrets(body, 0)
	if len(got) != 1 {
		t.Errorf("got %d matches, want 1 (dedupe failed): %v", len(got), got)
	}
}

func TestFindSecretsRespectsLimit(t *testing.T) {
	// Build a body with several distinct AWS keys.
	body := []byte("AKIA0000000000000000 AKIA1111111111111111 AKIA2222222222222222 AKIA3333333333333333")
	got := FindSecrets(body, 2)
	if len(got) != 2 {
		t.Errorf("got %d matches, want 2 (limit not enforced)", len(got))
	}
}

func TestFindSecretsEmpty(t *testing.T) {
	if got := FindSecrets(nil, 0); got != nil {
		t.Errorf("nil input: got %v, want nil", got)
	}
	if got := FindSecrets([]byte("nothing of interest here"), 0); got != nil {
		t.Errorf("clean body: got %v, want nil", got)
	}
}

func TestFindSecretsSuppressesPlaceholders(t *testing.T) {
	body := []byte(`const aws="AKIAIOSFODNN7EXAMPLE"; const key="YOUR_API_KEY_PLACEHOLDER_123456";`)
	if got := FindSecrets(body, 0); len(got) != 0 {
		t.Fatalf("placeholder credentials must be suppressed, got %v", got)
	}
}

func TestTrimURLTail(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"https://x.com/path", "https://x.com/path"},
		{"https://x.com/path,", "https://x.com/path"},
		{"https://x.com/path);", "https://x.com/path"},
		{`https://x.com/path"`, "https://x.com/path"},
		{"https://x.com.", "https://x.com"},
	}
	for _, c := range cases {
		if got := trimURLTail(c.in); got != c.want {
			t.Errorf("trimURLTail(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSnippetAround(t *testing.T) {
	body := []byte(strings.Repeat("x", 100) + "SECRET" + strings.Repeat("y", 100))
	got := snippetAround(body, 100, 106)
	// 30 bytes context on each side + 6-byte match.
	if len(got) != 66 {
		t.Errorf("snippet length = %d, want 66", len(got))
	}
	if !strings.Contains(got, "SECRET") {
		t.Errorf("snippet missing match marker: %q", got)
	}
}

func TestDistinctPatterns(t *testing.T) {
	matches := []SecretMatch{
		{Pattern: "a"}, {Pattern: "a"}, {Pattern: "b"},
	}
	if got := distinctPatterns(matches); got != 2 {
		t.Errorf("distinctPatterns = %d, want 2", got)
	}
}
