package pathglob

import "testing"

func TestMatch(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{
		{"/api/*", "/api/users/1", true},
		{"/api/**", "/api/users/1", true},
		{"/api/*", "/api", false},
		{"/logout", "/logout", true},
		{"/logout", "/logout/x", false},
		{"*.php", "/a/b/c.php", true},
		{"/v?/x", "/v1/x", true},
		{"/[ab]/x", "/a/x", true},
		{"/[!ab]/x", "/a/x", false},
		{"/a.b", "/axb", false},
		{"/[bad", "/[bad", false},
	}
	for _, c := range cases {
		if got := Match(c.pattern, c.path); got != c.want {
			t.Errorf("Match(%q, %q) = %v, want %v", c.pattern, c.path, got, c.want)
		}
	}
	if ScopePath("/a?b=1#f") != "/a" || ScopePath("/a#f?x") != "/a" {
		t.Error("ScopePath must cut the query and fragment")
	}
}
