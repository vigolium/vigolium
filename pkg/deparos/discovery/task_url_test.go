package discovery

import "testing"

func TestCollapseDoubleSlashes(t *testing.T) {
	cases := []struct{ in, want string }{
		// The reported case: stray // from a discovered path.
		{"https://h.example/jboss-net//happyaxis.jsp", "https://h.example/jboss-net/happyaxis.jsp"},
		{"https://h.example/axis2//axis2-web/HappyAxis.jsp.TMP", "https://h.example/axis2/axis2-web/HappyAxis.jsp.TMP"},
		// Multiple / longer runs collapse fully.
		{"https://h.example/a///b////c", "https://h.example/a/b/c"},
		// Double slash right at root.
		{"https://h.example//root", "https://h.example/root"},
		// Scheme separator is preserved; clean paths are untouched.
		{"https://h.example/clean/path", "https://h.example/clean/path"},
		{"http://h.example/x", "http://h.example/x"},
		{"https://h.example/", "https://h.example/"},
	}
	for _, tc := range cases {
		if got := collapseDoubleSlashes(tc.in); got != tc.want {
			t.Errorf("collapseDoubleSlashes(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
