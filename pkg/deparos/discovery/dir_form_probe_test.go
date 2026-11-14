package discovery

import "testing"

// MISS-8f: an extensionless 200 (/api) gets one directory-form probe (/api/).
func TestDirFormProbeURL(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"http://h/api", "http://h/api/", true},
		{"http://h/v1/users?x=1", "http://h/v1/users/", true},
		{"http://h/api/", "", false},
		{"http://h/", "", false},
		{"http://h/index.php", "", false},
	}
	for _, c := range cases {
		got, ok := dirFormProbeURL(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("dirFormProbeURL(%q) = %q, %v; want %q, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}
