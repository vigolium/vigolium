package server

import "testing"

func TestCheckAPIBind(t *testing.T) {
	for _, c := range []struct {
		host                 string
		noAuth, allow, wantE bool
	}{
		{"0.0.0.0", true, false, true},
		{"10.0.0.5", true, false, true},
		{"", true, false, true},
		{"0.0.0.0", true, true, false},
		{"0.0.0.0", false, false, false},
		{"127.0.0.1", true, false, false},
		{"localhost", true, false, false},
		{"::1", true, false, false},
	} {
		if err := CheckAPIBind(c.host, c.noAuth, c.allow); (err != nil) != c.wantE {
			t.Errorf("CheckAPIBind(%q, noAuth=%v, allow=%v) = %v", c.host, c.noAuth, c.allow, err)
		}
	}
}
