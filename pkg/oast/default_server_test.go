package oast

import "testing"

func TestUsesDefaultServer(t *testing.T) {
	for _, tc := range []struct {
		svc  *Service
		want bool
	}{
		{&Service{serverURL: "oast.pro"}, true},
		{&Service{serverURL: "https://oast.pro/"}, true},
		{&Service{serverURL: ""}, true},
		{&Service{serverURL: "interact.example.com"}, false},
		{&Service{serverURL: "oast.pro", fixedURL: "https://cb.example"}, false},
		{nil, false},
	} {
		if got := tc.svc.UsesDefaultServer(); got != tc.want {
			t.Errorf("UsesDefaultServer(%+v) = %v, want %v", tc.svc, got, tc.want)
		}
	}
}
