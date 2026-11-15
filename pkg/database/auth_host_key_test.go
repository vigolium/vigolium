package database

import (
	"reflect"
	"testing"
)

func TestAuthHostKey(t *testing.T) {
	for in, want := range map[string]string{
		"http://127.0.0.1:28942/login": "127.0.0.1:28942",
		"https://App.Test:443/":        "app.test",
		"http://app.test:80":           "app.test",
		"https://app.test:8443":        "app.test:8443",
		"app.test":                     "app.test",
		"app.test:8080":                "app.test:8080",
		"http://[::1]:8080/":           "[::1]:8080",
	} {
		if got := AuthHostKey(in); got != want {
			t.Errorf("AuthHostKey(%q) = %q, want %q", in, got, want)
		}
	}
	if got := AuthHostLookupKeys("127.0.0.1:28942"); !reflect.DeepEqual(got, []string{"127.0.0.1:28942", "127.0.0.1"}) {
		t.Errorf("lookup keys = %v", got)
	}
	if got := AuthHostLookupKeys("app.test"); !reflect.DeepEqual(got, []string{"app.test"}) {
		t.Errorf("lookup keys = %v", got)
	}
}
