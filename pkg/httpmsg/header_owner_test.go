package httpmsg

import (
	"slices"
	"testing"
)

func TestHeaderOwner_Keys(t *testing.T) {
	raw := []byte("GET /?q=1 HTTP/1.1\r\nHost: a.test\r\nX-Tenant: t1\r\nCookie: TrackingId=abc; other=2\r\n\r\n")
	points, err := CreateAllInsertionPoints(raw, true)
	if err != nil {
		t.Fatal(err)
	}
	var sawHeader, sawCookie, sawQuery bool
	for _, ip := range points {
		keys := OwnedHeaderKeysOf(ip)
		switch {
		case ip.Type() == INS_HEADER && ip.Name() == "X-Tenant":
			sawHeader = true
			if !slices.Equal(keys, []string{"x-tenant"}) {
				t.Errorf("header point keys = %v", keys)
			}
		case ip.Type() == INS_PARAM_COOKIE && ip.Name() == "TrackingId":
			sawCookie = true
			if !slices.Equal(keys, []string{"cookie:trackingid"}) {
				t.Errorf("cookie point keys = %v", keys)
			}
		case ip.Type() == INS_PARAM_URL && ip.Name() == "q":
			sawQuery = true
			if len(keys) != 0 {
				t.Errorf("query point must own no header, got %v", keys)
			}
		}
	}
	if !sawHeader || !sawCookie || !sawQuery {
		t.Fatalf("points missing: header=%v cookie=%v query=%v", sawHeader, sawCookie, sawQuery)
	}
}
