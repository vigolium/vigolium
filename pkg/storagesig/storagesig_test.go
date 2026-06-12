package storagesig

import "testing"

type fakeHeaders map[string]string

func (f fakeHeaders) Header(name string) string { return f[name] }

func TestResponseHasStorageSignal(t *testing.T) {
	cases := []struct {
		name string
		h    fakeHeaders
		want bool
	}{
		{"gcs", fakeHeaders{"x-goog-generation": "1700000000"}, true},
		{"s3", fakeHeaders{"x-amz-request-id": "ABC123"}, true},
		{"tos", fakeHeaders{"x-tos-request-id": "tos-xyz"}, true},
		{"oss", fakeHeaders{"x-oss-request-id": "oss-xyz"}, true},
		{"server-s3", fakeHeaders{"Server": "AmazonS3"}, true},
		{"server-gcs", fakeHeaders{"Server": "UploadServer"}, true},
		{"none", fakeHeaders{"Server": "nginx", "Content-Type": "image/png"}, false},
		{"photos-not-tos", fakeHeaders{"Server": "photos-cdn"}, false},
		{"nil", nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ResponseHasStorageSignal(c.h); got != c.want {
				t.Fatalf("got %v want %v", got, c.want)
			}
		})
	}
}

func TestLooksLikeStorageObjectPath(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/obj/tcc-config-web-maliva/tcc-v2-data-ad.ttfb.tracking_sdk-ttam", true},
		{"/obj/bucket/sub/key.png", true},
		{"/obj/bucket", false}, // bucket only, no object
		{"/api/users/123", false},
		{"/static/js/app.js", false},
		{"", false},
	}
	for _, c := range cases {
		if got := LooksLikeStorageObjectPath(c.path); got != c.want {
			t.Fatalf("%q: got %v want %v", c.path, got, c.want)
		}
	}
}

func TestBucketPrefixAndLeaf(t *testing.T) {
	p := "/obj/tcc-config-web-maliva/a/b/object-name"
	if got := BucketPrefix(p); got != "/obj/tcc-config-web-maliva" {
		t.Fatalf("BucketPrefix=%q", got)
	}
	if got := ObjectLeaf(p); got != "object-name" {
		t.Fatalf("ObjectLeaf=%q", got)
	}
	if got := HostBucketKey("https://sf-tcc-config.cdn.acme.com/obj/tcc-config-web-maliva/x"); got != "sf-tcc-config.cdn.acme.com|/obj/tcc-config-web-maliva" {
		t.Fatalf("HostBucketKey=%q", got)
	}
}

func TestStrongListing(t *testing.T) {
	s3 := `<?xml version="1.0"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>b</Name><Contents><Key>a/b/c</Key></Contents></ListBucketResult>`
	if prov, ok := StrongListing(s3); !ok || prov != "s3-compatible" {
		t.Fatalf("s3 listing not detected: %q %v", prov, ok)
	}
	gcs := `{"kind": "storage#objects", "items": [{"name": "a/b/c"}]}`
	if prov, ok := StrongListing(gcs); !ok || prov != "gcs-json" {
		t.Fatalf("gcs listing not detected: %q %v", prov, ok)
	}
	// An S3 error document must NOT be treated as a listing.
	errDoc := `<?xml version="1.0"?><Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message></Error>`
	if _, ok := StrongListing(errDoc); ok {
		t.Fatalf("error doc wrongly detected as listing")
	}
	if _, ok := StrongListing("just some html"); ok {
		t.Fatalf("plain body wrongly detected as listing")
	}
}

func TestListingKeysAndLeaf(t *testing.T) {
	s3 := `<ListBucketResult><Contents><Key>tcc/obj-one</Key></Contents><Contents><Key>tcc/obj-two</Key></Contents></ListBucketResult>`
	keys := ListingKeys(s3, 10)
	if len(keys) != 2 {
		t.Fatalf("keys=%v", keys)
	}
	if !ListingContainsLeaf(keys, "obj-one") {
		t.Fatalf("leaf suffix match failed: %v", keys)
	}
	if ListingContainsLeaf(keys, "absent") {
		t.Fatalf("unexpected leaf match")
	}
	gcs := `{"kind":"storage#objects","items":[{"name":"x/y"},{"name":"x/z"}]}`
	if got := ListingKeys(gcs, 10); len(got) != 2 {
		t.Fatalf("gcs keys=%v", got)
	}
}

func TestExtractStorageURLs(t *testing.T) {
	body := `<a href="https://lf-creative-factory.cdn.acme.com/obj/eden-sg/fyvajhm_lcpahlyj">x</a>
	also https://storage.googleapis.com/my-bucket/path/to/file.json and
	https://example.s3-us-west-2.amazonaws.com/key/here.txt`
	urls := ExtractStorageURLs(body, 10)
	if len(urls) < 3 {
		t.Fatalf("expected >=3 urls, got %v", urls)
	}
	// dedup
	dup := body + "\n" + body
	if got := ExtractStorageURLs(dup, 10); len(got) != len(urls) {
		t.Fatalf("dedup failed: %d vs %d", len(got), len(urls))
	}
}
