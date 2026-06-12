// Package storagesig provides behavioral (not hostname-allowlist) detection of
// object-storage backends and their listing responses. It is shared by the
// executor's static-file carve-out and the cloud-storage traversal/harvest
// modules so they agree on what "looks like object storage".
//
// The detection is deliberately behavioral: vanity CDN domains (e.g.
// *.cdn.acme.com) front S3/GCS/TOS/OSS backends without any
// recognizable storage hostname, so we key off response headers, the /obj/
// path shape, and the self-confirming listing body instead.
package storagesig

import (
	"net/url"
	"regexp"
	"strings"
)

// HeaderGetter is satisfied by *httpmsg.HttpResponse (Header(name) string),
// letting this package stay free of an httpmsg import.
type HeaderGetter interface {
	Header(name string) string
}

// storageHeaders are response headers emitted by object-storage backends. Their
// presence on a response is a strong signal the host fronts object storage,
// regardless of the (possibly vanity) hostname.
var storageHeaders = []string{
	// AWS S3 and S3-compatible
	"x-amz-request-id", "x-amz-id-2", "x-amz-bucket-region",
	// Google Cloud Storage
	"x-goog-generation", "x-goog-metageneration", "x-goog-hash",
	"x-goog-stored-content-length", "x-goog-storage-class",
	// Azure Blob
	"x-ms-request-id", "x-ms-blob-type",
	// Volcano Engine TOS
	"x-tos-request-id", "x-tos-id-2",
	// Alibaba OSS / Tencent COS / Huawei OBS / Baidu BOS
	"x-oss-request-id", "x-cos-request-id", "x-obs-request-id", "x-bce-request-id",
}

// storageServerMarkers are substrings of the Server header that identify an
// object-storage backend. Kept to specific, multi-character tokens to avoid
// false positives (e.g. we do NOT substring-match "tos", which would hit
// "photos"; TOS is detected via x-tos-request-id instead).
var storageServerMarkers = []string{
	"amazons3", "uploadserver", "aliyunoss", "tencent-cos",
	"windows-azure-blob", "jets3t",
}

// ResponseHasStorageSignal reports whether a response carries an
// object-storage backend signature in its headers.
func ResponseHasStorageSignal(h HeaderGetter) bool {
	if h == nil {
		return false
	}
	for _, name := range storageHeaders {
		if h.Header(name) != "" {
			return true
		}
	}
	if server := strings.ToLower(h.Header("Server")); server != "" {
		for _, m := range storageServerMarkers {
			if strings.Contains(server, m) {
				return true
			}
		}
	}
	return false
}

// storageMounts are first path segments that commonly mount an object-storage
// proxy. The TOS/ByteStore gateway in the wild uses /obj/<bucket>/<object>.
var storageMounts = map[string]bool{
	"obj": true,
}

// KeepStaticAsMeta reports whether a static file should be recorded
// metadata-only (because it fronts object storage) rather than dropped during
// ingestion. Pass a non-nil resp only when a response is actually available
// (request-only ingest passes nil).
func KeepStaticAsMeta(path string, resp HeaderGetter) bool {
	if LooksLikeStorageObjectPath(path) {
		return true
	}
	if resp != nil {
		return ResponseHasStorageSignal(resp)
	}
	return false
}

// LooksLikeStorageObjectPath reports whether a URL path has the shape of an
// object-storage object fetch — a known storage mount segment followed by a
// bucket and at least one object segment, e.g. /obj/<bucket>/<object>.
func LooksLikeStorageObjectPath(path string) bool {
	segs := splitNonEmpty(path)
	if len(segs) < 3 {
		return false
	}
	return storageMounts[strings.ToLower(segs[0])]
}

// BucketPrefix returns the bucket-level prefix of an object path, used as the
// per-bucket dedup key (the traversal bug lives at the bucket, not the object).
// /obj/<bucket>/<key...> -> /obj/<bucket>; otherwise the first segment.
func BucketPrefix(path string) string {
	segs := splitNonEmpty(path)
	switch {
	case len(segs) >= 2 && storageMounts[strings.ToLower(segs[0])]:
		return "/" + segs[0] + "/" + segs[1]
	case len(segs) >= 1:
		return "/" + segs[0]
	default:
		return "/"
	}
}

// ObjectLeaf returns the last non-empty path segment (the object name), used
// for the semantic "did we list the directory containing our object?" check.
func ObjectLeaf(path string) string {
	segs := splitNonEmpty(path)
	if len(segs) == 0 {
		return ""
	}
	return segs[len(segs)-1]
}

// HostBucketKey returns a host|bucket-prefix dedup key for an absolute URL.
// Returns "" when the URL cannot be parsed or has no host.
func HostBucketKey(absURL string) string {
	u, err := url.Parse(absURL)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Hostname() + "|" + BucketPrefix(u.Path)
}

// Listing detection ---------------------------------------------------------

// StrongListing reports whether a response body is a genuine object-storage
// directory/bucket listing (not an <Error> document). It requires positive
// listing markers so a 404 "NoSuchKey" error never matches. The returned
// provider label is for finding evidence.
func StrongListing(body string) (provider string, ok bool) {
	if body == "" {
		return "", false
	}
	lb := strings.ToLower(body)
	// S3 / GCS XML (S3-compatible) listing.
	if strings.Contains(lb, "<listbucketresult") &&
		(strings.Contains(lb, "<contents>") || strings.Contains(lb, "<key>")) {
		return "s3-compatible", true
	}
	// Azure blob listing.
	if strings.Contains(lb, "<enumerationresults") &&
		(strings.Contains(lb, "<blob>") || strings.Contains(lb, "<blobs>")) {
		return "azure-blob", true
	}
	// GCS JSON listing.
	if strings.Contains(strings.ReplaceAll(lb, " ", ""), `"kind":"storage#objects"`) {
		return "gcs-json", true
	}
	return "", false
}

var (
	reXMLKey   = regexp.MustCompile(`(?i)<Key>([^<]+)</Key>`)
	reXMLName  = regexp.MustCompile(`(?i)<Name>([^<]+)</Name>`)
	reJSONName = regexp.MustCompile(`"name"\s*:\s*"([^"]+)"`)
)

// ListingKeys extracts object keys/names from a listing body (S3 <Key>, Azure
// <Name>, GCS JSON "name"), deduped and capped at max.
func ListingKeys(body string, max int) []string {
	if body == "" || max <= 0 {
		return nil
	}
	seen := make(map[string]struct{})
	var out []string
	add := func(matches [][]string) {
		for _, m := range matches {
			if len(m) < 2 {
				continue
			}
			k := strings.TrimSpace(m[1])
			if k == "" {
				continue
			}
			if _, dup := seen[k]; dup {
				continue
			}
			seen[k] = struct{}{}
			out = append(out, k)
			if len(out) >= max {
				return
			}
		}
	}
	add(reXMLKey.FindAllStringSubmatch(body, max))
	if len(out) < max {
		add(reXMLName.FindAllStringSubmatch(body, max))
	}
	if len(out) < max {
		add(reJSONName.FindAllStringSubmatch(body, max))
	}
	return out
}

// ListingContainsLeaf reports whether the listing keys include the object's
// leaf segment (exact match or as the final path component of a key), which
// confirms the traversal listed the directory actually containing our object.
func ListingContainsLeaf(keys []string, leaf string) bool {
	if leaf == "" {
		return false
	}
	for _, k := range keys {
		if k == leaf || strings.HasSuffix(k, "/"+leaf) {
			return true
		}
	}
	return false
}

// URL harvesting ------------------------------------------------------------

var storageURLPatterns = []*regexp.Regexp{
	// Vanity-CDN / TOS object-proxy shape: https://host/obj/<bucket>/<key>
	regexp.MustCompile(`https?://[a-zA-Z0-9._-]+/obj/[a-zA-Z0-9._-]+/[^\s"'<>)\]]+`),
	// AWS S3 (virtual-host and path style).
	regexp.MustCompile(`https?://[a-zA-Z0-9._-]+\.s3[.\-][a-zA-Z0-9._-]*amazonaws\.com/[^\s"'<>)\]]+`),
	regexp.MustCompile(`https?://s3[.\-][a-zA-Z0-9._-]*amazonaws\.com/[a-zA-Z0-9._-]+/[^\s"'<>)\]]+`),
	// Google Cloud Storage.
	regexp.MustCompile(`https?://storage\.googleapis\.com/[a-zA-Z0-9._-]+/[^\s"'<>)\]]+`),
	regexp.MustCompile(`https?://[a-zA-Z0-9._-]+\.storage\.googleapis\.com/[^\s"'<>)\]]+`),
}

// ExtractStorageURLs scans a (text) response body for absolute object-storage
// URLs, returning deduped matches capped at max.
func ExtractStorageURLs(body string, max int) []string {
	if body == "" || max <= 0 {
		return nil
	}
	seen := make(map[string]struct{})
	var out []string
	for _, re := range storageURLPatterns {
		for _, m := range re.FindAllString(body, max) {
			m = strings.TrimRight(m, ".,);'\"")
			if _, dup := seen[m]; dup {
				continue
			}
			seen[m] = struct{}{}
			out = append(out, m)
			if len(out) >= max {
				return out
			}
		}
	}
	return out
}

func splitNonEmpty(path string) []string {
	var out []string
	for _, p := range strings.Split(path, "/") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
