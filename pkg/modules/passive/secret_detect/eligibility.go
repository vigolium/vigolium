package secret_detect

import pkghttp "github.com/vigolium/vigolium/pkg/deparos/http"

// ShouldScanBody is the shared secret-scan eligibility policy (non-empty, within
// the size cap, not media, text MIME). It delegates to pkghttp — which owns the
// implementation next to IsMediaContent — so the passive module, the
// known-issue-scan batch, and the discovery crawl can't drift on what reaches the
// detector.
func ShouldScanBody(contentType, urlPath string, bodyLen int) bool {
	return pkghttp.ShouldScanBodyForSecrets(contentType, urlPath, bodyLen)
}
