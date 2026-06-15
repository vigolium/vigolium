package tls_cert_recon

import "strings"

// commonIssuerMarkers are lowercase substrings that identify well-known public
// CAs and CDN issuers. A leaf certificate whose issuer Organization or Common
// Name contains any of them is treated as ordinary public infrastructure and
// skipped entirely — no SAN harvest, no finding. The recon value lives in the
// certificates these CAs do NOT sign: self-signed and private/internal-CA certs.
//
// This list does double duty: it is also the inverse definition of a
// "private/internal CA" — a non-self-signed cert whose issuer matches nothing
// here is classified as private-CA. Seed it with the major public CAs so they
// are not misclassified; it is meant to be extended.
var commonIssuerMarkers = []string{
	// ACME / Let's Encrypt
	"let's encrypt", "lets encrypt", "isrg",
	// DigiCert and its legacy brands
	"digicert", "geotrust", "rapidssl", "thawte", "verisign", "cybertrust",
	// Sectigo / Comodo
	"sectigo", "comodo", "usertrust", "aaa certificate services",
	// CDNs that front many sites
	"cloudflare", "akamai", "fastly",
	// Large platform / cloud CAs
	"globalsign", "google trust services", "amazon", "microsoft", "apple",
	// Retail CAs
	"godaddy", "starfield", "entrust", "zerossl", "buypass", "certum",
	"ssl.com", "actalis", "gandi", "identrust", "quovadis",
}

// isCommonIssuer reports whether the certificate was issued by a recognized
// public CA / CDN, matched case-insensitively against the issuer Organization
// and Common Name.
func isCommonIssuer(issuerOrg, issuerCN string) bool {
	hay := strings.ToLower(issuerOrg + "\x00" + issuerCN)
	for _, m := range commonIssuerMarkers {
		if strings.Contains(hay, m) {
			return true
		}
	}
	return false
}
