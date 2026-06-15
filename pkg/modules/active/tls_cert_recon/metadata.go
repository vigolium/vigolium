package tls_cert_recon

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "tls-cert-recon"
	ModuleName  = "TLS Certificate Recon"
	ModuleShort = "Reads each host's live TLS certificate for recon: self-signed / private-CA certs and the subdomains and internal names in their SANs"
)

var (
	ModuleDesc = `**What it means:** This check completes one TLS handshake per host and reads the leaf certificate. Public CA and CDN certs are skipped; what remains is recon-valuable self-signed or private-CA certs, from which it harvests Subject Alternative Names like sibling subdomains and internal IPs.

**How it's exploited:** A self-signed or internal-CA cert often marks forgotten staging or appliance infrastructure with weaker controls. Its SANs leak the org's naming - subdomains and internal hostnames disclose network layout for pivoting.

**Fix:** Serve a publicly trusted certificate on every internet-facing host, and keep certs naming internal hosts or private addresses off the internet.`

	ModuleConfirmation = "Confirmed by reading the leaf certificate during a live TLS handshake when its issuer is not a recognized public CA/CDN (self-signed or private/internal CA)"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"recon", "tls", "certificate", "fingerprint", "light"}
)
