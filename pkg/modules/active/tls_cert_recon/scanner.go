package tls_cert_recon

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/reconsig"
)

// dialTimeout bounds the per-host TLS handshake. The module opens its own
// connection (the shared HTTP requester does not surface the peer certificate),
// so this is the only knob keeping a dead or slow host from stalling the host
// worker. One handshake per host, status-independent.
const dialTimeout = 7 * time.Second

var (
	errNoTLSConn  = errors.New("connection is not TLS")
	errNoPeerCert = errors.New("server presented no certificate")
)

// internalSuffixes are DNS suffixes that never resolve publicly. A SAN ending
// in one of these (or a single-label name) discloses internal naming.
var internalSuffixes = []string{
	".local", ".internal", ".intranet", ".corp", ".lan", ".home",
	".localdomain", ".private", ".test", ".example", ".invalid", ".localhost",
}

// Module implements the TLS Certificate Recon active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new TLS Certificate Recon module.
func New() *Module {
	m := &Module{
		BaseActiveModule: modkit.NewBaseActiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeHost,
			modkit.AllInsertionPointTypes,
		),
		ds: dedup.LazyDiskSet("tls_cert_recon"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// IncludesBaseCanProcess returns false because this module uses a custom CanProcess.
func (m *Module) IncludesBaseCanProcess() bool { return false }

// CanProcess accepts any request that carries a resolvable service; the TLS /
// scheme gating happens once per host inside ScanPerHost.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	return ctx != nil && ctx.Request() != nil && ctx.Service() != nil
}

// ScanPerHost reads the host's live leaf certificate once and reports it when it
// is self-signed or issued by a private/internal CA (public-CA/CDN certs are
// skipped). It harvests apex-scoped subdomains and internal names from the SANs.
func (m *Module) ScanPerHost(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	service := ctx.Service()
	if service == nil {
		return nil, nil
	}
	// TLS recon only applies to HTTPS endpoints; never speculatively knock on
	// 443 for a plain-HTTP service.
	if !strings.EqualFold(service.Protocol(), "https") {
		return nil, nil
	}

	host := service.Host()
	if host == "" {
		return nil, nil
	}
	port := service.Port()
	if port == 0 {
		port = 443
	}

	// One handshake per host:port for the whole scan.
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	dedupKey := net.JoinHostPort(host, strconv.Itoa(port))
	if diskSet != nil && diskSet.IsSeen(dedupKey) {
		return nil, nil
	}

	cert, resolvedIP, err := fetchLeafCert(host, port, dialTimeout)
	if err != nil || cert == nil {
		return nil, nil // host down, not TLS, or no cert — nothing to report
	}

	// Issuer gate: a recognized public CA / CDN is ordinary infrastructure —
	// skip the certificate entirely (no harvest, no finding).
	issuerOrg := strings.Join(cert.Issuer.Organization, ", ")
	if isCommonIssuer(issuerOrg, cert.Issuer.CommonName) {
		return nil, nil
	}

	selfSigned := bytes.Equal(cert.RawIssuer, cert.RawSubject)
	certType := "private-ca"
	name := "Private/Internal CA TLS Certificate"
	if selfSigned {
		certType = "self-signed"
		name = "Self-Signed TLS Certificate"
	}

	buckets := classifySANs(host, cert.DNSNames, cert.IPAddresses, cert.Subject.CommonName)

	// Under --follow-subdomains, pull each in-scope SAN host into the scan: add
	// the EXACT host to the runtime allow-set (never the apex wildcard) and feed
	// its root URL back for scanning, exactly like subdomain_harvest.
	fed := 0
	if len(buckets.inScope) > 0 && scanCtx.ShouldFollowSubdomains() {
		feeder := scanCtx.Feeder()
		for _, h := range buckets.inScope {
			scanCtx.AllowHost(h)
			if rr, rerr := httpmsg.GetRawRequestFromURL("https://" + h + "/"); rerr == nil && feeder.Feed(rr) {
				fed++
			}
		}
	}

	issuerLabel := issuerOrg
	if issuerLabel == "" {
		issuerLabel = cert.Issuer.CommonName
	}
	if issuerLabel == "" {
		issuerLabel = "unknown"
	}

	extracted := []string{
		"Certificate type: " + certType,
		"Issuer: " + cert.Issuer.String(),
		"Subject: " + cert.Subject.String(),
		fmt.Sprintf("Validity: %s — %s", cert.NotBefore.UTC().Format("2006-01-02"), cert.NotAfter.UTC().Format("2006-01-02")),
	}
	for _, h := range buckets.inScope {
		extracted = append(extracted, "In-scope SAN: "+h)
	}
	for _, h := range buckets.internal {
		extracted = append(extracted, "Internal SAN: "+h)
	}

	tags := append([]string{}, ModuleTags...)
	tags = append(tags, certType)
	if len(buckets.internal) > 0 {
		tags = append(tags, "internal-naming")
	}

	var desc strings.Builder
	fmt.Fprintf(&desc, "Host '%s' presents a %s TLS certificate (issuer: %s). ", host, certType, issuerLabel)
	if selfSigned {
		desc.WriteString("The certificate is self-signed, which commonly marks staging, admin, or appliance infrastructure not intended for public trust. ")
	} else {
		desc.WriteString("It was issued by a private or internal CA rather than a recognized public authority, a pattern typical of internal-only infrastructure. ")
	}
	if len(buckets.inScope) > 0 {
		fmt.Fprintf(&desc, "%d in-scope subdomain(s) sharing the target's registrable domain were found in its SANs. ", len(buckets.inScope))
	}
	if len(buckets.internal) > 0 {
		fmt.Fprintf(&desc, "%d internal name(s)/private address(es) are embedded in its SANs, disclosing internal naming. ", len(buckets.internal))
	}
	if fed > 0 {
		fmt.Fprintf(&desc, "%d host(s) were added to scope and queued for scanning (--follow-subdomains).", fed)
	}

	target := ctx.Target()
	if target == "" {
		target = "https://" + dedupKey + "/"
	}

	meta := map[string]any{
		"cert_type":     certType,
		"self_signed":   selfSigned,
		"issuer":        cert.Issuer.String(),
		"issuer_org":    issuerOrg,
		"subject":       cert.Subject.String(),
		"subject_cn":    cert.Subject.CommonName,
		"not_before":    cert.NotBefore.UTC().Format(time.RFC3339),
		"not_after":     cert.NotAfter.UTC().Format(time.RFC3339),
		"serial":        cert.SerialNumber.String(),
		"sig_algorithm": cert.SignatureAlgorithm.String(),
		"san_dns":       cert.DNSNames,
		"in_scope_sans": buckets.inScope,
		"internal_sans": buckets.internal,
	}
	if resolvedIP != "" {
		meta["resolved_ip"] = resolvedIP
	}

	return []*output.ResultEvent{{
		ModuleID:         ModuleID,
		Host:             host,
		URL:              target,
		Matched:          target,
		IP:               resolvedIP,
		ExtractedResults: extracted,
		Info: output.Info{
			Name:        name,
			Description: desc.String(),
			Severity:    ModuleSeverity,
			Confidence:  ModuleConfidence,
			Tags:        tags,
		},
		Metadata: meta,
	}}, nil
}

// fetchLeafCert completes a TLS handshake to host:port and returns the leaf
// certificate plus the resolved peer IP. Certificate validation is intentionally
// disabled — scan targets routinely present expired, self-signed, or otherwise
// invalid certificates, which is exactly the signal this module reads.
func fetchLeafCert(host string, port int, timeout time.Duration) (*x509.Certificate, string, error) {
	if port == 0 {
		port = 443
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: timeout},
		Config: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // intentional: we inspect untrusted certs
			MinVersion:         tls.VersionTLS10,
			ServerName:         sniName(host),
		},
	}

	dctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	conn, err := dialer.DialContext(dctx, "tcp", addr)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = conn.Close() }()

	tconn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, "", errNoTLSConn
	}
	state := tconn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, "", errNoPeerCert
	}

	resolvedIP := ""
	if ra := conn.RemoteAddr(); ra != nil {
		if h, _, e := net.SplitHostPort(ra.String()); e == nil {
			resolvedIP = h
		}
	}
	return state.PeerCertificates[0], resolvedIP, nil
}

// sniName returns the SNI server name to send. IP literals are not valid SNI
// values (and Go would drop them), so dial without SNI in that case.
func sniName(host string) string {
	if net.ParseIP(host) != nil {
		return ""
	}
	return host
}

// sanBuckets splits a certificate's SANs into the two recon-relevant sets.
type sanBuckets struct {
	inScope  []string // hostnames sharing the target's registrable domain
	internal []string // internal-only hostnames and private/loopback IP addresses
}

// classifySANs splits the certificate's DNS-name SANs (plus the Subject CN) and
// IP SANs into in-scope subdomains and internal names. The target host itself
// and public hosts outside the target's registrable domain are ignored.
func classifySANs(targetHost string, dnsNames []string, ips []net.IP, cn string) sanBuckets {
	target := reconsig.NormalizeHost(targetHost)
	apex := reconsig.RegistrableDomain(targetHost)
	suffix := ""
	if apex != "" {
		suffix = "." + apex
	}

	var b sanBuckets
	seen := make(map[string]struct{})
	add := func(list *[]string, v string) {
		if v == "" {
			return
		}
		if _, dup := seen[v]; dup {
			return
		}
		seen[v] = struct{}{}
		*list = append(*list, v)
	}

	names := make([]string, 0, len(dnsNames)+1)
	names = append(names, dnsNames...)
	if cn != "" {
		names = append(names, cn)
	}
	for _, raw := range names {
		h := normalizeSANHost(raw)
		if h == "" || h == target {
			continue
		}
		switch {
		case apex != "" && (h == apex || strings.HasSuffix(h, suffix)):
			add(&b.inScope, h)
		case isInternalHostname(h):
			add(&b.internal, h)
		default:
			// Public host outside the target's registrable domain (shared/CDN
			// cert or an unrelated domain) — not our recon target.
		}
	}

	for _, ip := range ips {
		if isInternalIP(ip) {
			add(&b.internal, ip.String())
		}
	}
	return b
}

// normalizeSANHost lowercases a SAN DNS entry, drops a leading wildcard label,
// and strips port/dots so it can be compared against the target apex.
func normalizeSANHost(h string) string {
	h = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(h)), "*.")
	return reconsig.NormalizeHost(h)
}

// isInternalHostname reports whether a hostname is internal-only: a single-label
// name (never publicly routable) or one under a non-public DNS suffix. It
// normalizes its input so it is safe to call on a raw SAN entry or a value
// already passed through normalizeSANHost.
func isInternalHostname(h string) bool {
	h = normalizeSANHost(h)
	if h == "" {
		return false
	}
	if !strings.Contains(h, ".") {
		return true
	}
	for _, s := range internalSuffixes {
		if strings.HasSuffix(h, s) {
			return true
		}
	}
	return false
}

// isInternalIP reports whether an IP SAN points at non-public space: RFC1918 /
// ULA private ranges, loopback, link-local, unspecified, or CGNAT (RFC6598).
func isInternalIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
		return true
	}
	return false
}
