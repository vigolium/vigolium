package tls_protocol_cipher_audit

import (
	"context"
	"crypto/tls"
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
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// dialTimeout bounds each TLS handshake this module opens. It runs several probes
// per host (one baseline + one per weak setting, each re-confirmed), all serialized
// on the host worker, so the timeout keeps a slow/dead host from stalling the scan.
const dialTimeout = 7 * time.Second

// weakProbe is one weak-TLS configuration to test. A successful handshake with
// exactly this protocol range / cipher set is deterministic proof the server
// supports it — there is no false positive, only a negotiated fact.
type weakProbe struct {
	tag      string
	label    string
	severity severity.Severity
	minVer   uint16
	maxVer   uint16
	ciphers  []uint16 // nil = library default set for the version range
}

// weakProbes is the audit matrix. Protocol probes pin Min==Max to force one
// version; cipher probes pin a single weak family across TLS 1.0–1.2 (cipher
// selection is a no-op under TLS 1.3, so the range is capped there). NULL/anon/
// EXPORT suites and TLS-level compression are intentionally omitted: the Go TLS
// stack cannot offer them as a client, so they can't be tested honestly here.
var weakProbes = []weakProbe{
	{
		tag:      "tls10",
		label:    "TLS 1.0 enabled (deprecated — RFC 8996)",
		severity: severity.Medium,
		minVer:   tls.VersionTLS10,
		maxVer:   tls.VersionTLS10,
	},
	{
		tag:      "tls11",
		label:    "TLS 1.1 enabled (deprecated — RFC 8996)",
		severity: severity.Medium,
		minVer:   tls.VersionTLS11,
		maxVer:   tls.VersionTLS11,
	},
	{
		tag:      "rc4",
		label:    "RC4 cipher suite accepted (cryptographically broken)",
		severity: severity.Medium,
		minVer:   tls.VersionTLS10,
		maxVer:   tls.VersionTLS12,
		ciphers: []uint16{
			tls.TLS_RSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
		},
	},
	{
		tag:      "3des",
		label:    "3DES cipher suite accepted (Sweet32 — CVE-2016-2183)",
		severity: severity.Low,
		minVer:   tls.VersionTLS10,
		maxVer:   tls.VersionTLS12,
		ciphers: []uint16{
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		},
	},
	{
		tag:      "no-pfs",
		label:    "Static-RSA key exchange accepted (no forward secrecy)",
		severity: severity.Low,
		minVer:   tls.VersionTLS10,
		maxVer:   tls.VersionTLS12,
		ciphers: []uint16{
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	},
}

// Module implements the TLS Protocol & Cipher Audit active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new TLS Protocol & Cipher Audit module.
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
		ds: dedup.LazyDiskSet("tls_protocol_cipher_audit"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// IncludesBaseCanProcess returns false because this module uses a custom CanProcess.
func (m *Module) IncludesBaseCanProcess() bool { return false }

// CanProcess accepts any request carrying a resolvable service; the HTTPS/TLS
// gate is applied once per host inside ScanPerHost.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	return ctx != nil && ctx.Request() != nil && ctx.Service() != nil
}

// ScanPerHost audits the host's TLS configuration. It first confirms the host
// actually speaks TLS (a baseline handshake) — the technology gate — then probes
// each weak protocol/cipher setting, re-confirming every hit with a second
// handshake before reporting. A host that only supports TLS 1.2+/forward-secret
// AEAD suites yields no finding.
func (m *Module) ScanPerHost(
	ctx *httpmsg.HttpRequestResponse,
	_ *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	service := ctx.Service()
	if service == nil {
		return nil, nil
	}
	// Only audit HTTPS endpoints; never speculatively knock on 443 for plain HTTP.
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

	// One audit per host:port for the whole scan.
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	dedupKey := net.JoinHostPort(host, strconv.Itoa(port))
	if diskSet != nil && diskSet.IsSeen(dedupKey) {
		return nil, nil
	}

	// Technology gate: only audit hosts that actually complete a TLS handshake.
	// A default (library-chosen) handshake failing means the host is down, not TLS,
	// or otherwise unreachable — nothing to audit, fail closed.
	if _, ok := handshake(host, port, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // intentional: audit untrusted TLS
		MinVersion:         tls.VersionTLS10,
		ServerName:         sniName(host),
	}); !ok {
		return nil, nil
	}

	var findings []weakFinding
	for _, p := range weakProbes {
		cfg := &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // intentional: audit untrusted TLS
			MinVersion:         p.minVer,
			MaxVersion:         p.maxVer,
			ServerName:         sniName(host),
		}
		if len(p.ciphers) > 0 {
			cfg.CipherSuites = p.ciphers
		}

		state, ok := handshake(host, port, cfg)
		if !ok {
			continue
		}
		// Multi-round confirmation: re-verify with a second independent handshake so
		// a transient success can't produce a finding.
		if _, ok2 := handshake(host, port, cfg); !ok2 {
			continue
		}
		findings = append(findings, weakFinding{
			probe:   p,
			version: state.Version,
			cipher:  state.CipherSuite,
		})
	}

	if len(findings) == 0 {
		return nil, nil
	}

	return []*output.ResultEvent{m.buildResult(ctx, host, dedupKey, findings)}, nil
}

// weakFinding records a confirmed weak setting and what was actually negotiated.
type weakFinding struct {
	probe   weakProbe
	version uint16
	cipher  uint16
}

// buildResult assembles a single finding listing every confirmed weak setting for
// the host, with severity set to the worst item found.
func (m *Module) buildResult(ctx *httpmsg.HttpRequestResponse, host, dedupKey string, findings []weakFinding) *output.ResultEvent {
	worst := severity.Info
	extracted := make([]string, 0, len(findings))
	tags := append([]string{}, ModuleTags...)
	weakList := make([]string, 0, len(findings))
	for _, f := range findings {
		if f.probe.severity > worst {
			worst = f.probe.severity
		}
		extracted = append(extracted, fmt.Sprintf("%s [negotiated %s / %s]",
			f.probe.label, tls.VersionName(f.version), tls.CipherSuiteName(f.cipher)))
		tags = append(tags, f.probe.tag)
		weakList = append(weakList, f.probe.label)
	}

	target := ctx.Target()
	if target == "" {
		target = "https://" + dedupKey + "/"
	}

	var desc strings.Builder
	fmt.Fprintf(&desc, "Host '%s' negotiated %d weak TLS setting(s) via direct handshake: %s. ",
		host, len(findings), strings.Join(weakList, "; "))
	desc.WriteString("Each was confirmed by completing a real TLS handshake at that setting (re-verified with a second handshake), so it is a negotiated fact rather than a heuristic. ")
	desc.WriteString("Disable deprecated protocols (require TLS 1.2+) and remove RC4/3DES/static-RSA suites in favour of forward-secret AEAD ciphers.")

	return &output.ResultEvent{
		ModuleID:         ModuleID,
		Host:             host,
		URL:              target,
		Matched:          target,
		ExtractedResults: extracted,
		Info: output.Info{
			Name:        "Weak TLS Protocol / Cipher Configuration",
			Description: desc.String(),
			Severity:    worst,
			Confidence:  ModuleConfidence,
			Tags:        tags,
		},
		Metadata: map[string]any{
			"weak_settings": weakList,
		},
	}
}

// handshake opens a TLS connection to host:port with cfg and returns the resulting
// connection state. ok is true only when the handshake completes — for a probe
// that pins a weak protocol/cipher, ok==true is deterministic proof the server
// accepts it. Certificate validation is disabled (scan targets routinely present
// untrusted certs); this module reads the negotiated protocol/cipher, not trust.
func handshake(host string, port int, cfg *tls.Config) (tls.ConnectionState, bool) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: dialTimeout},
		Config:    cfg,
	}
	dctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()

	conn, err := dialer.DialContext(dctx, "tcp", addr)
	if err != nil {
		return tls.ConnectionState{}, false
	}
	defer func() { _ = conn.Close() }()

	tconn, ok := conn.(*tls.Conn)
	if !ok {
		return tls.ConnectionState{}, false
	}
	return tconn.ConnectionState(), true
}

// sniName returns the SNI value to send. IP literals are not valid SNI values, so
// dial without SNI in that case.
func sniName(host string) string {
	if net.ParseIP(host) != nil {
		return ""
	}
	return host
}
