package http

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"syscall"

	"github.com/vigolium/vigolium/pkg/core/hosterrors"
)

// Transport error classes returned by ClassifyTransportError. They are stable,
// machine-readable codes: they appear in scan outcomes and -j documents.
const (
	TransportErrDNS     = "dns"     // name did not resolve
	TransportErrRefused = "refused" // nothing listening / every dial refused
	TransportErrTimeout = "timeout" // dial, handshake or response deadline
	TransportErrTLS     = "tls"     // handshake or certificate failure
	TransportErrReset   = "reset"   // peer reset or closed the connection
	TransportErrOther   = "other"   // anything else
)

// DescribeTransportClass renders a TransportErr* class as the short phrase a
// console line uses ("connection refused", "DNS lookup failed"), so every
// "unreachable (...)" line words the same class the same way. An unknown or
// empty class falls back to "no HTTP answer".
func DescribeTransportClass(class string) string {
	switch class {
	case TransportErrDNS:
		return "DNS lookup failed"
	case TransportErrRefused:
		return "connection refused"
	case TransportErrTimeout:
		return "timed out"
	case TransportErrTLS:
		return "TLS handshake failed"
	case TransportErrReset:
		return "connection reset"
	default:
		return "no HTTP answer"
	}
}

// ClassifyTransportError maps an error from sending a request to one of the
// TransportErr* classes, or "" for a nil error. It answers "why did this target
// not answer" for the never-silent reporting (baseline failures, preflight,
// heuristics, doctor), so one target is not called "refused" by one path and
// "request failed" by another.
//
// Typed checks (net/syscall/tls/x509 errors through errors.As/Is) come first.
// The string fallback exists because the dialer (fastdialer) and the retrying
// client report some failures as text: "could not resolve host", "no address
// found for host", and "giving up after N attempts" wrappers whose cause is
// only in the message.
func ClassifyTransportError(err error) string {
	if err == nil {
		return ""
	}
	if class := classifyTypedTransportError(err); class != "" {
		return class
	}
	return classifyTransportErrorText(strings.ToLower(err.Error()))
}

// IsTransientTransportError reports a send failure that says nothing about the
// target's answer: a DNS, refused, timeout, TLS or reset failure, or a host the
// breaker has quarantined. A request abandoned because its module call timed
// out is not one (its message reads like a timeout): the caller gave up, the
// host did not fail.
func IsTransientTransportError(err error) bool {
	if err == nil || errors.Is(err, ErrRequestAbandoned) {
		return false
	}
	if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
		return true
	}
	switch ClassifyTransportError(err) {
	case TransportErrDNS, TransportErrRefused, TransportErrTimeout, TransportErrTLS, TransportErrReset:
		return true
	}
	return false
}

func classifyTypedTransportError(err error) string {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return TransportErrDNS
	}
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return TransportErrRefused
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.ECONNABORTED),
		errors.Is(err, syscall.EPIPE), errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, io.EOF):
		return TransportErrReset
	}

	var (
		recordErr  tls.RecordHeaderError
		alertErr   tls.AlertError
		verifyErr  *tls.CertificateVerificationError
		unknownCA  x509.UnknownAuthorityError
		hostErr    x509.HostnameError
		invalidErr x509.CertificateInvalidError
	)
	if errors.As(err, &recordErr) || errors.As(err, &alertErr) || errors.As(err, &verifyErr) ||
		errors.As(err, &unknownCA) || errors.As(err, &hostErr) || errors.As(err, &invalidErr) {
		return TransportErrTLS
	}

	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return TransportErrTimeout
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return TransportErrTimeout
	}
	return ""
}

// transportErrorMarkers are checked in order; the first class with a matching
// marker wins. Timeout precedes TLS so "TLS handshake timeout" is a timeout, and
// the generic fastdialer "could not connect" comes last so a wrapped, more
// specific cause in the same message wins over it.
var transportErrorMarkers = []struct {
	class   string
	markers []string
}{
	{TransportErrDNS, []string{"no such host", "could not resolve host", "no address found for host", "server misbehaving"}},
	{TransportErrRefused, []string{"connection refused", "actively refused"}},
	{TransportErrReset, []string{"connection reset", "broken pipe", "connection aborted", "unexpected eof", "server closed idle connection"}},
	{TransportErrTimeout, []string{"timeout", "timed out", "deadline exceeded"}},
	{TransportErrTLS, []string{"tls:", "x509:", "certificate", "tls handshake", "first record does not look like a tls handshake"}},
	{TransportErrRefused, []string{"could not connect to any address found for host"}},
}

func classifyTransportErrorText(msg string) string {
	for _, group := range transportErrorMarkers {
		for _, marker := range group.markers {
			if strings.Contains(msg, marker) {
				return group.class
			}
		}
	}
	if strings.HasSuffix(msg, ": eof") || msg == "eof" {
		return TransportErrReset
	}
	return TransportErrOther
}
