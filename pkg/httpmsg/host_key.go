package httpmsg

import (
	"net"
	"net/url"
	"strconv"
	"strings"
)

// The canonical host identities. Every key is lower-cased, brackets an IPv6
// host and always carries the port (the scheme's default when the URL names
// none), so http://A and http://a:80 share a key while http://a and https://a
// do not.

// HostPort is the canonical "host:port" key for host and port.
func HostPort(host string, port int) string {
	return strings.ToLower(net.JoinHostPort(host, strconv.Itoa(port)))
}

// URLHostPort is u's canonical "host:port", the port defaulted from the
// scheme (80 for an unknown one). "" when u names no host.
func URLHostPort(u *url.URL) string {
	if u == nil || u.Hostname() == "" {
		return ""
	}
	port := u.Port()
	if port == "" {
		p := GetDefaultPort(u.Scheme)
		if p < 0 {
			p = 80
		}
		port = strconv.Itoa(p)
	}
	return strings.ToLower(net.JoinHostPort(u.Hostname(), port))
}

// URLOrigin is u's canonical "scheme://host:port"; "" when u names no host.
func URLOrigin(u *url.URL) string {
	hp := URLHostPort(u)
	if hp == "" {
		return ""
	}
	return strings.ToLower(u.Scheme) + "://" + hp
}

// HostPortKey returns rr's "host:port" from its service, or "" when rr has no
// service. It is the dead-host breaker's key: unlike ID() it carries no
// method, so a host that stopped answering GETs is quarantined for POSTs too,
// and it is readable enough to report as-is.
func HostPortKey(rr *HttpRequestResponse) string {
	if rr == nil {
		return ""
	}
	service := rr.Service()
	if service == nil || service.Host() == "" {
		return ""
	}
	return HostPort(service.Host(), service.Port())
}

// TargetHostPortKey is HostPortKey falling back to the request URL when the
// service names no host (an absolute-form request line carries its own).
func TargetHostPortKey(rr *HttpRequestResponse) string {
	_, hp := rr.endpoint()
	return hp
}

// OriginKey returns rr's "scheme://host:port", from its service, else from its
// request URL; "" when neither names a host.
func OriginKey(rr *HttpRequestResponse) string {
	scheme, hp := rr.endpoint()
	if hp == "" {
		return ""
	}
	return scheme + "://" + hp
}

// endpoint returns rr's scheme and canonical host:port, from its service when
// that names a host, else from its request URL.
func (h *HttpRequestResponse) endpoint() (scheme, hostPort string) {
	if h == nil {
		return "", ""
	}
	if svc := h.Service(); svc != nil && svc.Host() != "" {
		return svc.Protocol(), HostPort(svc.Host(), svc.Port())
	}
	if u, err := h.sharedURL(); err == nil && u != nil && u.URL != nil {
		return strings.ToLower(u.Scheme), URLHostPort(u.URL)
	}
	return "", ""
}
