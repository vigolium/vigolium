package database

import (
	"net"
	"net/url"
	"strconv"
	"strings"
)

// AuthHostKey is the key a session is stored under in
// authentication_hostnames: the lowercased hostname, with the port only when
// it is not the scheme's default ("app.test", "127.0.0.1:8080"). target may
// be a URL or a host[:port]; scheme defaults to https for a bare host. Every
// writer and reader goes through it, so a session loaded for
// http://127.0.0.1:28942 is found by a scan of that URL and by replay of a
// record on it.
func AuthHostKey(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return ""
	}
	scheme, hostport := "https", target
	if strings.Contains(target, "://") {
		u, err := url.Parse(target)
		if err != nil || u.Host == "" {
			return strings.ToLower(target)
		}
		scheme, hostport = strings.ToLower(u.Scheme), u.Host
	}
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return strings.ToLower(strings.Trim(hostport, "[]"))
	}
	return AuthHostKeyFor(scheme, host, port)
}

// AuthHostKeyFor is AuthHostKey from parts; port "" or 0 means the default.
func AuthHostKeyFor(scheme, host, port string) string {
	host = strings.ToLower(strings.Trim(host, "[]"))
	if port == "" || port == "0" || isDefaultSchemePort(scheme, port) {
		return host
	}
	return net.JoinHostPort(host, port)
}

// AuthHostLookupKeys are the keys a reader tries, in order: the exact key,
// then the bare hostname (sessions stored without a port).
func AuthHostLookupKeys(key string) []string {
	keys := []string{key}
	if h, _, err := net.SplitHostPort(key); err == nil && h != key {
		keys = append(keys, strings.Trim(h, "[]"))
	}
	return keys
}

func isDefaultSchemePort(scheme, port string) bool {
	n, err := strconv.Atoi(port)
	if err != nil {
		return false
	}
	switch strings.ToLower(scheme) {
	case "http", "ws":
		return n == 80
	case "https", "wss", "":
		return n == 443
	}
	return false
}
