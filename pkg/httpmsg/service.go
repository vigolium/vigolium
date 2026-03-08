package httpmsg

import "errors"

// Service represents an HTTP service (host, port, protocol).
type Service struct {
	host     string
	port     int
	protocol string // "http" or "https"
}

// extractHostname removes port suffix from host:port string.
// Handles IPv4 (192.168.1.1:3000), IPv6 ([::1]:8080), and hostname:port.
func extractHostname(hostWithPort string) string {
	if len(hostWithPort) == 0 {
		return hostWithPort
	}

	// Handle IPv6 with brackets: [::1]:8080 → ::1
	if hostWithPort[0] == '[' {
		// Find closing bracket
		for i := 1; i < len(hostWithPort); i++ {
			if hostWithPort[i] == ']' {
				// Return content inside brackets (without brackets)
				return hostWithPort[1:i]
			}
		}
		// Malformed, return as-is
		return hostWithPort
	}

	// Count colons - IPv6 without brackets has multiple colons
	colonCount := 0
	for i := 0; i < len(hostWithPort); i++ {
		if hostWithPort[i] == ':' {
			colonCount++
		}
	}

	// If more than one colon, this is likely IPv6 without brackets - don't strip
	if colonCount > 1 {
		return hostWithPort
	}

	// Handle IPv4/hostname: example.com:8080 → example.com
	// Find last colon (there's at most one)
	colonIdx := -1
	for i := len(hostWithPort) - 1; i >= 0; i-- {
		if hostWithPort[i] == ':' {
			colonIdx = i
			break
		}
	}
	if colonIdx != -1 {
		return hostWithPort[:colonIdx]
	}

	return hostWithPort
}

// NewService creates a new Service instance from protocol string.
func NewService(host string, port int, protocol string) (*Service, error) {
	host = extractHostname(host)
	if host == "" {
		return nil, errors.New("host cannot be null")
	}

	isHTTPS := false
	if EqualsIgnoreCase(protocol, "https") {
		isHTTPS = true
	} else if EqualsIgnoreCase(protocol, "http") {
		isHTTPS = false
	} else {
		return nil, errors.New("invalid protocol: " + protocol)
	}

	return NewServiceSecure(host, port, isHTTPS), nil
}

// NewServiceSecure creates a new Service instance from boolean flag.
func NewServiceSecure(host string, port int, useHTTPS bool) *Service {
	host = extractHostname(host)
	protocol := "http"
	if useHTTPS {
		protocol = "https"
	}

	return &Service{
		host:     host,
		port:     port,
		protocol: protocol,
	}
}

// Host returns the service hostname.
func (s *Service) Host() string {
	return s.host
}

// Port returns the service port.
func (s *Service) Port() int {
	return s.port
}

// Protocol returns the service protocol ("http" or "https").
func (s *Service) Protocol() string {
	return s.protocol
}

// ParseService parses a URL string and creates Service.
func ParseService(urlStr string) (*Service, error) {
	if urlStr == "" {
		return nil, errors.New("URL cannot be empty")
	}

	// Step 1: Find protocol (search for "://")
	protocolEnd := -1
	for i := 0; i < len(urlStr)-2; i++ {
		if urlStr[i] == ':' && urlStr[i+1] == '/' && urlStr[i+2] == '/' {
			protocolEnd = i
			break
		}
	}

	if protocolEnd == -1 {
		return nil, errors.New("URL must contain protocol (http:// or https://)")
	}

	protocol := urlStr[0:protocolEnd]
	if protocol != "http" && protocol != "https" {
		return nil, errors.New("protocol must be http or https")
	}

	// Step 2: Extract host and port
	hostStart := protocolEnd + 3
	if hostStart >= len(urlStr) {
		return nil, errors.New("URL must contain host")
	}

	hostEnd := len(urlStr)
	portStart := -1

	for i := hostStart; i < len(urlStr); i++ {
		if urlStr[i] == ':' {
			hostEnd = i
			portStart = i + 1
			break
		}
		if urlStr[i] == '/' {
			hostEnd = i
			break
		}
	}

	host := urlStr[hostStart:hostEnd]
	if host == "" {
		return nil, errors.New("URL must contain host")
	}

	// Step 3: Extract port or use default
	port := 80
	if protocol == "https" {
		port = 443
	}

	if portStart != -1 {
		portEnd := len(urlStr)
		for i := portStart; i < len(urlStr); i++ {
			if urlStr[i] == '/' {
				portEnd = i
				break
			}
		}

		portStr := urlStr[portStart:portEnd]
		if portStr != "" {
			parsedPort := 0
			for i := 0; i < len(portStr); i++ {
				if portStr[i] < '0' || portStr[i] > '9' {
					return nil, errors.New("invalid port number")
				}
				parsedPort = parsedPort*10 + int(portStr[i]-'0')
			}
			port = parsedPort
		}
	}

	return NewServiceSecure(host, port, protocol == "https"), nil
}

// EqualsIgnoreCase compares two strings case-insensitively.
func EqualsIgnoreCase(a, b string) bool {
	if len(a) != len(b) {
		return false
	}

	for i := 0; i < len(a); i++ {
		if ToLower(a[i]) != ToLower(b[i]) {
			return false
		}
	}

	return true
}
