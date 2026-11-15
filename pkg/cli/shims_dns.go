package cli

import (
	"net"
	"slices"
	"strings"

	"github.com/vigolium/vigolium/pkg/dnsresolve"
)

// dig and host route to `vigolium dns`, so the answers land in the store
// instead of scrolling past. Their argv is not flag-shaped the way the other
// tools' is (`dig +short MX example.com @1.1.1.1`), so they translate by token
// rather than through shimArgs.drive; the rule tables exist for --help and the
// global-flag collision set.

func digRules() map[string]shimRule {
	return map[string]shimRule{
		"t":      {doc: "-t TYPE → --type TYPE"},
		"p":      {doc: "-p PORT → the port of every @server"},
		"x":      {refuse: "reverse lookups are not supported", doc: "refused (reverse lookup)"},
		"@":      {doc: "@server → --resolver server"},
		"+short": {doc: "+options are accepted (no-op): output is vigolium's"},
		"TYPE":   {doc: "a record type (A, AAAA, CNAME, MX, NS, TXT, SOA, CAA; ANY = all) → --type"},
	}
}

func hostRules() map[string]shimRule {
	return map[string]shimRule{
		"t":      {doc: "-t TYPE → --type TYPE"},
		"a":      {doc: "-a → every type"},
		"v":      {doc: "accepted (no-op)"},
		"SERVER": {doc: "a second positional → --resolver"},
	}
}

// dnsTypeToken reports whether tok names a record type dns resolves; ANY is
// every type.
func dnsTypeToken(tok string) (string, bool) {
	t := strings.ToLower(tok)
	if t == "any" {
		return "all", true
	}
	if slices.Contains(dnsresolve.Types, t) {
		return t, true
	}
	return "", false
}

// knownDNSTypes are record type names dig accepts as a bare positional. One
// that `vigolium dns` does not resolve is refused rather than looked up as a
// host name ("dig example.com SRV" must not become an A lookup of "SRV").
var knownDNSTypes = []string{
	"a", "aaaa", "afsdb", "apl", "caa", "cdnskey", "cds", "cert", "cname", "dhcid",
	"dlv", "dname", "dnskey", "ds", "hinfo", "hip", "https", "ipseckey", "key", "kx",
	"loc", "mx", "naptr", "ns", "nsec", "nsec3", "nsec3param", "openpgpkey", "ptr",
	"rp", "rrsig", "sig", "smimea", "soa", "spf", "srv", "sshfp", "svcb", "ta",
	"tkey", "tlsa", "tsig", "txt", "uri", "zonemd",
}

// unsupportedDNSType reports whether tok names a record type that `vigolium
// dns` does not resolve.
func unsupportedDNSType(tok string) bool {
	if _, ok := dnsTypeToken(tok); ok {
		return false
	}
	return slices.Contains(knownDNSTypes, strings.ToLower(tok))
}

// dnsArgv assembles the native command line.
func dnsArgv(names, types, servers []string, port string) []string {
	argv := []string{"dns"}
	argv = append(argv, names...)
	all := false
	var ts []string
	for _, t := range types {
		if t == "all" {
			all = true
			continue
		}
		ts = append(ts, t)
	}
	if len(ts) > 0 && !all {
		argv = append(argv, "--type", strings.Join(ts, ","))
	}
	for _, s := range servers {
		if port != "" && !strings.Contains(s, ":") {
			s += ":" + port
		}
		argv = append(argv, "--resolver", s)
	}
	return argv
}

func translateDig(args []string) (shimTranslation, error) {
	var names, types, servers, notes []string
	port := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case strings.HasPrefix(a, "@"):
			servers = append(servers, a[1:])
		case strings.HasPrefix(a, "+"):
			if len(notes) == 0 {
				notes = append(notes, "dig +options are accepted as no-ops: the answer shape is vigolium's")
			}
		case a == "-t" || a == "-p":
			if i+1 >= len(args) {
				return shimTranslation{}, usageErrorf("dig: %s needs a value", a)
			}
			i++
			if a == "-p" {
				port = args[i]
				continue
			}
			t, ok := dnsTypeToken(args[i])
			if !ok {
				return shimTranslation{}, usageErrorf("dig: record type %q is not supported by `vigolium dns` (types: %s)", args[i], strings.Join(dnsresolve.Types, ", "))
			}
			types = append(types, t)
		case a == "-x":
			return shimTranslation{}, usageErrorf("dig: reverse lookups (-x) are not supported by `vigolium dns`")
		case strings.HasPrefix(a, "-"):
			return shimTranslation{}, usageErrorf("dig: %s has no `vigolium dns` equivalent; run `vigolium dns --help`", a)
		default:
			if strings.EqualFold(a, "axfr") || strings.EqualFold(a, "ixfr") {
				return shimTranslation{}, usageErrorf("dig: zone transfers are out of scope for `vigolium dns` (resolution only)")
			}
			if t, ok := dnsTypeToken(a); ok {
				types = append(types, t)
				continue
			}
			if unsupportedDNSType(a) {
				return shimTranslation{}, usageErrorf("dig: record type %s is not supported by `vigolium dns` (types: %s)", strings.ToUpper(a), strings.Join(dnsresolve.Types, ", "))
			}
			names = append(names, a)
		}
	}
	if len(names) == 0 {
		return shimTranslation{}, usageErrorf("dig: a name to resolve is required")
	}
	if len(types) == 0 {
		// dig's own default is A.
		types = []string{"a"}
	}
	return shimTranslation{argv: dnsArgv(names, types, servers, port), notes: notes}, nil
}

func translateHost(args []string) (shimTranslation, error) {
	var positional, types []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-t":
			if i+1 >= len(args) {
				return shimTranslation{}, usageErrorf("host: -t needs a value")
			}
			i++
			t, ok := dnsTypeToken(args[i])
			if !ok {
				return shimTranslation{}, usageErrorf("host: record type %q is not supported by `vigolium dns` (types: %s)", args[i], strings.Join(dnsresolve.Types, ", "))
			}
			types = append(types, t)
		case a == "-a":
			types = append(types, "all")
		case a == "-v":
		case strings.HasPrefix(a, "-"):
			return shimTranslation{}, usageErrorf("host: %s has no `vigolium dns` equivalent; run `vigolium dns --help`", a)
		default:
			positional = append(positional, a)
		}
	}
	if len(positional) == 0 {
		return shimTranslation{}, usageErrorf("host: a name to resolve is required")
	}
	// host <IP> is a reverse (PTR) lookup, which `vigolium dns` does not do;
	// resolving the address as a name would answer a different question.
	if net.ParseIP(strings.Trim(positional[0], "[]")) != nil {
		return shimTranslation{}, usageErrorf("host: %s is an address, and reverse lookups are not supported by `vigolium dns`", positional[0])
	}
	var servers []string
	if len(positional) > 1 {
		servers = positional[1:2]
	}
	if len(types) == 0 {
		// host's own default: addresses and mail exchangers.
		types = []string{"a", "aaaa", "mx"}
	}
	return shimTranslation{argv: dnsArgv(positional[:1], types, servers, ""), notes: nil}, nil
}
