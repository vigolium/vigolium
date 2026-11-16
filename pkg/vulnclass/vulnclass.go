// Package vulnclass is the reported vulnerability class of a finding: one
// stable snake_case name per kind of bug (xss_reflected, xss_blind, sqli,
// ssrf, …), carried as `vuln_class` on every `finding -j` row and every
// `module ls -j` row so a consumer routes a finding by an exact value instead
// of pattern-matching module ids, names and tags.
//
// It is not the dedup class modules declare through modules.VulnClassifier
// (modkit.VulnClass*): that one groups modules that test the same sink so they
// skip a parameter another member already reported (reflected and DOM XSS
// share it). This one names what a finding asserts, so the two may differ.
//
// Each module's class is declared once, by id, in byModule (modules.go). A
// registry contract test (pkg/modules) fails when a registered module has no
// entry, or an entry names a module that is not registered, so a new module
// cannot ship unclassified. A finding whose class depends on the payload
// rather than the module (an OAST callback, a multi-class module) carries its
// own class on the result; FromOAST maps an OAST payload class.
//
// It is a leaf package (it imports only oastclass, itself a leaf) so pkg/oast,
// pkg/database and pkg/modules can all use it without a cycle.
package vulnclass

import "github.com/vigolium/vigolium/pkg/oast/oastclass"

// Class is a reported vulnerability class.
type Class string

// The vocabulary. Values are stable: a consumer keys routing on them, so a
// rename is a breaking change. Add a class rather than widening one.
const (
	// Server-side injection.
	SQLi                Class = "sqli"
	NoSQLi              Class = "nosqli"
	Cmdi                Class = "cmdi"
	CodeInjection       Class = "code_injection"
	SSTI                Class = "ssti"
	SSRF                Class = "ssrf"
	XXE                 Class = "xxe"
	LFI                 Class = "lfi"
	LDAPInjection       Class = "ldap_injection"
	XPathInjection      Class = "xpath_injection"
	SSIInjection        Class = "ssi_injection"
	ESIInjection        Class = "esi_injection"
	SMTPHeaderInjection Class = "smtp_header_injection"
	CRLFInjection       Class = "crlf_injection"
	HostHeaderInjection Class = "host_header_injection"
	Deserialization     Class = "deserialization"
	PrototypePollution  Class = "prototype_pollution"
	FileUpload          Class = "file_upload"
	MassAssignment      Class = "mass_assignment"
	CSVInjection        Class = "csv_injection"
	PromptInjection     Class = "prompt_injection"
	RCE                 Class = "rce"

	// Client-side.
	XSSReflected             Class = "xss_reflected"
	XSSStored                Class = "xss_stored"
	XSSBlind                 Class = "xss_blind"
	XSSDOM                   Class = "xss_dom"
	CSTI                     Class = "csti"
	ClientPrototypePollution Class = "client_prototype_pollution"
	DOMClobbering            Class = "dom_clobbering"
	ClientPathTraversal      Class = "client_path_traversal"
	CSSInjection             Class = "css_injection"
	JSONPCallback            Class = "jsonp_callback"
	OpenRedirect             Class = "open_redirect"
	Clickjacking             Class = "clickjacking"
	ReverseTabnabbing        Class = "reverse_tabnabbing"
	PostMessage              Class = "postmessage"

	// Authentication and authorization.
	IDOR                   Class = "idor"
	BFLA                   Class = "bfla"
	AuthBypass             Class = "auth_bypass"
	ACLBypass              Class = "acl_bypass"
	DefaultCredentials     Class = "default_credentials"
	JWT                    Class = "jwt"
	SessionManagement      Class = "session_management"
	OAuthMisconfig         Class = "oauth_misconfig"
	SAML                   Class = "saml"
	CSRF                   Class = "csrf"
	CSWSH                  Class = "cswsh"
	CORSMisconfig          Class = "cors_misconfig"
	RateLimitBypass        Class = "rate_limit_bypass"
	UserEnumeration        Class = "user_enumeration"
	PasswordResetPoisoning Class = "password_reset_poisoning"
	BusinessLogic          Class = "business_logic"

	// Protocol, cache and infrastructure.
	RequestSmuggling     Class = "request_smuggling"
	CachePoisoning       Class = "cache_poisoning"
	CacheDeception       Class = "cache_deception"
	SubdomainTakeover    Class = "subdomain_takeover"
	BucketTakeover       Class = "bucket_takeover"
	CloudStorageExposure Class = "cloud_storage_exposure"
	PaddingOracle        Class = "padding_oracle"
	RaceCondition        Class = "race_condition"
	DoS                  Class = "dos"
	DNSRebinding         Class = "dns_rebinding"
	ProxyTrust           Class = "proxy_trust"
	TransportSecurity    Class = "transport_security"
	SecurityHeaders      Class = "security_headers"
	CookieSecurity       Class = "cookie_security"
	WeakCrypto           Class = "weak_crypto"
	SupplyChain          Class = "supply_chain"

	// Exposure.
	InfoDisclosure    Class = "info_disclosure"
	DataExposure      Class = "data_exposure"
	SensitiveFile     Class = "sensitive_file"
	SourceDisclosure  Class = "source_disclosure"
	SourceMapExposure Class = "source_map_exposure"
	SecretExposure    Class = "secret_exposure"
	DirectoryListing  Class = "directory_listing"
	DebugExposure     Class = "debug_exposure"
	AdminExposure     Class = "admin_exposure"
	APIDocsExposure   Class = "api_docs_exposure"
	ExposedService    Class = "exposed_service"
	Misconfiguration  Class = "misconfiguration"
	OutdatedComponent Class = "outdated_component"

	// Not a vulnerability by itself.
	Fingerprint Class = "fingerprint"
	// Signal is an analysis result (anomaly, reflection, behaviour change,
	// harvested surface) that is a lead for another check, not a bug.
	Signal Class = "signal"
	// Multiple marks a module whose findings span classes (graphql-scan, the
	// MCP fuzzers, oast-probe). It appears on `module ls -j` rows only: each
	// finding of such a module carries the class its result names, and none
	// when it names none.
	Multiple Class = "multiple"
)

// Entry is one vocabulary row: the class and what it means.
type Entry struct {
	Class       Class  `json:"class"`
	Description string `json:"description"`
}

// vocabulary lists every class in a stable order with its meaning. It is the
// single source for validation (Valid) and the documented list.
var vocabulary = []Entry{
	{SQLi, "SQL injection"},
	{NoSQLi, "NoSQL / document-store operator injection"},
	{Cmdi, "OS command injection"},
	{CodeInjection, "server-side code or expression evaluation (eval, EL, server-side JS)"},
	{SSTI, "server-side template injection"},
	{SSRF, "server-side request forgery, including blind and routing-based"},
	{XXE, "XML external entity processing"},
	{LFI, "local file read / path traversal"},
	{LDAPInjection, "LDAP filter injection"},
	{XPathInjection, "XPath injection"},
	{SSIInjection, "server-side includes injection"},
	{ESIInjection, "edge side includes injection"},
	{SMTPHeaderInjection, "SMTP / email header injection"},
	{CRLFInjection, "CRLF injection / HTTP response splitting"},
	{HostHeaderInjection, "Host header injection"},
	{Deserialization, "insecure deserialization"},
	{PrototypePollution, "server-side prototype pollution"},
	{FileUpload, "unrestricted file upload"},
	{MassAssignment, "mass assignment"},
	{CSVInjection, "CSV / spreadsheet formula injection"},
	{PromptInjection, "LLM prompt injection"},
	{RCE, "remote code execution through a known product flaw or an exposed code-execution surface"},
	{XSSReflected, "reflected cross-site scripting"},
	{XSSStored, "stored cross-site scripting, confirmed in-band"},
	{XSSBlind, "blind (out-of-band) stored cross-site scripting, rendered where the scanner cannot see"},
	{XSSDOM, "DOM-based cross-site scripting (client-side sink)"},
	{CSTI, "client-side template injection"},
	{ClientPrototypePollution, "client-side prototype pollution"},
	{DOMClobbering, "DOM clobbering"},
	{ClientPathTraversal, "client-side path traversal"},
	{CSSInjection, "CSS injection, including path-relative stylesheet import"},
	{JSONPCallback, "JSONP callback injection"},
	{OpenRedirect, "open redirect"},
	{Clickjacking, "clickjacking / UI redress"},
	{ReverseTabnabbing, "reverse tabnabbing"},
	{PostMessage, "postMessage handler without origin checks"},
	{IDOR, "object-level authorization (IDOR / BOLA)"},
	{BFLA, "function-level authorization"},
	{AuthBypass, "missing or bypassable authentication in the application"},
	{ACLBypass, "edge / proxy access rule bypass (403 bypass, path normalization)"},
	{DefaultCredentials, "default or weak credentials"},
	{JWT, "JSON Web Token weakness"},
	{SessionManagement, "session handling weakness"},
	{OAuthMisconfig, "OAuth / OIDC misconfiguration"},
	{SAML, "SAML / XML signature weakness"},
	{CSRF, "cross-site request forgery"},
	{CSWSH, "cross-site WebSocket hijacking"},
	{CORSMisconfig, "CORS misconfiguration"},
	{RateLimitBypass, "rate-limit bypass"},
	{UserEnumeration, "user enumeration"},
	{PasswordResetPoisoning, "password reset link poisoning"},
	{BusinessLogic, "business-logic risk (client-controlled price or status)"},
	{RequestSmuggling, "HTTP request smuggling / desync"},
	{CachePoisoning, "web cache poisoning, including cache-poisoned DoS"},
	{CacheDeception, "web cache deception"},
	{SubdomainTakeover, "subdomain takeover"},
	{BucketTakeover, "dangling cloud bucket takeover"},
	{CloudStorageExposure, "public cloud storage listing or read"},
	{PaddingOracle, "CBC padding oracle"},
	{RaceCondition, "race condition"},
	{DoS, "denial of service"},
	{DNSRebinding, "DNS rebinding / missing Origin validation"},
	{ProxyTrust, "trusted forwarding headers from the client"},
	{TransportSecurity, "TLS, HSTS and mixed-content weakness"},
	{SecurityHeaders, "missing or weak security response headers"},
	{CookieSecurity, "cookie attribute weakness"},
	{WeakCrypto, "weak cryptography"},
	{SupplyChain, "supply-chain risk (dependency confusion, tool definition drift)"},
	{InfoDisclosure, "information disclosure"},
	{DataExposure, "unauthenticated application data exposure"},
	{SensitiveFile, "sensitive or backup file exposure"},
	{SourceDisclosure, "server source code disclosure"},
	{SourceMapExposure, "JavaScript source map exposure"},
	{SecretExposure, "secret or credential exposure"},
	{DirectoryListing, "directory listing"},
	{DebugExposure, "debug endpoint or debug mode exposure"},
	{AdminExposure, "exposed admin console or dashboard"},
	{APIDocsExposure, "exposed API documentation or introspection"},
	{ExposedService, "exposed service or API surface that should not be public"},
	{Misconfiguration, "product or framework misconfiguration"},
	{OutdatedComponent, "a product and version identified, or a version-gated flaw surface"},
	{Fingerprint, "technology fingerprint (not a vulnerability)"},
	{Signal, "analysis signal that is a lead for another check (not a vulnerability)"},
	{Multiple, "module rows only: the module's findings span classes, each finding names its own"},
}

// Vocabulary returns every class with its meaning, in a stable order.
func Vocabulary() []Entry {
	out := make([]Entry, len(vocabulary))
	copy(out, vocabulary)
	return out
}

// vocabularySet is the vocabulary's classes, for Valid.
var vocabularySet = func() map[Class]struct{} {
	set := make(map[Class]struct{}, len(vocabulary))
	for _, e := range vocabulary {
		set[e.Class] = struct{}{}
	}
	return set
}()

// Valid reports whether c is in the vocabulary.
func (c Class) Valid() bool {
	_, ok := vocabularySet[c]
	return ok
}

// ForModule returns the class declared for a module id, or "" for an id with
// no declaration (a known-issue template, an extension, an imported finding).
func ForModule(moduleID string) Class {
	return byModule[moduleID]
}

// DeclaredModules returns every module id with a declared class, for the
// registry contract test.
func DeclaredModules() map[string]Class {
	out := make(map[string]Class, len(byModule))
	for k, v := range byModule {
		out[k] = v
	}
	return out
}

// ForFinding resolves the class a finding reports: the class its result named
// (explicit), else the module's declared class. Multiple never reaches a
// finding: it says the module's findings differ, so a finding without its own
// class has none.
func ForFinding(explicit Class, moduleID string) Class {
	if explicit != "" && explicit != Multiple && explicit.Valid() {
		return explicit
	}
	if c := ForModule(moduleID); c != Multiple {
		return c
	}
	return ""
}

// FromOAST maps the class an OAST payload was minted for to the reported
// class, or "" when the payload class says nothing more than the planting
// module does (generic, MCP argument).
func FromOAST(c oastclass.Class) Class {
	switch c {
	case oastclass.SSRF, oastclass.SSRFSmuggle, oastclass.HeaderHarvest, oastclass.HostRouting:
		return SSRF
	case oastclass.XXE:
		return XXE
	case oastclass.CMDI:
		return Cmdi
	case oastclass.SQLi:
		return SQLi
	case oastclass.JWTKeyURL:
		return JWT
	case oastclass.PasswordResetPoisoning:
		return PasswordResetPoisoning
	case oastclass.BlindXSS:
		return XSSBlind
	case oastclass.SSTI:
		return SSTI
	case oastclass.Deserialization:
		return Deserialization
	case oastclass.JNDI, oastclass.Text4Shell:
		return RCE
	case oastclass.ESI:
		return ESIInjection
	case oastclass.SMTP:
		return SMTPHeaderInjection
	}
	return ""
}
