package config

import "strings"

// TechExtensionSignature maps an application stack to the server-side file
// extensions that stack serves. A fingerprint match (a response header or
// cookie that only a given stack emits) confirms those extensions as valid
// routes without needing an observed link — feeding the extension-confirm
// pipeline's "fingerprint" source.
type TechExtensionSignature struct {
	// Tech is the human-readable stack name, shown in console output.
	Tech string
	// Extensions are the server-side extensions (no leading dot) this stack serves.
	Extensions []string
	// Cookies are Set-Cookie names that uniquely indicate this stack (matched
	// case-insensitively as a substring of the Set-Cookie blob).
	Cookies []string
	// PoweredBy are X-Powered-By substrings (case-insensitive).
	PoweredBy []string
	// Server are Server-header substrings (case-insensitive).
	Server []string
	// HeaderPresent are header names whose mere presence confirms the stack
	// (e.g. X-AspNet-Version), matched case-insensitively.
	HeaderPresent []string
}

// TechExtensionSignatures is the ordered fingerprint table consulted by
// DetectTechExtensions. Order is only cosmetic (console output); a response
// may match several stacks.
var TechExtensionSignatures = []TechExtensionSignature{
	{
		Tech:       "PHP",
		Extensions: []string{"php", "php3", "php4", "php5", "phtml"},
		Cookies:    []string{"PHPSESSID"},
		PoweredBy:  []string{"php"},
		Server:     []string{"php"},
	},
	{
		Tech:       "Java/JSP",
		Extensions: []string{"jsp", "jspx", "jspa", "do", "action"},
		Cookies:    []string{"JSESSIONID"},
		PoweredBy:  []string{"servlet", "jsp", "jboss", "wildfly"},
		Server:     []string{"tomcat", "coyote", "jetty", "jboss", "wildfly", "glassfish", "weblogic", "resin"},
	},
	{
		Tech:          "ASP.NET",
		Extensions:    []string{"aspx", "ashx", "asmx", "asp"},
		Cookies:       []string{"asp.net_sessionid", ".aspxauth", ".aspxanonymous"},
		PoweredBy:     []string{"asp.net"},
		Server:        []string{"kestrel"},
		HeaderPresent: []string{"X-AspNet-Version", "X-AspNetMvc-Version"},
	},
	{
		Tech:       "Classic ASP",
		Extensions: []string{"asp"},
		Cookies:    []string{"aspsessionid"},
	},
	{
		Tech:       "ColdFusion",
		Extensions: []string{"cfm", "cfml"},
		Cookies:    []string{"cfid", "cftoken", "cfauthorization"},
		Server:     []string{"coldfusion"},
	},
	{
		Tech:       "Perl/CGI",
		Extensions: []string{"cgi"},
		Server:     []string{"/cgi"},
	},
}

// DetectTechExtensions inspects a response's headers and Set-Cookie values and
// returns every TechExtensionSignature whose signals are present. getHeader is
// a case-insensitive header accessor (e.g. http.Header.Get); setCookies are the
// raw Set-Cookie header values.
func DetectTechExtensions(getHeader func(string) string, setCookies []string) []TechExtensionSignature {
	if getHeader == nil {
		getHeader = func(string) string { return "" }
	}

	poweredBy := strings.ToLower(getHeader("X-Powered-By"))
	server := strings.ToLower(getHeader("Server"))
	cookieBlob := strings.ToLower(strings.Join(setCookies, "\n"))
	// A Set-Cookie may also surface via the single accessor on some chains.
	cookieBlob += "\n" + strings.ToLower(getHeader("Set-Cookie"))

	var matched []TechExtensionSignature
	for _, sig := range TechExtensionSignatures {
		if sig.matches(getHeader, poweredBy, server, cookieBlob) {
			matched = append(matched, sig)
		}
	}
	return matched
}

// matches reports whether the signature's signals are present in the response.
func (s TechExtensionSignature) matches(getHeader func(string) string, poweredBy, server, cookieBlob string) bool {
	for _, c := range s.Cookies {
		if strings.Contains(cookieBlob, strings.ToLower(c)) {
			return true
		}
	}
	for _, p := range s.PoweredBy {
		if poweredBy != "" && strings.Contains(poweredBy, strings.ToLower(p)) {
			return true
		}
	}
	for _, sv := range s.Server {
		if server != "" && strings.Contains(server, strings.ToLower(sv)) {
			return true
		}
	}
	for _, h := range s.HeaderPresent {
		if getHeader(h) != "" {
			return true
		}
	}
	return false
}
