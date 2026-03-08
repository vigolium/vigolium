package astgrep

import (
	"strings"
)

// MatchesToRoutes extracts structured route information from ast-grep matches.
// It parses metavariable captures ($METHOD, $PATH, $PARAMS) from match data.
func MatchesToRoutes(matches []Match) []Route {
	var routes []Route
	for _, m := range matches {
		route := matchToRoute(m)
		if route.Method != "" || route.Path != "" {
			routes = append(routes, route)
		}
	}
	return routes
}

// matchToRoute converts a single ast-grep match to a Route.
func matchToRoute(m Match) Route {
	route := Route{
		File: m.File,
		Line: m.Range.Start.Line + 1, // ast-grep uses 0-based lines
	}

	// Extract METHOD from metavariables
	if mv, ok := m.MetaVariables["METHOD"]; ok {
		route.Method = strings.ToUpper(strings.TrimSpace(mv.Text))
	}

	// Extract PATH from metavariables
	if mv, ok := m.MetaVariables["PATH"]; ok {
		route.Path = cleanPathValue(mv.Text)
	}

	// Extract PARAMS from metavariables (may be comma-separated or single)
	if mv, ok := m.MetaVariables["PARAMS"]; ok {
		params := parseParams(mv.Text)
		if len(params) > 0 {
			route.Params = params
		}
	}

	// Also check $FUNC for Next.js-style handlers where the function name IS the method
	if route.Method == "" {
		if mv, ok := m.MetaVariables["FUNC"]; ok {
			name := strings.TrimSpace(mv.Text)
			upper := strings.ToUpper(name)
			if isHTTPMethod(upper) {
				route.Method = upper
			}
		}
	}

	// Parse from message as fallback (ast-grep rules often put info in message)
	if route.Method == "" || route.Path == "" {
		parseRouteFromMessage(m.Message, &route)
	}

	return route
}

// cleanPathValue removes surrounding quotes from path literals.
func cleanPathValue(s string) string {
	s = strings.TrimSpace(s)
	// Remove surrounding quotes (single or double)
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			s = s[1 : len(s)-1]
		}
	}
	return s
}

// parseParams splits a parameter string into individual parameter names.
func parseParams(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}

	var params []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		// Extract just the parameter name (strip type annotations)
		if colonIdx := strings.Index(p, ":"); colonIdx != -1 {
			p = strings.TrimSpace(p[:colonIdx])
		}
		// Strip default values
		if eqIdx := strings.Index(p, "="); eqIdx != -1 {
			p = strings.TrimSpace(p[:eqIdx])
		}
		if p != "" {
			params = append(params, p)
		}
	}
	return params
}

// parseRouteFromMessage extracts route info from the rule message string.
// Messages typically follow the format: "Route: METHOD PATH"
func parseRouteFromMessage(message string, route *Route) {
	message = strings.TrimSpace(message)
	if message == "" {
		return
	}

	// Look for "Route: METHOD PATH" pattern
	if idx := strings.Index(message, "Route:"); idx != -1 {
		rest := strings.TrimSpace(message[idx+6:])
		parts := strings.Fields(rest)
		if len(parts) >= 1 && route.Method == "" {
			upper := strings.ToUpper(parts[0])
			if isHTTPMethod(upper) {
				route.Method = upper
			}
		}
		if len(parts) >= 2 && route.Path == "" {
			route.Path = cleanPathValue(parts[1])
		}
	}

	// Look for "handler: METHOD" pattern (Next.js)
	if idx := strings.Index(message, "handler:"); idx != -1 {
		rest := strings.TrimSpace(message[idx+8:])
		parts := strings.Fields(rest)
		if len(parts) >= 1 && route.Method == "" {
			upper := strings.ToUpper(parts[0])
			if isHTTPMethod(upper) {
				route.Method = upper
			}
		}
	}
}

// isHTTPMethod returns true if the string is a valid HTTP method.
func isHTTPMethod(s string) bool {
	switch s {
	case "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "ANY", "HANDLE", "ALL",
		"LIST", "CREATE", "RETRIEVE", "UPDATE", "DESTROY", "CONNECT", "TRACE":
		return true
	}
	return false
}
