package astgrep

import (
	"slices"
	"sort"
	"strings"
)

// MatchesToRoutes extracts structured route information from ast-grep matches.
// It parses metavariable captures ($METHOD, $PATH, $PARAMS) from match data.
// Param-binding matches (no method/path, only params) are correlated with
// route-handler matches by file proximity to populate QueryParams/BodyParams.
func MatchesToRoutes(matches []Match) []Route {
	var routes []Route
	var paramMatches []Match

	for _, m := range matches {
		route := matchToRoute(m)
		if route.Method != "" || route.Path != "" {
			routes = append(routes, route)
		} else if len(route.Params) > 0 {
			// Param-binding match with no route info — save for correlation
			paramMatches = append(paramMatches, m)
		}
	}

	if len(paramMatches) > 0 && len(routes) > 0 {
		correlateParamsToRoutes(routes, paramMatches)
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

// paramLocation indicates where in the HTTP request a parameter is sourced.
type paramLocation int

const (
	paramLocationUnknown paramLocation = iota
	paramLocationQuery
	paramLocationBody
	paramLocationPath
)

// correlateParamsToRoutes associates param-binding matches with the nearest
// route-handler in the same file (by line proximity). It classifies each param
// as query, body, or path based on the match text pattern.
func correlateParamsToRoutes(routes []Route, paramMatches []Match) {
	// Build per-file index of routes (sorted by line)
	type indexedRoute struct {
		idx  int
		line int
	}
	fileRoutes := make(map[string][]indexedRoute)
	for i, r := range routes {
		fileRoutes[r.File] = append(fileRoutes[r.File], indexedRoute{idx: i, line: r.Line})
	}
	for _, entries := range fileRoutes {
		sort.Slice(entries, func(i, j int) bool { return entries[i].line < entries[j].line })
	}

	for _, m := range paramMatches {
		entries, ok := fileRoutes[m.File]
		if !ok || len(entries) == 0 {
			continue
		}

		matchLine := m.Range.Start.Line + 1 // 0-based → 1-based

		// Find the nearest route with line ≤ matchLine (closest preceding route handler)
		bestIdx := -1
		bestDist := int(^uint(0) >> 1) // max int
		for _, e := range entries {
			if e.line <= matchLine {
				dist := matchLine - e.line
				if dist < bestDist {
					bestDist = dist
					bestIdx = e.idx
				}
			}
		}
		// If no preceding route, fall back to the nearest route overall
		if bestIdx == -1 {
			for _, e := range entries {
				dist := e.line - matchLine
				if dist < 0 {
					dist = -dist
				}
				if dist < bestDist {
					bestDist = dist
					bestIdx = e.idx
				}
			}
		}
		if bestIdx == -1 {
			continue
		}

		// Extract param names and classify
		mv, ok := m.MetaVariables["PARAMS"]
		if !ok {
			continue
		}
		params := parseParams(mv.Text)
		loc := classifyParamLocation(m.Text, m.ID)

		for _, p := range params {
			switch loc {
			case paramLocationQuery:
				if !slices.Contains(routes[bestIdx].QueryParams, p) {
					routes[bestIdx].QueryParams = append(routes[bestIdx].QueryParams, p)
				}
			case paramLocationBody:
				if !slices.Contains(routes[bestIdx].BodyParams, p) {
					routes[bestIdx].BodyParams = append(routes[bestIdx].BodyParams, p)
				}
			default:
				// Unknown or path params — add to generic Params if not already there
				if !slices.Contains(routes[bestIdx].Params, p) {
					routes[bestIdx].Params = append(routes[bestIdx].Params, p)
				}
			}
		}
	}
}

// classifyParamLocation determines whether a param-binding match refers to
// query, body, or path parameters based on the match text and rule ID.
func classifyParamLocation(text, ruleID string) paramLocation {
	t := strings.ToLower(text)

	// Express / Node.js
	if strings.Contains(t, ".query.") || strings.Contains(t, ".query[") {
		return paramLocationQuery
	}
	if strings.Contains(t, ".body.") || strings.Contains(t, ".body[") {
		return paramLocationBody
	}
	if strings.Contains(t, ".params.") || strings.Contains(t, ".params[") {
		return paramLocationPath
	}

	// Flask
	if strings.Contains(t, "request.args") {
		return paramLocationQuery
	}
	if strings.Contains(t, "request.form") || strings.Contains(t, "request.json") {
		return paramLocationBody
	}
	if strings.Contains(t, "request.values") {
		return paramLocationQuery // values checks both args and form, treat as query
	}

	// Django
	if strings.Contains(t, "request.get") || strings.Contains(t, ".query_params") {
		return paramLocationQuery
	}
	if strings.Contains(t, "request.post") || strings.Contains(t, "request.data") {
		return paramLocationBody
	}

	// Gin (Go)
	if strings.Contains(t, ".query(") || strings.Contains(t, ".defaultquery(") ||
		strings.Contains(t, ".url.query()") {
		return paramLocationQuery
	}
	if strings.Contains(t, ".postform(") || strings.Contains(t, ".bindjson(") ||
		strings.Contains(t, ".shouldbindjson(") || strings.Contains(t, ".shouldbind(") {
		return paramLocationBody
	}
	if strings.Contains(t, ".param(") && !strings.Contains(t, ".params.") {
		return paramLocationPath
	}

	// Go net/http
	if strings.Contains(t, ".formvalue(") {
		return paramLocationQuery
	}
	if strings.Contains(t, ".postformvalue(") {
		return paramLocationBody
	}

	return paramLocationUnknown
}

