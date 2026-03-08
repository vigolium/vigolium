package xss_light_scanner

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// PathInjectionGenerator generates path variants for XSS testing.
// It creates insertion points for different path manipulation strategies.
type PathInjectionGenerator struct{}

// PathVariant represents a path manipulation variant with its insertion point.
type PathVariant struct {
	InsertionPoint httpmsg.InsertionPoint
	Strategy       string // "recursive", "cut", or "append"
}

// GenerateRecursivePathPoints creates insertion points for each path segment.
// Example: /api/v1/users → [/api, /v1, /users] each as separate insertion points
func (g *PathInjectionGenerator) GenerateRecursivePathPoints(request []byte) ([]httpmsg.InsertionPoint, error) {
	pathOnly, err := httpmsg.GetPathOnly(request)
	if err != nil {
		return nil, err
	}

	segments := g.splitPathSegments(pathOnly)
	if len(segments) == 0 {
		return nil, nil
	}

	var points []httpmsg.InsertionPoint

	// Create insertion point for each segment
	for i, segment := range segments {
		if segment == "" {
			continue
		}

		// Find segment position in request
		segmentStart, segmentEnd := g.findSegmentPosition(request, pathOnly, i)
		if segmentStart == -1 {
			continue
		}

		ip := httpmsg.NewEncodedInsertionPoint(
			"path["+segment+"]",
			request,
			segmentStart,
			segmentEnd,
			&httpmsg.NoopEncoder{},
			nil,
			httpmsg.INS_URL_PATH_FOLDER,
		)
		points = append(points, ip)
	}

	return points, nil
}

// GenerateCutPathPoints creates insertion points with progressively cut paths.
// Example: /api/v1/users → test at /api/v1, /api, /
// This tests if server reflects cut paths in error pages.
func (g *PathInjectionGenerator) GenerateCutPathPoints(request []byte) ([]httpmsg.InsertionPoint, error) {
	pathOnly, err := httpmsg.GetPathOnly(request)
	if err != nil {
		return nil, err
	}

	segments := g.splitPathSegments(pathOnly)
	if len(segments) <= 1 {
		return nil, nil
	}

	var points []httpmsg.InsertionPoint

	// Create variants by cutting from end
	// /api/v1/users → /api/v1/PAYLOAD, /api/PAYLOAD, /PAYLOAD
	for cutCount := 1; cutCount < len(segments); cutCount++ {
		// Build the cut path
		remaining := segments[:len(segments)-cutCount]
		cutPath := "/" + strings.Join(remaining, "/") + "/"

		// Find position where we need to inject (at the end of cut path)
		queryString, _ := httpmsg.GetQueryString(request)
		fullPath := cutPath
		if queryString != "" {
			fullPath = cutPath + "?" + queryString
		}

		// Create a modified request with cut path
		modifiedRequest, err := httpmsg.SetPath(request, fullPath)
		if err != nil {
			continue
		}

		// Create insertion point at the end of the path (before query)
		pathEnd := strings.Index(string(modifiedRequest), fullPath)
		if pathEnd == -1 {
			continue
		}

		injectPos := pathEnd + len(cutPath) - 1 // Position of trailing slash

		ip := httpmsg.NewEncodedInsertionPoint(
			"path_cut["+cutPath+"]",
			modifiedRequest,
			injectPos,
			injectPos,
			&httpmsg.NoopEncoder{},
			nil,
			httpmsg.INS_URL_PATH_FOLDER,
		)
		points = append(points, ip)
	}

	return points, nil
}

// GenerateAppendPathPoint creates an insertion point by appending a fake segment.
// Example: /api/v1/users → /api/v1/users/PAYLOAD
// This tests if server reflects unknown paths in 404 pages.
func (g *PathInjectionGenerator) GenerateAppendPathPoint(request []byte) (httpmsg.InsertionPoint, error) {
	pathOnly, err := httpmsg.GetPathOnly(request)
	if err != nil {
		return nil, err
	}

	// Ensure path ends with /
	appendPath := pathOnly
	if !strings.HasSuffix(appendPath, "/") {
		appendPath = appendPath + "/"
	}

	// Build new path with placeholder for injection
	queryString, _ := httpmsg.GetQueryString(request)
	fullPath := appendPath
	if queryString != "" {
		fullPath = appendPath + "?" + queryString
	}

	// Create modified request with trailing slash
	modifiedRequest, err := httpmsg.SetPath(request, fullPath)
	if err != nil {
		return nil, err
	}

	// Find injection position (at end of path before query)
	pathEnd := strings.Index(string(modifiedRequest), fullPath)
	if pathEnd == -1 {
		return nil, nil
	}

	injectPos := pathEnd + len(appendPath)

	ip := httpmsg.NewEncodedInsertionPoint(
		"path_append",
		modifiedRequest,
		injectPos,
		injectPos,
		&httpmsg.NoopEncoder{},
		nil,
		httpmsg.INS_URL_PATH_FOLDER,
	)

	return ip, nil
}

// splitPathSegments splits a path into its segments.
// Example: /api/v1/users → ["api", "v1", "users"]
func (g *PathInjectionGenerator) splitPathSegments(path string) []string {
	// Remove leading/trailing slashes and split
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "/")
}

// findSegmentPosition finds the byte position of a path segment in the request.
func (g *PathInjectionGenerator) findSegmentPosition(request []byte, pathOnly string, segmentIndex int) (start, end int) {
	segments := g.splitPathSegments(pathOnly)
	if segmentIndex >= len(segments) {
		return -1, -1
	}

	// Find the request line in the raw request
	requestStr := string(request)

	// Build path up to the segment
	pathPrefix := "/"
	for i := 0; i < segmentIndex; i++ {
		pathPrefix += segments[i] + "/"
	}

	// Find path in request
	pathStart := strings.Index(requestStr, " "+pathOnly)
	if pathStart == -1 {
		pathStart = strings.Index(requestStr, " "+pathOnly+"?")
	}
	if pathStart == -1 {
		return -1, -1
	}
	pathStart++ // Move past the space

	// Calculate segment position within path
	segmentOffset := len(pathPrefix)
	segmentLen := len(segments[segmentIndex])

	start = pathStart + segmentOffset
	end = start + segmentLen

	return start, end
}

// CreatePathInsertionPoint creates an insertion point for a specific path position.
func CreatePathInsertionPoint(request []byte, start, end int, name string) httpmsg.InsertionPoint {
	return httpmsg.NewEncodedInsertionPoint(
		name,
		request,
		start,
		end,
		&httpmsg.NoopEncoder{},
		nil,
		httpmsg.INS_URL_PATH_FOLDER,
	)
}
