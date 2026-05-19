package tag

import "github.com/vigolium/vigolium/pkg/deparos/storage"

// MatchInput provides data from DiscoveredNode for tag matching.
// Decouples matchers from direct DiscoveredNode dependency.
type MatchInput struct {
	RequestHeaders  map[string]string
	RequestBody     []byte
	ResponseHeaders map[string]string
	ResponseBody    []byte
	StatusCode      int
	MIMEType        string
	RequestPath     string // URL path for path-based filtering
}

// NewMatchInput creates MatchInput from a DiscoveredNode.
func NewMatchInput(node *storage.DiscoveredNode) *MatchInput {
	input := &MatchInput{}

	if u := node.URL(); u != nil {
		input.RequestPath = u.Path
	}

	if req := node.Request(); req != nil {
		input.RequestHeaders = req.Headers
		input.RequestBody = req.Body
	}

	if resp := node.Response(); resp != nil {
		input.ResponseHeaders = resp.Headers
		input.ResponseBody = resp.Body
		input.StatusCode = resp.StatusCode
		input.MIMEType = resp.MIMEType
	}

	return input
}

// TagMatcher detects a specific tag pattern.
// Implementations must be thread-safe for concurrent use.
type TagMatcher interface {
	// Tag returns the tag this matcher detects.
	Tag() Tag

	// Match analyzes input and returns true if tag applies.
	Match(input *MatchInput) bool
}
