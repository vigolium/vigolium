package tag

import (
	"github.com/vigolium/vigolium/pkg/deparos/storage"
)

// Analyzer orchestrates all tag matchers.
type Analyzer struct {
	matchers []TagMatcher
}

// NewAnalyzer creates an analyzer with all default matchers.
func NewAnalyzer() *Analyzer {
	return &Analyzer{
		matchers: []TagMatcher{
			NewVibeAppMatcher(),
			NewJWTMatcher(),
			NewAPIKeyMatcher(),
			NewErrorPageMatcher(),
			NewModernAppMatcher(),
			NewJSONDataMatcher(),
		},
	}
}

// Analyze runs all matchers and returns matched tags.
func (a *Analyzer) Analyze(node *storage.DiscoveredNode) []Tag {
	input := NewMatchInput(node)

	var tags []Tag
	for _, matcher := range a.matchers {
		if matcher.Match(input) {
			tags = append(tags, matcher.Tag())
		}
	}

	return tags
}

// AnalyzeResult runs all matchers on a storage.Result and returns matched tags as strings.
func (a *Analyzer) AnalyzeResult(result *storage.Result) []string {
	input := &MatchInput{}

	if result.URL != nil {
		input.RequestPath = result.URL.Path
	}
	if result.Request != nil {
		input.RequestHeaders = result.Request.Headers
		input.RequestBody = result.Request.Body
	}
	if result.Response != nil {
		input.ResponseHeaders = result.Response.Headers
		input.ResponseBody = result.Response.Body
		input.StatusCode = result.Response.StatusCode
		input.MIMEType = result.Response.MIMEType
	}

	var tags []string
	for _, matcher := range a.matchers {
		if matcher.Match(input) {
			tags = append(tags, string(matcher.Tag()))
		}
	}
	return tags
}
