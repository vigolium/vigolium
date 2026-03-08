package spider

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFormExtractor_SelectGeneratesNVariants(t *testing.T) {
	htmlStr := `
		<form action="/search" method="GET">
			<select name="category">
				<option value="electronics">Electronics</option>
				<option value="books">Books</option>
				<option value="clothing">Clothing</option>
			</select>
			<input type="submit" value="Search">
		</form>
	`

	requests := extractFormRequests(t, htmlStr)

	// Should generate 3 requests (one per select option)
	require.Len(t, requests, 3, "Should generate 3 requests for 3 select options")

	// Collect all category values
	categoryValues := make(map[string]bool)
	for _, req := range requests {
		query := req.URL.RawQuery
		// Extract category value from query string
		for _, param := range strings.Split(query, "&") {
			if strings.HasPrefix(param, "category=") {
				categoryValues[strings.TrimPrefix(param, "category=")] = true
			}
		}
		// Ensure only ONE category param per request
		assert.Equal(t, 1, strings.Count(query, "category="),
			"Each request should have exactly 1 category param, got: %s", query)
	}

	assert.True(t, categoryValues["electronics"], "Should have electronics option")
	assert.True(t, categoryValues["books"], "Should have books option")
	assert.True(t, categoryValues["clothing"], "Should have clothing option")
}

func TestFormExtractor_MultipleSelectsCartesianProduct(t *testing.T) {
	htmlStr := `
		<form action="/search" method="GET">
			<select name="category">
				<option value="a">A</option>
				<option value="b">B</option>
			</select>
			<select name="sort">
				<option value="asc">Ascending</option>
				<option value="desc">Descending</option>
			</select>
		</form>
	`

	requests := extractFormRequests(t, htmlStr)

	// Should generate 2 * 2 = 4 requests (cartesian product)
	require.Len(t, requests, 4, "Should generate 4 requests (2 category * 2 sort)")

	// Collect all combinations
	combinations := make(map[string]bool)
	for _, req := range requests {
		combinations[req.URL.RawQuery] = true
	}

	// Verify all 4 combinations exist
	assert.Len(t, combinations, 4, "Should have 4 unique query combinations")
}

func TestFormExtractor_RadioAndSelectCombined(t *testing.T) {
	htmlStr := `
		<form action="/submit" method="GET">
			<input type="radio" name="gender" value="male">
			<input type="radio" name="gender" value="female">
			<select name="country">
				<option value="us">USA</option>
				<option value="uk">UK</option>
			</select>
		</form>
	`

	requests := extractFormRequests(t, htmlStr)

	// Should generate 2 * 2 = 4 requests (2 radio * 2 select)
	require.Len(t, requests, 4, "Should generate 4 requests (2 gender * 2 country)")

	// Verify each request has exactly 1 gender and 1 country
	for _, req := range requests {
		query := req.URL.RawQuery
		assert.Equal(t, 1, strings.Count(query, "gender="),
			"Each request should have exactly 1 gender param")
		assert.Equal(t, 1, strings.Count(query, "country="),
			"Each request should have exactly 1 country param")
	}
}

func TestFormExtractor_SelectWithCheckboxes(t *testing.T) {
	htmlStr := `
		<form action="/submit" method="GET">
			<select name="category">
				<option value="cat1">Cat 1</option>
				<option value="cat2">Cat 2</option>
			</select>
			<input type="checkbox" name="newsletter" value="yes">
			<input type="checkbox" name="terms" value="accepted">
		</form>
	`

	requests := extractFormRequests(t, htmlStr)

	// Should generate 2 requests (2 select options, checkboxes don't add variants)
	require.Len(t, requests, 2, "Should generate 2 requests (checkboxes don't multiply)")

	// Each request should have all checkboxes checked
	for _, req := range requests {
		query := req.URL.RawQuery
		assert.Contains(t, query, "newsletter=yes", "Checkbox should be included")
		assert.Contains(t, query, "terms=accepted", "Checkbox should be included")
	}
}

func TestFormExtractor_LargeSelectNoDuplicateParams(t *testing.T) {
	// Build select with 50 options
	var options strings.Builder
	for i := 0; i < 50; i++ {
		options.WriteString(`<option value="opt` + string(rune('0'+i%10)) + `">Option</option>`)
	}

	htmlStr := `
		<form action="/search" method="GET">
			<select name="bigselect">` + options.String() + `</select>
		</form>
	`

	requests := extractFormRequests(t, htmlStr)

	// Should generate 50 requests
	require.Len(t, requests, 50, "Should generate 50 requests for 50 options")

	// Each request should have exactly 1 bigselect param (no duplicates!)
	for i, req := range requests {
		query := req.URL.RawQuery
		count := strings.Count(query, "bigselect=")
		assert.Equal(t, 1, count,
			"Request %d should have exactly 1 bigselect param, got %d in: %s", i, count, query)
	}
}

func TestFormExtractor_MultiSelectGeneratesNVariants(t *testing.T) {
	htmlStr := `
		<form action="/submit" method="GET">
			<select name="tags" multiple>
				<option value="tag1">Tag 1</option>
				<option value="tag2">Tag 2</option>
				<option value="tag3">Tag 3</option>
			</select>
		</form>
	`

	requests := extractFormRequests(t, htmlStr)

	// Multi-select should generate N variants (one per option), like single-select
	require.Len(t, requests, 3, "Multi-select should generate 3 requests (one per option)")

	// Collect all tag values
	tagValues := make(map[string]bool)
	for _, req := range requests {
		query := req.URL.RawQuery
		// Each request should have exactly 1 tags param (no duplicates!)
		assert.Equal(t, 1, strings.Count(query, "tags="),
			"Each request should have exactly 1 tags param, got: %s", query)
		// Extract tag value
		for _, param := range strings.Split(query, "&") {
			if strings.HasPrefix(param, "tags=") {
				tagValues[strings.TrimPrefix(param, "tags=")] = true
			}
		}
	}

	assert.True(t, tagValues["tag1"], "Should have tag1 option")
	assert.True(t, tagValues["tag2"], "Should have tag2 option")
	assert.True(t, tagValues["tag3"], "Should have tag3 option")
}

func TestFormExtractor_FormWithNoVariableInputs(t *testing.T) {
	htmlStr := `
		<form action="/submit" method="GET">
			<input type="text" name="username" value="">
			<input type="hidden" name="csrf" value="token123">
			<input type="submit" value="Submit">
		</form>
	`

	requests := extractFormRequests(t, htmlStr)

	// Should generate exactly 1 request
	require.Len(t, requests, 1, "Form with no radio/select should generate 1 request")

	query := requests[0].URL.RawQuery
	assert.Contains(t, query, "username=")
	assert.Contains(t, query, "csrf=token123")
}

func TestFormExtractor_EmptySelectNoVariants(t *testing.T) {
	htmlStr := `
		<form action="/submit" method="GET">
			<select name="empty"></select>
			<input type="text" name="name" value="test">
		</form>
	`

	requests := extractFormRequests(t, htmlStr)

	// Empty select should not cause issues
	require.Len(t, requests, 1, "Empty select should generate 1 request")
	assert.Contains(t, requests[0].URL.RawQuery, "name=test")
}

func TestFormExtractor_SelectWithTextInputs(t *testing.T) {
	htmlStr := `
		<form action="/search" method="GET">
			<input type="text" name="query" value="test">
			<select name="filter">
				<option value="all">All</option>
				<option value="recent">Recent</option>
			</select>
			<input type="hidden" name="page" value="1">
		</form>
	`

	requests := extractFormRequests(t, htmlStr)

	require.Len(t, requests, 2, "Should generate 2 requests")

	for _, req := range requests {
		query := req.URL.RawQuery
		assert.Contains(t, query, "query=test", "Text input should be included")
		assert.Contains(t, query, "page=1", "Hidden input should be included")
		assert.Equal(t, 1, strings.Count(query, "filter="),
			"Should have exactly 1 filter param")
	}
}

func TestFormExtractor_POSTFormWithSelect(t *testing.T) {
	htmlStr := `
		<form action="/submit" method="POST">
			<select name="category">
				<option value="a">A</option>
				<option value="b">B</option>
			</select>
			<input type="text" name="name" value="test">
		</form>
	`

	requests := extractFormRequests(t, htmlStr)

	require.Len(t, requests, 2, "Should generate 2 requests")

	for _, req := range requests {
		assert.Equal(t, "POST", req.Method)
		assert.Contains(t, req.Body, "name=test")
		assert.Equal(t, 1, strings.Count(req.Body, "category="),
			"POST body should have exactly 1 category param")
	}
}

func TestFormExtractor_MultipleSubmitButtons(t *testing.T) {
	htmlStr := `
		<form action="/submit" method="GET">
			<select name="action">
				<option value="save">Save</option>
				<option value="delete">Delete</option>
			</select>
			<input type="submit" name="btn" value="confirm">
			<input type="submit" name="btn" value="cancel">
		</form>
	`

	requests := extractFormRequests(t, htmlStr)

	// 2 select options * 2 submit buttons = 4 requests
	require.Len(t, requests, 4, "Should generate 4 requests (2 options * 2 buttons)")
}

func TestFormExtractor_DuplicateHiddenInputsDedup(t *testing.T) {
	htmlStr := `
		<form action="/submit" method="GET">
			<input type="hidden" name="csrf" value="token1">
			<input type="hidden" name="csrf" value="token2">
			<input type="hidden" name="csrf" value="token3">
			<input type="text" name="query" value="test">
		</form>
	`

	requests := extractFormRequests(t, htmlStr)

	require.Len(t, requests, 1, "Should generate 1 request")

	query := requests[0].URL.RawQuery
	// Only 1 csrf param should be present (first value wins)
	assert.Equal(t, 1, strings.Count(query, "csrf="),
		"Should have exactly 1 csrf param, got: %s", query)
	assert.Contains(t, query, "csrf=token1", "First csrf value should be used")
}

func TestFormExtractor_ActionURLParamsOverride(t *testing.T) {
	htmlStr := `
		<form action="/search?sort=name&limit=10" method="GET">
			<input type="text" name="sort" value="date">
			<input type="text" name="query" value="test">
		</form>
	`

	requests := extractFormRequests(t, htmlStr)

	require.Len(t, requests, 1, "Should generate 1 request")

	query := requests[0].URL.RawQuery
	// Form params should override action URL params
	assert.Equal(t, 1, strings.Count(query, "sort="),
		"Should have exactly 1 sort param, got: %s", query)
	assert.Contains(t, query, "sort=date", "Form value should override action URL value")
	// Action URL params not in form should be preserved
	assert.Contains(t, query, "limit=10", "Action URL params not in form should be preserved")
	assert.Contains(t, query, "query=test", "Form-only params should be included")
}

func TestFormExtractor_MultiSelectLargeNoDuplicateParams(t *testing.T) {
	// Build multi-select with 100 options
	var options strings.Builder
	for i := 0; i < 100; i++ {
		options.WriteString(`<option value="opt` + string(rune('A'+i%26)) + `">Option</option>`)
	}

	htmlStr := `
		<form action="/submit" method="GET">
			<select name="bigmulti" multiple>` + options.String() + `</select>
		</form>
	`

	requests := extractFormRequests(t, htmlStr)

	// Should generate 100 requests (one per option)
	require.Len(t, requests, 100, "Should generate 100 requests for 100 multi-select options")

	// Each request should have exactly 1 bigmulti param (no duplicates!)
	for i, req := range requests {
		query := req.URL.RawQuery
		count := strings.Count(query, "bigmulti=")
		assert.Equal(t, 1, count,
			"Request %d should have exactly 1 bigmulti param, got %d in: %s", i, count, query)
	}
}

// Helper function to extract form requests from HTML
func extractFormRequests(t *testing.T, htmlStr string) []*FormRequest {
	t.Helper()

	baseURL, err := url.Parse("http://example.com/page")
	require.NoError(t, err)

	response := &HTTPResponse{
		Body: []byte(htmlStr),
	}

	extractor := NewFormExtractor(NewURLResolver())
	requests, err := extractor.ExtractForms(context.Background(), baseURL, response)
	require.NoError(t, err)

	return requests
}
