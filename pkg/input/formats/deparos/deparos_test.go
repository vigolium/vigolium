package deparos

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

const testDataPath = "../../../../test/testdata/third-party-output/deparos-results.jsonl"

func TestDeparosParse(t *testing.T) {
	parser := New()

	var results []*httpmsg.HttpRequestResponse
	err := parser.Parse(testDataPath, func(rr *httpmsg.HttpRequestResponse) bool {
		results = append(results, rr)
		return true
	})
	require.NoError(t, err)
	assert.Equal(t, 9, len(results), "expected 9 results from deparos test data")

	// First result should have a reconstructed response with status 200
	first := results[0]
	require.NotNil(t, first.Request(), "first result should have a request")
	require.NotNil(t, first.Response(), "first result should have a reconstructed response")
	assert.Equal(t, 200, first.Response().StatusCode())
}

func TestDeparosCount(t *testing.T) {
	parser := New()

	count, err := parser.Count(testDataPath)
	require.NoError(t, err)
	assert.Equal(t, int64(9), count)
}

func TestDeparosName(t *testing.T) {
	parser := New()
	assert.Equal(t, "deparos", parser.Name())
}
