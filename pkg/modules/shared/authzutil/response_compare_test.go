package authzutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSummarizeResponse(t *testing.T) {
	body := []byte(`{"error": "unauthorized"}`)
	summary := SummarizeResponse(403, "application/json", body)
	require.NotNil(t, summary)
	assert.Equal(t, 403, summary.StatusCode)
	assert.Equal(t, len(body), summary.BodyLength)
	assert.Equal(t, "application/json", summary.ContentType)
	assert.True(t, summary.HasErrorMessage)
}

func TestSummarizeResponse_NoError(t *testing.T) {
	body := []byte(`{"data": [1, 2, 3]}`)
	summary := SummarizeResponse(200, "application/json", body)
	assert.False(t, summary.HasErrorMessage)
}

func TestSummarizeResponse_EmptyBody(t *testing.T) {
	summary := SummarizeResponse(204, "", nil)
	assert.Equal(t, 0, summary.BodyLength)
	assert.False(t, summary.HasErrorMessage)
}

func TestCompareResponses_Identical(t *testing.T) {
	body := []byte(`{"user": "john"}`)
	baseline := SummarizeResponse(200, "application/json", body)
	probe := SummarizeResponse(200, "application/json", body)

	comp := CompareResponses(baseline, probe, DefaultCompareOptions())
	assert.True(t, comp.StatusCodeMatch)
	assert.True(t, comp.ContentIdentical)
	assert.True(t, comp.StructurallyIdentical)
	assert.Equal(t, 0, comp.BodyLengthDelta)
	assert.Equal(t, 1.0, comp.BodyLengthRatio)
}

func TestCompareResponses_DifferentStatus(t *testing.T) {
	baseline := SummarizeResponse(200, "application/json", []byte(`ok`))
	probe := SummarizeResponse(403, "application/json", []byte(`forbidden`))

	comp := CompareResponses(baseline, probe, DefaultCompareOptions())
	assert.False(t, comp.StatusCodeMatch)
	assert.False(t, comp.ContentIdentical)
	assert.False(t, comp.StructurallyIdentical)
}

func TestCompareResponses_SimilarLength(t *testing.T) {
	baseline := SummarizeResponse(200, "application/json", []byte(`{"user": "john", "role": "admin"}`))
	probe := SummarizeResponse(200, "application/json", []byte(`{"user": "jane", "role": "admin"}`))

	comp := CompareResponses(baseline, probe, DefaultCompareOptions())
	assert.True(t, comp.StatusCodeMatch)
	assert.False(t, comp.ContentIdentical)
	assert.True(t, comp.StructurallyIdentical) // similar size, same status
	assert.InDelta(t, 1.0, comp.BodyLengthRatio, 0.05)
}

func TestCompareResponses_VeryDifferentLength(t *testing.T) {
	baseline := SummarizeResponse(200, "application/json", []byte(`{"data": "a"}`))
	probe := SummarizeResponse(200, "application/json", make([]byte, 10000))

	opts := DefaultCompareOptions()
	comp := CompareResponses(baseline, probe, opts)
	assert.True(t, comp.StatusCodeMatch)
	assert.False(t, comp.ContentIdentical)
	assert.False(t, comp.StructurallyIdentical) // length ratio too low
}

func TestCompareResponses_BothEmpty(t *testing.T) {
	baseline := SummarizeResponse(204, "", nil)
	probe := SummarizeResponse(204, "", nil)

	comp := CompareResponses(baseline, probe, DefaultCompareOptions())
	assert.True(t, comp.StatusCodeMatch)
	assert.True(t, comp.ContentIdentical)
	assert.Equal(t, 1.0, comp.BodyLengthRatio)
}

func TestCompareResponses_NilInputs(t *testing.T) {
	comp := CompareResponses(nil, nil, DefaultCompareOptions())
	assert.False(t, comp.StatusCodeMatch)

	comp = CompareResponses(SummarizeResponse(200, "", nil), nil, DefaultCompareOptions())
	assert.False(t, comp.StatusCodeMatch)
}

func TestCompareResponses_UserFieldsDiffer(t *testing.T) {
	baseline := SummarizeResponse(200, "application/json", []byte(`{"username": "john", "email": "john@test.com"}`))
	probe := SummarizeResponse(200, "application/json", []byte(`{"username": "jane", "data": "other"}`))

	opts := DefaultCompareOptions()
	comp := CompareResponses(baseline, probe, opts)

	// "username" is in both (shared), "email" is only in baseline (differing)
	assert.Contains(t, comp.SharedFields, "username")
	assert.Contains(t, comp.DifferingFields, "email")
	assert.True(t, comp.UserFieldsDiffer)
}

func TestAuthzVerdict_String(t *testing.T) {
	assert.Equal(t, "enforced", VerdictEnforced.String())
	assert.Equal(t, "bypassed", VerdictBypassed.String())
	assert.Equal(t, "uncertain", VerdictUncertain.String())
}

func TestDefaultCompareOptions(t *testing.T) {
	opts := DefaultCompareOptions()
	assert.Equal(t, 0.8, opts.SimilarityThreshold)
	assert.NotEmpty(t, opts.UserSpecificFields)
}
