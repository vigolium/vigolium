package stateexposure

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAnalyzeClassifiesSignalsWithoutEchoingValues(t *testing.T) {
	state := `{
		"api_key":"sk_live_01` + `23456789ab` + `cdef",
		"aws_key":"AKIAIOSFODNN7EXAMPLE",
		"role":"admin",
		"email":"user@example.test",
		"db":"postgres://app:real-password@10.0.0.4/db"
	}`
	hits := Analyze(state)
	require.NotEmpty(t, hits)

	candidates := 0
	for _, hit := range hits {
		if hit.Candidate {
			candidates++
		}
		assert.NotContains(t, hit.Evidence, "sk_live_01" + "23456789ab" + "cdef")
		assert.NotContains(t, hit.Evidence, "real-password")
	}
	assert.Equal(t, 2, candidates, "private token and password-bearing database URL should be candidates")
}

func TestAnalyzeRoutineClientStateIsObservationOnly(t *testing.T) {
	hits := Analyze(`{"isAdmin":true,"email":"user@example.test","internal":"http://192.168.1.10:8080","api_key":"AKIAIOSFODNN7EXAMPLE"}`)
	require.NotEmpty(t, hits)
	for _, hit := range hits {
		assert.False(t, hit.Candidate, hit.Category)
	}
}

func TestAnalyzePlaceholderCredentialIsObservation(t *testing.T) {
	hits := Analyze(`{"api_key":"YOUR_API_KEY"}`)
	require.Len(t, hits, 1)
	assert.False(t, hits[0].Candidate)
}
