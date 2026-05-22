package severity

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestSeverityString(t *testing.T) {
	cases := []struct {
		sev  Severity
		want string
	}{
		{Info, "info"},
		{Suspect, "suspect"},
		{Low, "low"},
		{Medium, "medium"},
		{High, "high"},
		{Critical, "critical"},
		// Undefined and out-of-range values map to "" (no mapping entry).
		{Undefined, ""},
		{Severity(999), ""},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, tc.sev.String(), "Severity(%d).String()", int(tc.sev))
	}
}

func TestAllNames(t *testing.T) {
	got := AllNames()
	want := []string{"info", "suspect", "low", "medium", "high", "critical"}
	assert.Equal(t, want, got)
	// Ordering is least-to-most-severe and matches the underlying enum order.
	assert.Equal(t, Info.String(), got[0])
	assert.Equal(t, Critical.String(), got[len(got)-1])
}

func TestToSeverity(t *testing.T) {
	cases := []struct {
		in      string
		want    Severity
		wantErr bool
	}{
		{"info", Info, false},
		{"INFO", Info, false},     // normalized to lowercase
		{"  high  ", High, false}, // trimmed
		{"critical", Critical, false},
		{"unknown", -1, true},
		{"", -1, true},
	}
	for _, tc := range cases {
		got, err := toSeverity(tc.in)
		if tc.wantErr {
			require.Error(t, err, "input %q", tc.in)
			continue
		}
		require.NoError(t, err, "input %q", tc.in)
		assert.Equal(t, tc.want, got)
	}
}

func TestSeverityMarshalJSON(t *testing.T) {
	for _, sev := range []Severity{Info, Suspect, Low, Medium, High, Critical} {
		data, err := sev.MarshalJSON()
		require.NoError(t, err)
		var s string
		require.NoError(t, json.Unmarshal(data, &s))
		assert.Equal(t, sev.String(), s)
	}
}

func TestSeveritiesRoundTripJSON(t *testing.T) {
	// Array form.
	var sevs Severities
	require.NoError(t, json.Unmarshal([]byte(`["low","high"]`), &sevs))
	assert.Equal(t, Severities{Low, High}, sevs)

	out, err := json.Marshal(sevs)
	require.NoError(t, err)
	assert.JSONEq(t, `["low","high"]`, string(out))

	// Single-string form (StringSlice accepts a scalar).
	var single Severities
	require.NoError(t, json.Unmarshal([]byte(`"medium"`), &single))
	assert.Equal(t, Severities{Medium}, single)
}

func TestSeveritiesUnmarshalJSONInvalid(t *testing.T) {
	var sevs Severities
	err := json.Unmarshal([]byte(`["bogus"]`), &sevs)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a valid severity")
}

func TestSeveritiesUnmarshalYAML(t *testing.T) {
	// List form.
	var listVal struct {
		Sev Severities `yaml:"sev"`
	}
	require.NoError(t, yaml.Unmarshal([]byte("sev:\n  - low\n  - critical\n"), &listVal))
	assert.Equal(t, Severities{Low, Critical}, listVal.Sev)

	// Inline scalar form.
	var scalarVal struct {
		Sev Severities `yaml:"sev"`
	}
	require.NoError(t, yaml.Unmarshal([]byte("sev: high\n"), &scalarVal))
	assert.Equal(t, Severities{High}, scalarVal.Sev)

	// Invalid value surfaces an error.
	var badVal struct {
		Sev Severities `yaml:"sev"`
	}
	require.Error(t, yaml.Unmarshal([]byte("sev: notreal\n"), &badVal))
}

func TestSeveritiesSet(t *testing.T) {
	var sevs Severities
	require.NoError(t, sevs.Set("low, high , medium"))
	assert.Equal(t, Severities{Low, High, Medium}, sevs)

	// Dedup: repeated value is skipped, insertion order preserved.
	require.NoError(t, sevs.Set("low"))
	assert.Equal(t, Severities{Low, High, Medium}, sevs)

	// Empty segments are ignored.
	var empties Severities
	require.NoError(t, empties.Set("low,,"))
	assert.Equal(t, Severities{Low}, empties)

	// Invalid value errors.
	var bad Severities
	require.Error(t, bad.Set("nope"))
}

func TestSeveritiesType(t *testing.T) {
	var sevs Severities
	assert.Equal(t, "severities", sevs.Type())
}

func TestSeveritiesString(t *testing.T) {
	sevs := Severities{Low, High}
	assert.Equal(t, "low, high", sevs.String())
	assert.Equal(t, "", Severities{}.String())
}

func TestConfidenceString(t *testing.T) {
	assert.Equal(t, "tentative", Tentative.String())
	assert.Equal(t, "firm", Firm.String())
	assert.Equal(t, "certain", Certain.String())
	// Undefined / unknown falls back to "firm".
	assert.Equal(t, "firm", ConfidenceUndefined.String())
	assert.Equal(t, "firm", Confidence(99).String())
}

func TestConfidenceMarshalJSON(t *testing.T) {
	data, err := Certain.MarshalJSON()
	require.NoError(t, err)
	var s string
	require.NoError(t, json.Unmarshal(data, &s))
	assert.Equal(t, "certain", s)
}

func TestToConfidence(t *testing.T) {
	cases := []struct {
		in   string
		want Confidence
	}{
		{"certain", Certain},
		{"CERTAIN", Certain},
		{"  firm ", Firm},
		{"tentative", Tentative},
		{"", ConfidenceUndefined},
		{"unknown", ConfidenceUndefined},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, ToConfidence(tc.in), "input %q", tc.in)
	}
}
