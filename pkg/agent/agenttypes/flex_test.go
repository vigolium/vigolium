package agenttypes

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAgentFinding_FlexLine(t *testing.T) {
	tests := []struct {
		name string
		json string
		line int
	}{
		{"int", `{"title":"xss","line":42}`, 42},
		{"string", `{"title":"xss","line":"42"}`, 42},
		{"float", `{"title":"xss","line":42.0}`, 42},
		{"zero", `{"title":"xss","line":0}`, 0},
		{"missing", `{"title":"xss"}`, 0},
		{"garbage", `{"title":"xss","line":"n/a"}`, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var f AgentFinding
			require.NoError(t, json.Unmarshal([]byte(tt.json), &f))
			assert.Equal(t, tt.line, f.Line)
			assert.Equal(t, "xss", f.Title)
		})
	}
}

func TestAgentFinding_FlexTags(t *testing.T) {
	tests := []struct {
		name string
		json string
		tags []string
	}{
		{"array", `{"title":"t","tags":["a","b"]}`, []string{"a", "b"}},
		{"single string", `{"title":"t","tags":"xss"}`, []string{"xss"}},
		{"missing", `{"title":"t"}`, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var f AgentFinding
			require.NoError(t, json.Unmarshal([]byte(tt.json), &f))
			assert.Equal(t, tt.tags, f.Tags)
		})
	}
}

func TestAgentExpectResponse_FlexStatus(t *testing.T) {
	tests := []struct {
		name   string
		json   string
		status []int
	}{
		{"int array", `{"status":[200,201]}`, []int{200, 201}},
		{"string array", `{"status":["200","201"]}`, []int{200, 201}},
		{"mixed array", `{"status":[200,"201"]}`, []int{200, 201}},
		{"single int", `{"status":200}`, []int{200}},
		{"single string", `{"status":"200"}`, []int{200}},
		{"missing", `{}`, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var r AgentExpectResponse
			require.NoError(t, json.Unmarshal([]byte(tt.json), &r))
			assert.Equal(t, tt.status, r.Status)
		})
	}
}

func TestAgentExtractRule_FlexGroup(t *testing.T) {
	tests := []struct {
		name  string
		json  string
		group int
	}{
		{"int", `{"source":"regex","group":1}`, 1},
		{"string", `{"source":"regex","group":"1"}`, 1},
		{"missing", `{"source":"cookie"}`, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var r AgentExtractRule
			require.NoError(t, json.Unmarshal([]byte(tt.json), &r))
			assert.Equal(t, tt.group, r.Group)
		})
	}
}

func TestQuickCheckMatch_FlexStatus(t *testing.T) {
	tests := []struct {
		name   string
		json   string
		status int
	}{
		{"int", `{"status":200}`, 200},
		{"string", `{"status":"200"}`, 200},
		{"missing", `{"body_contains":"ok"}`, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var m QuickCheckMatch
			require.NoError(t, json.Unmarshal([]byte(tt.json), &m))
			assert.Equal(t, tt.status, m.Status)
		})
	}
}

func TestFlexInt(t *testing.T) {
	assert.Equal(t, 42, flexInt(float64(42)))
	assert.Equal(t, 42, flexInt("42"))
	assert.Equal(t, 42, flexInt("42.0"))
	assert.Equal(t, 0, flexInt("garbage"))
	assert.Equal(t, 0, flexInt(nil))
	assert.Equal(t, 0, flexInt(true))
}

func TestFlexIntSlice(t *testing.T) {
	assert.Equal(t, []int{200, 201}, flexIntSlice([]interface{}{float64(200), float64(201)}))
	assert.Equal(t, []int{200, 201}, flexIntSlice([]interface{}{"200", "201"}))
	assert.Equal(t, []int{200}, flexIntSlice(float64(200)))
	assert.Equal(t, []int{200}, flexIntSlice("200"))
	assert.Nil(t, flexIntSlice(nil))
}

func TestFlexStringSlice(t *testing.T) {
	assert.Equal(t, []string{"a", "b"}, flexStringSlice([]interface{}{"a", "b"}))
	assert.Equal(t, []string{"xss"}, flexStringSlice("xss"))
	assert.Nil(t, flexStringSlice(""))
	assert.Nil(t, flexStringSlice(nil))
}
