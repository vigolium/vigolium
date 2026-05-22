package stringslice

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestToSlice(t *testing.T) {
	cases := []struct {
		name string
		ss   StringSlice
		want []string
	}{
		{"single string", StringSlice{Value: "a"}, []string{"a"}},
		{"string slice", StringSlice{Value: []string{"a", "b"}}, []string{"a", "b"}},
		{"nil", StringSlice{Value: nil}, []string{}},
		{"zero value", StringSlice{}, []string{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.ss.ToSlice())
		})
	}
}

func TestToSlicePanicsOnUnexpectedType(t *testing.T) {
	ss := StringSlice{Value: 42}
	assert.Panics(t, func() { _ = ss.ToSlice() })
}

func TestIsEmpty(t *testing.T) {
	assert.True(t, (&StringSlice{}).IsEmpty())
	assert.True(t, (&StringSlice{Value: []string{}}).IsEmpty())
	assert.False(t, (&StringSlice{Value: "a"}).IsEmpty())
	assert.False(t, (&StringSlice{Value: []string{"a"}}).IsEmpty())
}

func TestString(t *testing.T) {
	assert.Equal(t, "a, b", StringSlice{Value: []string{"a", "b"}}.String())
	assert.Equal(t, "x", StringSlice{Value: "x"}.String())
	assert.Equal(t, "", StringSlice{}.String())
}

func TestNormalize(t *testing.T) {
	ss := StringSlice{}
	assert.Equal(t, "abc", ss.Normalize("  ABC  "))
	assert.Equal(t, "mixed", ss.Normalize("MiXeD"))
}

func TestUnmarshalJSON(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"single string", `"Foo"`, []string{"foo"}},
		{"comma string", `"Foo,Bar"`, []string{"foo", "bar"}},
		{"array", `["Foo","Bar"]`, []string{"foo", "bar"}},
		{"empty string", `""`, []string{}},
		{"empty array", `[]`, []string{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var ss StringSlice
			require.NoError(t, json.Unmarshal([]byte(tc.in), &ss))
			assert.Equal(t, tc.want, ss.ToSlice())
		})
	}
}

func TestUnmarshalJSONInvalid(t *testing.T) {
	var ss StringSlice
	require.Error(t, json.Unmarshal([]byte(`{"k":"v"}`), &ss))
}

func TestUnmarshalYAML(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"single scalar", "v: Foo\n", []string{"foo"}},
		{"comma scalar", "v: Foo,Bar\n", []string{"foo", "bar"}},
		{"list", "v:\n  - Foo\n  - Bar\n", []string{"foo", "bar"}},
		{"empty scalar", "v: \"\"\n", []string{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var holder struct {
				V StringSlice `yaml:"v"`
			}
			require.NoError(t, yaml.Unmarshal([]byte(tc.in), &holder))
			assert.Equal(t, tc.want, holder.V.ToSlice())
		})
	}
}

func TestMarshalJSON(t *testing.T) {
	ss := StringSlice{Value: []string{"a", "b"}}
	out, err := json.Marshal(ss)
	require.NoError(t, err)
	assert.JSONEq(t, `["a","b"]`, string(out))
}

func TestMarshalYAML(t *testing.T) {
	ss := StringSlice{Value: []string{"a", "b"}}
	v, err := ss.MarshalYAML()
	require.NoError(t, err)
	assert.Equal(t, []string{"a", "b"}, v)
}

func TestRoundTripJSON(t *testing.T) {
	var ss StringSlice
	require.NoError(t, json.Unmarshal([]byte(`["a","b"]`), &ss))
	out, err := json.Marshal(ss)
	require.NoError(t, err)
	assert.JSONEq(t, `["a","b"]`, string(out))
}
