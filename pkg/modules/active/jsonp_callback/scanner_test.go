package jsonp_callback

import (
	"testing"
)

func TestJSONPPattern(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{"simple jsonp", `callback({"key":"value"})`, true},
		{"jsonp with semicolon", `callback({"key":"value"});`, true},
		{"jsonp with underscore", `_callback({"key":"value"})`, true},
		{"jsonp with array", `callback([1,2,3])`, true},
		{"plain json", `{"key":"value"}`, false},
		{"plain array", `[1,2,3]`, false},
		{"html", `<html></html>`, false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := jsonpPattern.MatchString(tt.body)
			if got != tt.expected {
				t.Errorf("jsonpPattern.MatchString(%q) = %v, want %v", tt.body, got, tt.expected)
			}
		})
	}
}

func TestInjectedPattern(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{"injected callback", `vgnmCallback({"key":"value"})`, true},
		{"injected with space", ` vgnmCallback({"key":"value"})`, true},
		{"different callback", `otherFunc({"key":"value"})`, false},
		{"plain json", `{"key":"value"}`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := injectedPattern.MatchString(tt.body)
			if got != tt.expected {
				t.Errorf("injectedPattern.MatchString(%q) = %v, want %v", tt.body, got, tt.expected)
			}
		})
	}
}

func TestContainsSensitiveData(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{"has email", `{"email": "test@example.com"}`, true},
		{"has token", `{"access_token": "abc123"}`, true},
		{"has password", `{"password": "secret"}`, true},
		{"no sensitive data", `{"name": "John", "age": 30}`, false},
		{"has phone", `{"phone": "123-456-7890"}`, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containsSensitiveData(tt.body)
			if got != tt.expected {
				t.Errorf("containsSensitiveData(%q) = %v, want %v", tt.body, got, tt.expected)
			}
		})
	}
}
