package terminal

import (
	"os"
	"testing"
)

func TestColorize(t *testing.T) {
	// Save original state
	originalEnabled := colorEnabled
	defer func() { colorEnabled = originalEnabled }()

	tests := []struct {
		name     string
		enabled  bool
		input    string
		expected string
	}{
		{
			name:     "color enabled - red",
			enabled:  true,
			input:    "test",
			expected: "\033[31mtest\033[0m",
		},
		{
			name:     "color disabled - red",
			enabled:  false,
			input:    "test",
			expected: "test",
		},
		{
			name:     "color enabled - empty string",
			enabled:  true,
			input:    "",
			expected: "\033[31m\033[0m",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SetColorEnabled(tt.enabled)
			result := Red(tt.input)
			if result != tt.expected {
				t.Errorf("Red(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestBasicColors(t *testing.T) {
	// Save original state
	originalEnabled := colorEnabled
	defer func() { colorEnabled = originalEnabled }()

	SetColorEnabled(true)

	tests := []struct {
		name     string
		fn       func(string) string
		expected string
	}{
		{"Red", Red, "\033[31mtest\033[0m"},
		{"Green", Green, "\033[32mtest\033[0m"},
		{"Yellow", Yellow, "\033[33mtest\033[0m"},
		{"Blue", Blue, "\033[34mtest\033[0m"},
		{"Cyan", Cyan, "\033[36mtest\033[0m"},
		{"Magenta", Magenta, "\033[35mtest\033[0m"},
		{"Gray", Gray, "\033[90mtest\033[0m"},
		{"White", White, "\033[37mtest\033[0m"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.fn("test")
			if result != tt.expected {
				t.Errorf("%s(\"test\") = %q, want %q", tt.name, result, tt.expected)
			}
		})
	}
}

func TestBoldColors(t *testing.T) {
	// Save original state
	originalEnabled := colorEnabled
	defer func() { colorEnabled = originalEnabled }()

	SetColorEnabled(true)

	tests := []struct {
		name     string
		fn       func(string) string
		expected string
	}{
		{"BoldRed", BoldRed, "\033[1m\033[31mtest\033[0m"},
		{"BoldGreen", BoldGreen, "\033[1m\033[32mtest\033[0m"},
		{"BoldYellow", BoldYellow, "\033[1m\033[33mtest\033[0m"},
		{"BoldBlue", BoldBlue, "\033[1m\033[34mtest\033[0m"},
		{"BoldCyan", BoldCyan, "\033[1m\033[36mtest\033[0m"},
		{"BoldMagenta", BoldMagenta, "\033[1m\033[35mtest\033[0m"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.fn("test")
			if result != tt.expected {
				t.Errorf("%s(\"test\") = %q, want %q", tt.name, result, tt.expected)
			}
		})
	}
}

func TestColorDisabled(t *testing.T) {
	// Save original state
	originalEnabled := colorEnabled
	defer func() { colorEnabled = originalEnabled }()

	SetColorEnabled(false)

	input := "test"
	tests := []struct {
		name string
		fn   func(string) string
	}{
		{"Red", Red},
		{"Green", Green},
		{"BoldRed", BoldRed},
		{"BoldGreen", BoldGreen},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.fn(input)
			if result != input {
				t.Errorf("%s(%q) = %q with colors disabled, want %q", tt.name, input, result, input)
			}
		})
	}
}

func TestNOCOLOR(t *testing.T) {
	// This test verifies the NO_COLOR environment variable is respected
	// Note: This test doesn't actually set NO_COLOR as init() runs before tests
	// It just verifies the SetColorEnabled function works

	// Save original state
	originalEnabled := colorEnabled
	defer func() { colorEnabled = originalEnabled }()

	// Simulate NO_COLOR behavior
	SetColorEnabled(false)

	result := Red("test")
	if result != "test" {
		t.Errorf("Red(\"test\") with colors disabled = %q, want \"test\"", result)
	}
}

func TestIsColorEnabled(t *testing.T) {
	// Save original state
	originalEnabled := colorEnabled
	defer func() { colorEnabled = originalEnabled }()

	SetColorEnabled(true)
	if !IsColorEnabled() {
		t.Error("IsColorEnabled() = false, want true")
	}

	SetColorEnabled(false)
	if IsColorEnabled() {
		t.Error("IsColorEnabled() = true, want false")
	}
}

func TestCIMode(t *testing.T) {
	// Save original state
	originalCIMode := ciMode
	defer func() { ciMode = originalCIMode }()

	SetCIMode(true)
	if !IsCIMode() {
		t.Error("IsCIMode() = false, want true")
	}

	SetCIMode(false)
	if IsCIMode() {
		t.Error("IsCIMode() = true, want false")
	}
}

// TestInit verifies the init function behavior
// This is a basic test that checks if NO_COLOR env var is respected
func TestInit(t *testing.T) {
	// Check if NO_COLOR env var is set
	noColor := os.Getenv("NO_COLOR")
	if noColor != "" {
		// If NO_COLOR is set, colors should be disabled
		if IsColorEnabled() {
			t.Error("Colors should be disabled when NO_COLOR is set")
		}
	}
}
