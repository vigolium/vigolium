package terminal

import (
	"strings"
	"testing"
)

func TestSymbolConstants(t *testing.T) {
	// Verify symbol constants are defined and not empty
	symbols := map[string]string{
		"SymbolPending":   SymbolPending,
		"SymbolRunning":   SymbolRunning,
		"SymbolStart":     SymbolStart,
		"SymbolSuccess":   SymbolSuccess,
		"SymbolFailed":    SymbolFailed,
		"SymbolSkipped":   SymbolSkipped,
		"SymbolInfo":      SymbolInfo,
		"SymbolWarning":   SymbolWarning,
		"SymbolError":     SymbolError,
		"SymbolArrow":     SymbolArrow,
		"SymbolBullet":    SymbolBullet,
		"SymbolDiamond":   SymbolDiamond,
		"SymbolFunction":  SymbolFunction,
		"SymbolBash":      SymbolBash,
		"SymbolForeach":   SymbolForeach,
		"SymbolAgent":     SymbolAgent,
		"SymbolSSH":       SymbolSSH,
		"SymbolStar":      SymbolStar,
		"SymbolStarEmpty": SymbolStarEmpty,
		"SymbolSparkle":   SymbolSparkle,
		"SymbolSparkle2":  SymbolSparkle2,
		"SymbolFlower":    SymbolFlower,
		"SymbolSun":       SymbolSun,
		"SymbolSnow":      SymbolSnow,
		"SymbolLightning": SymbolLightning,
		"SymbolMenu":      SymbolMenu,
		"SymbolTherefore": SymbolTherefore,
		"SymbolCommand":   SymbolCommand,
		"SymbolCross":     SymbolCross,
		"SymbolAsterisk":  SymbolAsterisk,
		"SymbolHeart":     SymbolHeart,
		"SymbolDiamondSm": SymbolDiamondSm,
		"SymbolBowtie":    SymbolBowtie,
		"SymbolTip":       SymbolTip,
		"SymbolNote":      SymbolNote,
		"SymbolExample":   SymbolExample,
		"SymbolQuestion":  SymbolQuestion,
		"SymbolHint":      SymbolHint,
		"SymbolPin":       SymbolPin,
		"SymbolTarget":    SymbolTarget,
		"SymbolFlag":      SymbolFlag,
		"SymbolClock":     SymbolClock,
		"SymbolRefresh":   SymbolRefresh,
		"SymbolChevron":   SymbolChevron,
		"SymbolEllipsis":  SymbolEllipsis,
		"SymbolDot":       SymbolDot,
		"SymbolPipe":      SymbolPipe,
		"SymbolDash":      SymbolDash,
		"SymbolTriangle":  SymbolTriangle,
	}

	for name, symbol := range symbols {
		if symbol == "" {
			t.Errorf("%s should not be empty", name)
		}
	}
}

func TestStepSymbol(t *testing.T) {
	// Save original state
	originalEnabled := colorEnabled
	defer func() { colorEnabled = originalEnabled }()

	tests := []struct {
		status   string
		contains string // substring to check for in output
	}{
		{"pending", SymbolPending},
		{"running", SymbolRunning},
		{"success", SymbolSuccess},
		{"failed", SymbolFailed},
		{"skipped", SymbolSkipped},
		{"unknown", SymbolBullet},
	}

	for _, tt := range tests {
		t.Run(tt.status, func(t *testing.T) {
			SetColorEnabled(false) // Test without colors first
			result := StepSymbol(tt.status)
			if result != tt.contains {
				t.Errorf("StepSymbol(%q) = %q, want %q", tt.status, result, tt.contains)
			}

			SetColorEnabled(true) // Test with colors
			result = StepSymbol(tt.status)
			if !strings.Contains(result, tt.contains) {
				t.Errorf("StepSymbol(%q) with colors should contain %q", tt.status, tt.contains)
			}
		})
	}
}

func TestPaddedStepSymbol(t *testing.T) {
	// Save original state
	originalEnabled := colorEnabled
	defer func() { colorEnabled = originalEnabled }()

	SetColorEnabled(false)

	result := PaddedStepSymbol("pending")
	expected := SymbolPending + "     " // 6 chars total
	if result != expected {
		t.Errorf("PaddedStepSymbol(\"pending\") = %q, want %q", result, expected)
	}
}

func TestStatusSymbols(t *testing.T) {
	// Save original state
	originalEnabled := colorEnabled
	defer func() { colorEnabled = originalEnabled }()

	SetColorEnabled(false)

	tests := []struct {
		name     string
		fn       func() string
		expected string
	}{
		{"InfoSymbol", InfoSymbol, SymbolInfo},
		{"WarningSymbol", WarningSymbol, SymbolWarning},
		{"ErrorSymbol", ErrorSymbol, SymbolError},
		{"SuccessSymbol", SuccessSymbol, SymbolSuccess},
		{"FailedSymbol", FailedSymbol, SymbolFailed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.fn()
			if result != tt.expected {
				t.Errorf("%s() = %q, want %q", tt.name, result, tt.expected)
			}
		})
	}
}

func TestInfoMessageSymbols(t *testing.T) {
	originalEnabled := colorEnabled
	defer func() { colorEnabled = originalEnabled }()

	SetColorEnabled(false)

	tests := []struct {
		name     string
		fn       func() string
		expected string
	}{
		{"TipSymbol", TipSymbol, SymbolTip},
		{"NoteSymbol", NoteSymbol, SymbolNote},
		{"ExampleSymbol", ExampleSymbol, SymbolExample},
		{"HintSymbol", HintSymbol, SymbolHint},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.fn()
			if result != tt.expected {
				t.Errorf("%s() = %q, want %q", tt.name, result, tt.expected)
			}
		})
	}
}

func TestInfoMessagePrefixes(t *testing.T) {
	originalEnabled := colorEnabled
	defer func() { colorEnabled = originalEnabled }()

	SetColorEnabled(false)

	tests := []struct {
		name     string
		fn       func() string
		contains string
	}{
		{"TipPrefix", TipPrefix, "Tip:"},
		{"NotePrefix", NotePrefix, "Note:"},
		{"ExamplePrefix", ExamplePrefix, "Example:"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.fn()
			if !strings.Contains(result, tt.contains) {
				t.Errorf("%s() = %q, should contain %q", tt.name, result, tt.contains)
			}
		})
	}
}

func TestSectionSymbols(t *testing.T) {
	// Save original state
	originalEnabled := colorEnabled
	defer func() { colorEnabled = originalEnabled }()

	SetColorEnabled(false)

	tests := []struct {
		name     string
		fn       func() string
		expected string
	}{
		{"SectionSymbol", SectionSymbol, SymbolStart},
		{"SubSectionSymbol", SubSectionSymbol, SymbolSparkle},
		{"ResultSymbol", ResultSymbol, SymbolTherefore},
		{"ListSymbol", ListSymbol, SymbolMenu},
		{"ArrowSymbol", ArrowSymbol, SymbolArrow},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.fn()
			if result != tt.expected {
				t.Errorf("%s() = %q, want %q", tt.name, result, tt.expected)
			}
		})
	}
}

func TestModuleSymbols(t *testing.T) {
	// Save original state
	originalEnabled := colorEnabled
	defer func() { colorEnabled = originalEnabled }()

	SetColorEnabled(false)

	tests := []struct {
		name     string
		fn       func() string
		expected string
	}{
		{"ActiveModuleSymbol", ActiveModuleSymbol, SymbolInfo},
		{"PassiveModuleSymbol", PassiveModuleSymbol, SymbolDiamond},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.fn()
			if result != tt.expected {
				t.Errorf("%s() = %q, want %q", tt.name, result, tt.expected)
			}
		})
	}
}

func TestSeveritySymbols(t *testing.T) {
	// Save original state
	originalEnabled := colorEnabled
	defer func() { colorEnabled = originalEnabled }()

	SetColorEnabled(false)

	tests := []struct {
		name     string
		fn       func() string
		expected string
	}{
		{"CriticalSymbol", CriticalSymbol, SymbolError},
		{"HighSymbol", HighSymbol, SymbolDiamondSm},
		{"MediumSymbol", MediumSymbol, SymbolInfo},
		{"LowSymbol", LowSymbol, SymbolBullet},
		{"InfoSeveritySymbol", InfoSeveritySymbol, SymbolDiamond},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.fn()
			if result != tt.expected {
				t.Errorf("%s() = %q, want %q", tt.name, result, tt.expected)
			}
		})
	}
}

func TestSymbolsWithColors(t *testing.T) {
	// Save original state
	originalEnabled := colorEnabled
	defer func() { colorEnabled = originalEnabled }()

	SetColorEnabled(true)

	// Verify that colored symbols contain ANSI codes
	tests := []struct {
		name string
		fn   func() string
	}{
		{"InfoSymbol", InfoSymbol},
		{"WarningSymbol", WarningSymbol},
		{"ErrorSymbol", ErrorSymbol},
		{"SuccessSymbol", SuccessSymbol},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.fn()
			if !strings.Contains(result, "\033[") {
				t.Errorf("%s() should contain ANSI codes when colors enabled", tt.name)
			}
		})
	}
}
