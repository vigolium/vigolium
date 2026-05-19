package terminal

import "regexp"

// ansiEscapeRe matches ANSI escape sequences (color codes, cursor movements, etc.).
var ansiEscapeRe = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// StripANSI removes all ANSI escape sequences from s.
func StripANSI(s string) string {
	return ansiEscapeRe.ReplaceAllString(s, "")
}

// ANSI color codes
const (
	colorReset     = "\033[0m"
	colorBold      = "\033[1m"
	colorRed       = "\033[31m"
	colorGreen     = "\033[32m"
	colorYellow    = "\033[33m"
	colorBlue      = "\033[34m"
	colorMagenta   = "\033[35m"
	colorCyan      = "\033[36m"
	colorWhite     = "\033[37m"
	colorGray      = "\033[90m"
	colorHiRed     = "\033[91m"
	colorHiPurple  = "\033[38;5;97m"
	colorHiGreen   = "\033[92m"
	colorHiBlue    = "\033[94m"
	colorHiMagenta = "\033[95m"
	colorHiCyan    = "\033[36m"
	colorHiWhite   = "\033[97m"
	colorTeal      = "\033[38;5;30m"
	colorHiTeal    = "\033[38;5;44m"

	// Gruvbox theme (true-color)
	colorGrbRed        = "\033[38;2;251;73;52m"
	colorGrbGreen      = "\033[38;2;184;187;38m"
	colorGrbYellow     = "\033[38;2;250;189;47m"
	colorGrbBlue       = "\033[38;2;131;165;152m"
	colorGrbPurple     = "\033[38;2;211;134;155m"
	colorGrbAqua       = "\033[38;2;142;192;124m"
	colorGrbOrange     = "\033[38;2;254;128;25m"
	colorGrbForeground = "\033[38;2;235;219;178m"
	colorGrbBackground = "\033[38;2;146;131;116m"
)

// colorize wraps text with ANSI color codes if color is enabled
func colorize(color, text string) string {
	if !colorEnabled {
		return text
	}
	return color + text + colorReset
}

// Basic colors

// Red returns text in red
func Red(s string) string {
	return colorize(colorRed, s)
}

// Green returns text in green
func Green(s string) string {
	return colorize(colorGreen, s)
}

// Yellow returns text in yellow
func Yellow(s string) string {
	return colorize(colorYellow, s)
}

// Blue returns text in blue
func Blue(s string) string {
	return colorize(colorBlue, s)
}

// Cyan returns text in cyan
func Cyan(s string) string {
	return colorize(colorCyan, s)
}

// Magenta returns text in magenta
func Magenta(s string) string {
	return colorize(colorMagenta, s)
}

// Gray returns text in gray
func Gray(s string) string {
	return colorize(colorGray, s)
}

// White returns text in white
func White(s string) string {
	return colorize(colorWhite, s)
}

// Teal returns text in teal
func Teal(s string) string {
	return colorize(colorTeal, s)
}

// Bold variants

// Bold returns text in bold
func Bold(s string) string {
	return colorize(colorBold, s)
}

// BoldRed returns text in bold red
func BoldRed(s string) string {
	if !colorEnabled {
		return s
	}
	return colorBold + colorRed + s + colorReset
}

// BoldGreen returns text in bold green
func BoldGreen(s string) string {
	if !colorEnabled {
		return s
	}
	return colorBold + colorGreen + s + colorReset
}

// BoldYellow returns text in bold yellow
func BoldYellow(s string) string {
	if !colorEnabled {
		return s
	}
	return colorBold + colorYellow + s + colorReset
}

// BoldCyan returns text in bold cyan
func BoldCyan(s string) string {
	if !colorEnabled {
		return s
	}
	return colorBold + colorCyan + s + colorReset
}

// BoldBlue returns text in bold blue
func BoldBlue(s string) string {
	if !colorEnabled {
		return s
	}
	return colorBold + colorBlue + s + colorReset
}

// BoldMagenta returns text in bold magenta
func BoldMagenta(s string) string {
	if !colorEnabled {
		return s
	}
	return colorBold + colorMagenta + s + colorReset
}

// Bright/Hi variants

// HiRed returns text in bright red
func HiRed(s string) string {
	return colorize(colorHiRed, s)
}

// HiPurple returns text in bright purple
func HiPurple(s string) string {
	return colorize(colorHiPurple, s)
}

// HiGreen returns text in bright green
func HiGreen(s string) string {
	return colorize(colorHiGreen, s)
}

// HiCyan returns text in bright cyan
func HiCyan(s string) string {
	return colorize(colorHiCyan, s)
}

// HiBlue returns text in bright blue
func HiBlue(s string) string {
	return colorize(colorHiBlue, s)
}

// BoldHiBlue returns bold bright blue text
func BoldHiBlue(s string) string {
	if !colorEnabled {
		return s
	}
	return colorBold + colorHiBlue + s + colorReset
}

// HiMagenta returns text in bright magenta
func HiMagenta(s string) string {
	return colorize(colorHiMagenta, s)
}

// HiWhite returns text in bright white
func HiWhite(s string) string {
	return colorize(colorHiWhite, s)
}

// HiTeal returns text in bright teal
func HiTeal(s string) string {
	return colorize(colorHiTeal, s)
}

// Gruvbox theme colors

// Orange returns text in gruvbox orange
func Orange(s string) string {
	return colorize(colorGrbOrange, s)
}

// Aqua returns text in gruvbox aqua
func Aqua(s string) string {
	return colorize(colorGrbAqua, s)
}

// Purple returns text in gruvbox purple
func Purple(s string) string {
	return colorize(colorGrbPurple, s)
}

// Foreground returns text in gruvbox foreground (warm light)
func Foreground(s string) string {
	return colorize(colorGrbForeground, s)
}

// Muted returns text in gruvbox background gray
func Muted(s string) string {
	return colorize(colorGrbBackground, s)
}

// BoldOrange returns text in bold gruvbox orange
func BoldOrange(s string) string {
	if !colorEnabled {
		return s
	}
	return colorBold + colorGrbOrange + s + colorReset
}

// BoldAqua returns text in bold gruvbox aqua
func BoldAqua(s string) string {
	if !colorEnabled {
		return s
	}
	return colorBold + colorGrbAqua + s + colorReset
}

// BoldPurple returns text in bold gruvbox purple
func BoldPurple(s string) string {
	if !colorEnabled {
		return s
	}
	return colorBold + colorGrbPurple + s + colorReset
}

// GrbRed returns text in gruvbox red
func GrbRed(s string) string {
	return colorize(colorGrbRed, s)
}

// GrbGreen returns text in gruvbox green
func GrbGreen(s string) string {
	return colorize(colorGrbGreen, s)
}

// GrbYellow returns text in gruvbox yellow
func GrbYellow(s string) string {
	return colorize(colorGrbYellow, s)
}

// GrbBlue returns text in gruvbox blue
func GrbBlue(s string) string {
	return colorize(colorGrbBlue, s)
}
