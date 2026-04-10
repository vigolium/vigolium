package terminal

// Terminal symbols for different states and step types.
const (
	// Status symbols — used for step/task state indicators
	SymbolPending = "○" // Pending / waiting
	SymbolRunning = "⏺" // In progress / active
	SymbolSuccess = "✔" // Succeeded / passed
	SymbolFailed  = "⏹" // Stopped (stop square; distinct from ✖ error)
	SymbolSkipped = "◌" // Skipped / not applicable
	SymbolInfo    = "◆" // Informational notice
	SymbolWarning = "▼" // Warning / caution
	SymbolError   = "✖" // Error / critical failure

	// Navigation and flow
	SymbolStart   = "▶" // Start / play
	SymbolArrow   = "▷" // Flow direction / next
	SymbolBullet  = "•" // List item
	SymbolDiamond = "◇" // Hollow diamond / passive indicator

	// Step type and runner symbols
	SymbolFunction = "ƒ" // Function execution
	SymbolBash     = "$" // Shell command
	SymbolForeach  = "∀" // Iteration (universal quantifier)
	SymbolAgent    = "⚙" // Agent / automated process
	SymbolSSH      = "⇄" // Remote / SSH connection

	// Decorative symbols for headers and labels
	SymbolStar      = "★" // Primary highlight
	SymbolStarEmpty = "☆" // Secondary highlight
	SymbolSparkle   = "✦" // Section header / emphasis
	SymbolSparkle2  = "✧" // Subsection / secondary emphasis
	SymbolFlower    = "✿" // Decorative accent
	SymbolSun       = "☼" // Active / healthy state
	SymbolSnow      = "❄" // Frozen / disabled state
	SymbolLightning = "ϟ" // Fast / high-performance
	SymbolMenu      = "☰" // Menu / list header
	SymbolTherefore = "∴" // Conclusion / result
	SymbolCommand   = "⌘" // Keyboard shortcut / action
	SymbolCross     = "✢" // Emphasis marker
	SymbolAsterisk  = "＊" // Footnote / annotation
	SymbolHeart     = "♡" // Favorite / saved
	SymbolDiamondSm = "❖" // Decorative diamond
	SymbolBowtie    = "⋈" // Join / relation

	// Informational message types
	SymbolTip      = SymbolFlower   // Tip / helpful suggestion (✿)
	SymbolNote     = SymbolAsterisk // Note / important detail (＊)
	SymbolExample  = SymbolCommand  // Example / usage demonstration (⌘)
	SymbolQuestion = "?"            // Help / question prompt
	SymbolHint     = "›"            // Hint / subtle guidance
	SymbolPin      = "⊳"            // Pinned / key takeaway

	// Scan and security
	SymbolTarget = "◎" // Scan target / scope
	SymbolFlag   = "⚑" // Finding / flagged vulnerability

	// Progress and timing
	SymbolClock   = "⏱" // Duration / elapsed time
	SymbolRefresh = "⟳" // Retry / refresh cycle

	// Structure and layout
	SymbolChevron  = "❯" // Breadcrumb / sub-item
	SymbolEllipsis = "⋯" // Truncated / more content
	SymbolDot      = "·" // Subtle separator
	SymbolPipe     = "│" // Vertical connector / tree line
	SymbolDash     = "─" // Horizontal rule segment
	SymbolTriangle = "▸" // Collapsed / expandable item
)

// StepSymbol returns a colored status symbol based on step status
func StepSymbol(status string) string {
	switch status {
	case "pending":
		return Gray(SymbolPending)
	case "running":
		return Cyan(SymbolRunning)
	case "success":
		return Green(SymbolSuccess)
	case "failed":
		return Red(SymbolFailed)
	case "skipped":
		return Gray(SymbolSkipped)
	default:
		return SymbolBullet
	}
}

// PaddedStepSymbol returns a step symbol padded to 6 characters for table alignment
func PaddedStepSymbol(status string) string {
	return StepSymbol(status) + "     "
}

// Common status symbols with colors

// InfoSymbol returns a colored info symbol
func InfoSymbol() string {
	return Cyan(SymbolInfo)
}

// PhasePrefix returns the muted "❯ phase │" prefix used by agent phase output
// lines. Callers append their own space + message.
func PhasePrefix(phase string) string {
	return Muted(SymbolChevron + " " + phase + " " + SymbolPipe)
}

// WarningSymbol returns a colored warning symbol
func WarningSymbol() string {
	return Yellow(SymbolWarning)
}

// ErrorSymbol returns a colored error symbol
func ErrorSymbol() string {
	return Red(SymbolError)
}

// SuccessSymbol returns a colored success symbol
func SuccessSymbol() string {
	return Green(SymbolSuccess)
}

// FailedSymbol returns a colored failed symbol
func FailedSymbol() string {
	return Red(SymbolFailed)
}

// ErrorPrefix returns a red "✖ Error:" prefix for error messages
func ErrorPrefix() string {
	return BoldRed(SymbolError + " Error:")
}

// WarnPrefix returns a yellow "⚠ Warn:" prefix for warning messages
func WarnPrefix() string {
	return BoldYellow(SymbolWarning + " Warn:")
}

// Informational message helpers

// TipSymbol returns a HiTeal ✿ for helpful suggestions
func TipSymbol() string {
	return HiTeal(SymbolTip)
}

// NoteSymbol returns a cyan ＊ for important details
func NoteSymbol() string {
	return Cyan(SymbolNote)
}

// ExampleSymbol returns a green ⌘ for usage demonstrations
func ExampleSymbol() string {
	return Green(SymbolExample)
}

// HintSymbol returns a gray › for subtle guidance
func HintSymbol() string {
	return Gray(SymbolHint)
}

// TipPrefix returns a HiTeal "✿ Tip:" prefix for tip messages
func TipPrefix() string {
	return HiTeal(SymbolTip + " Tip:")
}

// NotePrefix returns a cyan "＊ Note:" prefix for note messages
func NotePrefix() string {
	return BoldCyan(SymbolNote + " Note:")
}

// ExamplePrefix returns a green "⌘ Example:" prefix for example messages
func ExamplePrefix() string {
	return BoldGreen(SymbolExample + " Example:")
}

// Section symbols

// SectionSymbol returns a bold cyan section symbol
func SectionSymbol() string {
	return BoldCyan(SymbolStart)
}

// SubSectionSymbol returns a cyan subsection symbol
func SubSectionSymbol() string {
	return Cyan(SymbolSparkle)
}

// ResultSymbol returns a yellow result symbol
func ResultSymbol() string {
	return Yellow(SymbolTherefore)
}

// ListSymbol returns a cyan list symbol
func ListSymbol() string {
	return Cyan(SymbolMenu)
}

// ArrowSymbol returns a cyan arrow symbol
func ArrowSymbol() string {
	return Cyan(SymbolArrow)
}

// FunctionSymbol returns a colored function symbol
func FunctionSymbol() string {
	return Purple(SymbolFunction)
}

// Module type symbols

// ActiveModuleSymbol returns a bold red diamond for active modules
func ActiveModuleSymbol() string {
	return BoldRed(SymbolInfo)
}

// PassiveModuleSymbol returns a bold blue hollow diamond for passive modules
func PassiveModuleSymbol() string {
	return BoldBlue(SymbolDiamond)
}

// Severity symbols

// CriticalSymbol returns a bold magenta symbol for critical severity
func CriticalSymbol() string {
	return BoldMagenta(SymbolError)
}

// HighSymbol returns a bold red symbol for high severity
func HighSymbol() string {
	return BoldRed(SymbolDiamondSm)
}

// MediumSymbol returns a bold yellow symbol for medium severity
func MediumSymbol() string {
	return BoldYellow(SymbolInfo)
}

// LowSymbol returns a bold green symbol for low severity
func LowSymbol() string {
	return BoldGreen(SymbolBullet)
}

// SuspectSymbol returns a bold cyan symbol for suspect severity
func SuspectSymbol() string {
	return BoldCyan(SymbolQuestion)
}

// InfoSeveritySymbol returns a bold blue symbol for info severity
func InfoSeveritySymbol() string {
	return BoldBlue(SymbolDiamond)
}
