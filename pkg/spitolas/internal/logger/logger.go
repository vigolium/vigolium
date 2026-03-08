package logger

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Level represents logging verbosity.
type Level int

const (
	LevelSilent Level = iota // No output at all
	LevelError               // Default - errors and fatal only
	LevelDebug               // Verbose - all details
)

// New creates a new zap logger with the specified level.
// Following zap best practices from BetterStack guide.
func New(level Level) *zap.Logger {
	// Silent mode: return no-op logger
	if level == LevelSilent {
		return zap.NewNop()
	}

	// Use Development config for CLI tool (human-friendly output)
	cfg := zap.NewDevelopmentConfig()

	// Customize encoder for cleaner CLI output
	cfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	cfg.EncoderConfig.EncodeTime = zapcore.TimeEncoderOfLayout("15:04:05.000")
	cfg.EncoderConfig.EncodeCaller = zapcore.ShortCallerEncoder
	cfg.EncoderConfig.ConsoleSeparator = "  "

	// Disable stacktrace for non-error levels (cleaner output)
	cfg.DisableStacktrace = true

	// Set output to stderr (standard for logs)
	cfg.OutputPaths = []string{"stderr"}
	cfg.ErrorOutputPaths = []string{"stderr"}

	// Set level based on flag
	switch level {
	case LevelDebug:
		cfg.Level = zap.NewAtomicLevelAt(zapcore.DebugLevel)
	default:
		cfg.Level = zap.NewAtomicLevelAt(zapcore.ErrorLevel)
	}

	logger, err := cfg.Build()
	if err != nil {
		// Fallback to production logger if build fails
		logger, _ = zap.NewProduction()
	}

	return logger
}

// Nop returns a no-op logger (for testing).
func Nop() *zap.Logger {
	return zap.NewNop()
}

// IsSilent checks if we should suppress all output.
func IsSilent(level Level) bool {
	return level == LevelSilent
}
