package logger

import (
	"fmt"
	"os"
	"strings"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/buffer"
	"go.uber.org/zap/zapcore"
)

// Level represents log level configuration
type Level int

const (
	// DebugLevel enables verbose debug logging
	DebugLevel Level = iota
	// InfoLevel is the default logging level
	InfoLevel
	// ErrorLevel only logs errors
	ErrorLevel
	// SilentLevel disables all logging
	SilentLevel
)

// Config holds logger configuration.
type Config struct {
	Level   Level
	Verbose bool   // Show caller info when true
	Silent  bool   // Suppress all output
	LogDir  string // Directory for log files (optional)
	LogFile string // Specific log file path (optional)
}

// ANSI color codes
const (
	colorReset   = "\033[0m"
	colorGray    = "\033[90m"
	colorRed     = "\033[31m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorCyan    = "\033[36m"
	colorMagenta = "\033[35m"
	colorBold    = "\033[1m"
	colorHiCyan  = "\033[96m"
)

// colorJSONFields wraps {...} substrings in gray for console display.
func colorJSONFields(s string) string {
	var b strings.Builder
	for {
		idx := strings.Index(s, "{")
		if idx < 0 {
			b.WriteString(s)
			break
		}
		end := strings.Index(s[idx:], "}")
		if end < 0 {
			b.WriteString(s)
			break
		}
		end += idx + 1
		b.WriteString(s[:idx])
		b.WriteString(colorGray)
		b.WriteString(s[idx:end])
		b.WriteString(colorReset)
		s = s[end:]
	}
	return b.String()
}

// ColoredTimeEncoder encodes time as gray ISO 8601 for console output.
func ColoredTimeEncoder(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
	enc.AppendString(colorGray + t.Format("2006-01-02T15:04:05.000Z0700") + colorReset)
}

// PlainTimeEncoder encodes time as plain ISO 8601 for file output.
func PlainTimeEncoder(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
	enc.AppendString(t.Format("2006-01-02T15:04:05.000Z0700"))
}

// ColoredLevelEncoder encodes log levels with bold+color per level.
func ColoredLevelEncoder(level zapcore.Level, enc zapcore.PrimitiveArrayEncoder) {
	var color string
	switch level {
	case zapcore.DebugLevel:
		color = colorBold + colorMagenta
	case zapcore.InfoLevel:
		color = colorBold + colorCyan
	case zapcore.WarnLevel:
		color = colorBold + colorYellow
	case zapcore.ErrorLevel, zapcore.DPanicLevel, zapcore.PanicLevel, zapcore.FatalLevel:
		color = colorBold + colorRed
	default:
		color = colorBold + colorCyan
	}
	enc.AppendString(color + level.CapitalString() + colorReset)
}

// ColoredCallerEncoder encodes the caller path in bright cyan.
func ColoredCallerEncoder(caller zapcore.EntryCaller, enc zapcore.PrimitiveArrayEncoder) {
	enc.AppendString(colorHiCyan + caller.TrimmedPath() + colorReset)
}

// coloredConsoleEncoder wraps a console encoder to add gray coloring to JSON-like structured fields.
type coloredConsoleEncoder struct {
	zapcore.Encoder
}

func (e *coloredConsoleEncoder) EncodeEntry(entry zapcore.Entry, fields []zapcore.Field) (*buffer.Buffer, error) {
	buf, err := e.Encoder.EncodeEntry(entry, fields)
	if err != nil {
		return buf, err
	}
	line := buf.String()
	colored := colorJSONFields(line)
	buf.Reset()
	buf.AppendString(colored)
	return buf, nil
}

func (e *coloredConsoleEncoder) Clone() zapcore.Encoder {
	return &coloredConsoleEncoder{Encoder: e.Encoder.Clone()}
}

// Init initializes the global zap logger from a Config and replaces the global logger.
// Returns the configured logger for deferred Sync().
func Init(cfg Config) *zap.Logger {
	if cfg.Silent {
		cfg.Level = SilentLevel
	}

	if cfg.Level == SilentLevel {
		nop := zap.NewNop()
		zap.ReplaceGlobals(nop)
		return nop
	}

	var zapLevel zapcore.Level
	switch cfg.Level {
	case DebugLevel:
		zapLevel = zapcore.DebugLevel
	case InfoLevel:
		zapLevel = zapcore.InfoLevel
	case ErrorLevel:
		zapLevel = zapcore.ErrorLevel
	default:
		zapLevel = zapcore.InfoLevel
	}

	// Console encoder: colored timestamps, bold+colored levels, space separator
	consoleEncoderCfg := zapcore.EncoderConfig{
		TimeKey:          "ts",
		LevelKey:         "level",
		NameKey:          "logger",
		CallerKey:        "caller",
		MessageKey:       "msg",
		StacktraceKey:    "stacktrace",
		LineEnding:       zapcore.DefaultLineEnding,
		EncodeLevel:      ColoredLevelEncoder,
		EncodeTime:       ColoredTimeEncoder,
		EncodeDuration:   zapcore.StringDurationEncoder,
		EncodeCaller:     ColoredCallerEncoder,
		ConsoleSeparator: " ",
	}

	// Hide caller unless verbose
	if !cfg.Verbose {
		consoleEncoderCfg.CallerKey = ""
	}

	consoleEncoder := &coloredConsoleEncoder{
		Encoder: zapcore.NewConsoleEncoder(consoleEncoderCfg),
	}

	consoleSyncer := zapcore.AddSync(os.Stderr)
	consoleCore := zapcore.NewCore(consoleEncoder, consoleSyncer, zapLevel)

	var cores []zapcore.Core
	cores = append(cores, consoleCore)

	// Optional file output: plain JSON
	logFilePath := cfg.LogFile
	if logFilePath == "" && cfg.LogDir != "" {
		logFilePath = fmt.Sprintf("%s/vigolium-%s.log", cfg.LogDir, time.Now().Format("20060102"))
	}
	if logFilePath != "" {
		if err := os.MkdirAll(dirOf(logFilePath), 0o755); err == nil {
			if f, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
				fileEncoderCfg := zap.NewProductionEncoderConfig()
				fileEncoderCfg.EncodeTime = PlainTimeEncoder
				fileCore := zapcore.NewCore(
					zapcore.NewJSONEncoder(fileEncoderCfg),
					zapcore.AddSync(f),
					zapLevel,
				)
				cores = append(cores, fileCore)
			}
		}
	}

	core := zapcore.NewTee(cores...)

	// Sample high-volume debug/info logs: first 5 of each message per second,
	// then every 100th thereafter. Warn/Error are never sampled.
	if zapLevel <= zapcore.InfoLevel {
		core = zapcore.NewSamplerWithOptions(core,
			time.Second,
			5,
			100,
		)
	}

	opts := []zap.Option{zap.AddCallerSkip(0)}
	if cfg.Verbose {
		opts = append(opts, zap.AddCaller())
	}

	l := zap.New(core, opts...)
	zap.ReplaceGlobals(l)
	return l
}

// InitLevel initializes the logger with just a level (backward compatibility).
func InitLevel(level Level) *zap.Logger {
	return Init(Config{Level: level})
}

// dirOf returns the directory component of a file path.
func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			return path[:i]
		}
	}
	return "."
}
