package agent

import (
	"io"
	"os"
	"path/filepath"
	"strings"

	"go.uber.org/zap"
)

// thinkingSink writes the model's reasoning deltas to a per-template file
// under the session directory. Discards content when no session dir is set
// (which is the common case for one-off CLI runs).
//
// File naming: thinking-<template>.md, append mode so retries within a
// single run accumulate. PromptTemplate is sanitized to a safe filename
// (slashes / spaces → "-").
type thinkingSink struct {
	f *os.File
}

// openThinkingSink returns a sink writing to the appropriate file, or a
// nil-receiver sink that discards everything when no session dir is set.
func openThinkingSink(opts Options) *thinkingSink {
	if opts.SessionDir == "" {
		return nil
	}
	tmpl := opts.PromptTemplate
	if tmpl == "" {
		tmpl = "inline"
	}
	// Defensive: prevent directory traversal via template name.
	safe := strings.NewReplacer("/", "-", "\\", "-", "..", "-", " ", "-").Replace(tmpl)
	path := filepath.Join(opts.SessionDir, "thinking-"+safe+".md")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		zap.L().Debug("thinking sink open failed; reasoning will be discarded",
			zap.String("path", path),
			zap.Error(err))
		return nil
	}
	return &thinkingSink{f: f}
}

// writer returns the underlying io.Writer or nil when the sink is disabled.
// Callers pass this directly to runOliumOnEngineWithThinking; that function
// already nil-checks before each Write.
func (s *thinkingSink) writer() io.Writer {
	if s == nil || s.f == nil {
		return nil
	}
	return s.f
}

func (s *thinkingSink) close() {
	if s == nil || s.f == nil {
		return
	}
	_ = s.f.Close()
}
