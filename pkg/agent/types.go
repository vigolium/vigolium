package agent

import "github.com/vigolium/vigolium/pkg/agent/backend"

// runResult is a package-local alias for the exported RunResult type.
// This preserves all existing unexported references throughout the package.
type runResult = RunResult

// Package-local aliases for backend config types.
// These preserve unexported references in test files and internal code.
type (
	sdkRunConfig      = backend.SDKRunConfig
	codexRunConfig    = backend.CodexRunConfig
	opencodeRunConfig = backend.OpenCodeRunConfig
)

// Package-local alias for backend function used in tests.
var buildSDKOptions = backend.BuildSDKOptions
