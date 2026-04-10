package agent

import "github.com/vigolium/vigolium/pkg/agent/backend"

// runResult is a package-local alias for the exported RunResult type.
// This preserves all existing unexported references throughout the package.
type runResult = RunResult

// Package-local alias for the backend SDK config type.
// Preserves unexported references in test files and internal code.
type sdkRunConfig = backend.SDKRunConfig

// Package-local alias for backend function used in tests.
var buildSDKOptions = backend.BuildSDKOptions
