package grpc_web_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "grpc-web-detect"
	ModuleName  = "gRPC-Web Detect"
	ModuleShort = "Detects gRPC-Web protocol usage in HTTP traffic"
)

var (
	ModuleDesc = `**What it means:** The application exposes a gRPC-Web endpoint, identified passively from gRPC-Web Content-Type headers (application/grpc-web, +proto, -text) or a grpc-status header. An informational fingerprint that reveals an API protocol generic web testing often overlooks.

**How it's exploited:** Knowing an endpoint speaks gRPC-Web lets an attacker use protocol-aware tooling: enumerating RPC service and method names, fuzzing length-prefixed protobuf messages, and probing each method for missing authorization or business-logic abuse. This mainly accelerates reconnaissance.

**Fix:** Treat gRPC-Web methods as authenticated, authorized API endpoints with input validation and rate limiting, and avoid exposing internal or debug services through the gateway.`

	ModuleConfirmation = "Confirmed when request or response contains gRPC-Web content types or gRPC-specific headers"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"api", "fingerprint", "light"}
)
