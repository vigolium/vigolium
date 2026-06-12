package grpc_web_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "grpc-web-detect"
	ModuleName  = "gRPC-Web Detect"
	ModuleShort = "Detects gRPC-Web protocol usage in HTTP traffic"
)

var (
	ModuleDesc = `**What it means:** The application exposes a gRPC-Web endpoint, identified passively from gRPC-Web Content-Type headers (application/grpc-web, application/grpc-web+proto, application/grpc-web-text) or a grpc-status response header. This is an informational fingerprint, not a vulnerability on its own, but it reveals an API protocol and an attack surface that generic web and REST testing often overlook.

**How it's exploited:** Knowing an endpoint speaks gRPC-Web lets an attacker target it with protocol-aware tooling: enumerating RPC service and method names, replaying or fuzzing length-prefixed protobuf messages, and probing each method for missing authorization, input-validation flaws, or business-logic abuse. The disclosure mainly accelerates reconnaissance and focuses follow-up attacks rather than directly compromising the system.

**Fix:** Treat gRPC-Web methods as authenticated, authorized API endpoints with strict input validation and rate limiting, and avoid exposing internal or debug services through the gRPC-Web gateway.`

	ModuleConfirmation = "Confirmed when request or response contains gRPC-Web content types or gRPC-specific headers"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"api", "fingerprint", "light"}
)
