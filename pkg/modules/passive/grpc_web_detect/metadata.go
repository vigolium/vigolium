package grpc_web_detect

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "grpc-web-detect"
	ModuleName  = "gRPC-Web Detect"
	ModuleShort = "Detects gRPC-Web protocol usage in HTTP traffic"
)

var (
	ModuleDesc = `## Description
Passively detects gRPC-Web protocol usage by inspecting request and response
Content-Type headers and gRPC-specific response headers.

## Notes
- Detects gRPC-Web content types (application/grpc-web, application/grpc-web+proto, application/grpc-web-text)
- Checks for grpc-status response header
- Checks for gRPC content types in requests
- Useful for identifying gRPC-Web endpoints for further testing

## References
- https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-WEB.md
- https://grpc.io/docs/platforms/web/`

	ModuleConfirmation = "Confirmed when request or response contains gRPC-Web content types or gRPC-specific headers"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Firm
	ModuleTags = []string{"api", "fingerprint", "light"}
)
