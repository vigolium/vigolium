package grpc_surface_audit

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "grpc-surface-audit"
	ModuleName  = "gRPC-Web Surface Audit"
	ModuleShort = "Audits gRPC-Web (HTTP/1.1) endpoints for missing authorization and exposed reflection/health services"
)

var (
	ModuleDesc = `**What it means:** A gRPC-Web method enforces no authorization: the same call still returns grpc-status 0 with substantive data after the Authorization and Cookie headers are stripped, or server reflection / health services answer anonymous callers.

**How it's exploited:** An attacker replays the length-prefixed request without credentials to read other users' or internal data, and uses reflection or health services to enumerate the RPC surface for further abuse.

**Fix:** Enforce authentication and per-method authorization at the gRPC gateway, deny by default, and disable reflection/health on public deployments.`

	ModuleConfirmation = "Confirmed when an idempotent gRPC-Web method returns grpc-status 0 with substantive, stable data across multiple credential-stripped replays"
	ModuleSeverity     = severity.High
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"grpc", "api", "authorization", "heavy"}
)
