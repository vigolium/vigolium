Phase: 9
Sequence: 077
Slug: grpc-storage-jwt-absent-exp-bypass
Verdict: VALID
Rationale: The unified storage gRPC service uses grpcutils.NewAuthenticator which delegates to authlib's VerifierBase.Verify(); the same go-jose nil-Expiry bypass applies to gRPC metadata tokens, allowing permanently-valid access tokens without exp to authenticate to Grafana's internal unified storage service.
Severity-Original: MEDIUM
PoC-Status: theoretical
Origin-Finding: security/findings-draft/p7-003-jwt-missing-exp-enforcement.md
Origin-Pattern: AP-003

## Summary

Grafana's unified storage gRPC service at `pkg/storage/unified/sql/service.go:196` uses `grpcutils.NewAuthenticator(ReadGrpcServerConfig(cfg), tracer)` as its gRPC authentication interceptor. This calls `authlib.NewAccessTokenVerifier` and `authlib.NewIDTokenVerifier` via `authn.NewDefaultAuthenticator()` at `authlib/grpcutils/grpc_authenticator.go:38-44`. The same `authlib.VerifierBase.Verify()` code path is used as in the ext_jwt HTTP path (p7-076), which means the same nil-Expiry bypass applies: tokens issued without an `exp` claim decode to `Expiry=nil` in the go-jose `Claims` struct, and go-jose's `ValidateWithLeeway` skips expiry enforcement when `c.Expiry == nil`.

The unified storage service accepts tokens from gRPC metadata (the `Authorization` metadata key via `authn.NewGRPCTokenProvider`). This service manages Grafana's Kubernetes-style resource storage (dashboards, alert rules, etc. in the unified storage backend). A permanently-valid gRPC access token for this service could allow persistent unauthorized read/write access to unified storage resources.

The configuration for this path is at `grpc_server_authentication.signing_keys_url` and `grpc_server_authentication.allowed_audiences`. These are operator-configurable, and in Grafana Cloud deployments, this is used for service-to-service authentication between Grafana components.

## Location

- **Service init**: `pkg/storage/unified/sql/service.go:196` -- `grpcutils.NewAuthenticator(ReadGrpcServerConfig(cfg), tracer)`
- **Config reader**: `pkg/storage/unified/sql/service.go:423-431` -- `ReadGrpcServerConfig` reads `grpc_server_authentication` section
- **Interceptor**: `github.com/grafana/authlib@.../grpcutils/grpc_authenticator.go:28-44` -- `NewAuthenticator` creates authenticator with `VerifierBase`
- **Verification**: `github.com/grafana/authlib@.../authn/verifier.go:88-123` -- `VerifierBase.Verify()` with nil-Expiry bypass
- **Library nil guard**: `github.com/go-jose/go-jose/v4@v4.1.3/jwt/validation.go:116` -- `if c.Expiry != nil && ...`
- **Token extraction**: `github.com/grafana/authlib@.../authn/grpc_provider.go` -- tokens from gRPC metadata

## Attacker Control

The gRPC access token is read from gRPC metadata by `authn.NewGRPCTokenProvider`. To exploit this:
1. Attacker must reach the gRPC service endpoint (typically an internal network port, not public-facing)
2. Attacker must possess a valid access token signed by the JWKS key at `grpc_server_authentication.signing_keys_url`
3. The token must match the `grpc_server_authentication.allowed_audiences` configuration

If an access token without `exp` is obtained (via key compromise, token interception in logging, or issuance error), it remains valid for the gRPC service indefinitely.

Network reachability: The unified storage gRPC service runs on an internal port. In Grafana Cloud deployments, this may be reachable from other internal services. In self-hosted deployments, the gRPC port exposure depends on operator configuration.

## Trust Boundary Crossed

TB2 -- Authentication Gate (gRPC service authentication). The gRPC authentication interceptor is the sole authentication control for unified storage service RPCs. A permanently-valid token bypasses the intended session lifetime for service-to-service authentication.

## Impact

- **Persistent storage access**: A permanent gRPC access token could authenticate to the unified storage service indefinitely, enabling continuous read/write of Grafana resources (dashboards, alert rules, folders) stored in unified storage
- **Service-level persistence**: Service identities authenticated via `authenticateAsService()` have permissions embedded in the token claims; a permanent token maintains those permissions until the signing key is rotated
- **Internal service boundary**: Unlike the HTTP JWT path, this affects a service-to-service boundary that may be considered higher-trust. A permanently-valid token at this boundary could be used for sustained exfiltration or modification of Grafana configuration resources
- **Same underlying code**: The `VerifierBase.Verify()` and go-jose nil-Expiry bypass are identical to p7-076; this variant is distinguished by the gRPC transport and unified storage target service

## Evidence

```go
// pkg/storage/unified/sql/service.go:196
// Unified storage gRPC service -- uses NewAuthenticator with VerifierBase
authn := grpcutils.NewAuthenticator(ReadGrpcServerConfig(cfg), tracer)
```

```go
// pkg/storage/unified/sql/service.go:423-431
// Config reader -- signing_keys_url and allowed_audiences are operator-configurable
func ReadGrpcServerConfig(cfg *setting.Cfg) *grpcutils.AuthenticatorConfig {
    section := cfg.SectionWithEnvOverrides("grpc_server_authentication")
    return &grpcutils.AuthenticatorConfig{
        SigningKeysURL:   section.Key("signing_keys_url").MustString(""),
        AllowedAudiences: section.Key("allowed_audiences").Strings(","),
        AllowInsecure:    cfg.Env == setting.Dev,
    }
}
```

```go
// github.com/grafana/authlib@.../grpcutils/grpc_authenticator.go:28-44
// NewAuthenticator -- uses VerifierBase which has nil-Expiry bypass
auth := authn.NewDefaultAuthenticator(
    authn.NewAccessTokenVerifier(authn.VerifierConfig{AllowedAudiences: cfg.AllowedAudiences}, kr),
    authn.NewIDTokenVerifier(authn.VerifierConfig{}, kr),
)
```

```go
// github.com/grafana/authlib@.../authn/verifier.go:115-120
// Same VerifierBase.Verify as p7-076 -- go-jose nil-Expiry bypass
if err := claims.Validate(jwt.Expected{
    AnyAudience: jwt.Audience(v.cfg.AllowedAudiences),
    Time:        time.Now(),
}); err != nil {
    return nil, mapErr(err)
}
// go-jose: if c.Expiry != nil && ... -- nil Expiry skips check
```

## Reproduction Steps

1. Configure Grafana unified storage with gRPC authentication:
   ```ini
   [grpc_server_authentication]
   signing_keys_url = https://your-jwks-endpoint/.well-known/jwks.json
   allowed_audiences = your-audience
   ```
2. Generate an EC P-256 key pair; serve the public key at the JWKS endpoint
3. Issue an access token (typ: `at+jwt`) WITHOUT an `exp` claim, signed with the private key:
   ```json
   {"sub": "accesspolicy:svc-id", "namespace": "*", "permissions": ["fixed:*:*"], "aud": "your-audience"}
   ```
4. Connect a gRPC client to the unified storage service port
5. Include the token in gRPC metadata: `authorization: Bearer <token>`
6. Issue a `ListResource` or `GetResource` RPC
7. Observe that the request is authenticated and processed
8. Wait any amount of time and repeat -- the token remains valid indefinitely

## Comparison with Related Findings

| Dimension | p7-003 (auth.jwt) | p7-076 (ext_jwt HTTP) | p7-077 (gRPC storage) |
|-----------|-------------------|-----------------------|------------------------|
| Transport | HTTP/REST | HTTP/REST | gRPC |
| Library | go-jose (direct) | authlib -> go-jose | authlib -> go-jose |
| Service | User auth | Service auth (HTTP) | Unified storage (gRPC) |
| Port | HTTP port | HTTP port | Internal gRPC port |
| Config section | auth.jwt | auth.extended_jwt | grpc_server_authentication |
| Network exposure | Public-facing | Internal/Cloud | Internal |
| Exploitability | MEDIUM | MEDIUM (Grafana Cloud) | MEDIUM (internal network) |
