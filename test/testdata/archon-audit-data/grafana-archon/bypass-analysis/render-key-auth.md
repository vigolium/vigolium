# Bypass Analysis: render_key JWT Auth When Renderer Disabled

**Commit**: `85c811ef4b8a541a4e3688d7eef88eec7166224a`
**Component**: Rendering auth (render_key JWT)
**Tag**: [undisclosed]
**Cluster ID**: render-auth-bypass

## Patch Summary

**Pre-patch vulnerability**: When no image renderer was configured (`RendererServerUrl` is empty), the `RenderingService` was still instantiated and its `GetRenderUser` method would accept any correctly HMAC-signed JWT token. The JWT feature flag `renderAuthJWT` is GA with default expression `true`, so the JWT path was active by default. The default signing secret is the literal string `"-"` (`DefaultRendererAuthToken`). This means any attacker who knew the default secret (public in source code) could forge a render_key JWT cookie claiming any OrgID/UserID/OrgRole (including `Admin`) and authenticate against any Grafana instance that had not configured a renderer and had not changed the default token.

**Fix mechanism**:
1. The `renderKeyProvider` is now only instantiated when `cfg.RendererServerUrl != ""`. If no renderer URL is set, `perRequestRenderKeyProvider` remains `nil`.
2. `GetRenderUser` now checks `rs.perRequestRenderKeyProvider == nil` at the top and returns `(nil, false)` immediately, rejecting all render keys.
3. `Render()` and `RenderCSV()` also early-return `ErrRenderUnavailable` when the provider is nil.
4. The `validate()` method was moved from `RenderingService` to each `renderKeyProvider` implementation, eliminating the centralized method that could be reached regardless of renderer state.

## Bypass Verdict: **Sound** (with minor observations)

The core vulnerability -- accepting render_key auth when no renderer is configured -- is properly fixed. The nil-check on `perRequestRenderKeyProvider` is performed before any token parsing occurs, and the provider is only created when `RendererServerUrl` is non-empty.

## Analysis of Bypass Vectors

### 1. Default Secret Still Usable When Renderer IS Configured

**Observation**: The default secret check (`cfg.RendererAuthToken == setting.DefaultRendererAuthToken`) only applies when `FlagRenderAuthJWT` is enabled. In dev mode, the default secret `"-"` is still allowed with just a warning. This means:

- **Production with `renderAuthJWT` enabled (default)**: Default secret `"-"` blocks startup. Sound.
- **Dev mode with `renderAuthJWT` enabled**: Default secret `"-"` is permitted with a warning. Intended behavior for development but noted.
- **Production with `renderAuthJWT` disabled**: Falls through to `perRequestRenderKeyProvider` (cache-based), which does NOT use the `RendererAuthToken` for signing, so the default secret is irrelevant to cache-based key validation. Sound.

No bypass here for the fixed scenario (no renderer configured). When a renderer IS configured, the existing protections for weak secrets remain unchanged and were not part of this vulnerability.

### 2. Alternate Entry Points

The `GetRenderUser` method is the sole entry point for render key validation. It is called only from `pkg/services/authn/clients/render.go:Authenticate()`. The `Render` authn client's `Test()` method checks for the presence of a `renderKey` cookie. There are no other callers of `GetRenderUser` in production code. **No bypass**.

### 3. Render Client Always Enabled

The `Render` authn client's `IsEnabled()` unconditionally returns `true`. This means the authn framework will always try to authenticate requests that have a `renderKey` cookie, even when no renderer is configured. This is fine because `GetRenderUser` now rejects all tokens when the provider is nil. However, it means the `Test()` method will still match and `Authenticate()` will be called -- but authentication will fail. This is a defense-in-depth concern, not a bypass.

### 4. Config-Gated Checks

The fix is NOT gated on a config flag. The nil-check on `perRequestRenderKeyProvider` is unconditional. The provider is only non-nil when `RendererServerUrl` is set. There is no way to bypass this through configuration changes. **No bypass**.

### 5. The `from` Variable Bug (Minor)

After the patch, the `from` variable in `GetRenderUser` is declared but never assigned (it remains `""`). This means the Prometheus metric label `from` will always be empty string. This is a metrics/observability bug, not a security issue.

### 6. Feature Flag Dependency

The `renderAuthJWT` flag is GA with `Expression: "true"`, meaning it defaults to enabled. The distinction between JWT-based and cache-based render key providers only matters when a renderer IS configured. When no renderer is configured, neither provider is created. **No bypass**.

### 7. Race Condition / TOCTOU

The `perRequestRenderKeyProvider` field is set once during `ProvideService()` (DI initialization) and never modified afterward. There is no race condition. **No bypass**.

## Evidence

Key code paths (post-patch):

- **Nil guard in GetRenderUser** (`pkg/services/rendering/auth.go:33-37`): Returns `(nil, false)` when `perRequestRenderKeyProvider` is nil.
- **Provider only created when renderer configured** (`pkg/services/rendering/rendering.go:112-147`): The outer `if cfg.RendererServerUrl != ""` ensures no provider is created for unconfigured renderers.
- **Default secret is `"-"`** (`pkg/setting/setting.go:64`): Hardcoded and publicly known, but now irrelevant when no renderer is configured.
- **Render authn client always enabled** (`pkg/services/authn/clients/render.go:69-71`): `IsEnabled()` returns `true` unconditionally, but `GetRenderUser` now rejects before parsing.

## Residual Risk

When a renderer IS configured and `renderAuthJWT` is enabled in dev mode, the default secret `"-"` is permitted. An attacker with network access to a dev-mode Grafana instance with a renderer configured could forge render tokens. This is pre-existing behavior and not introduced or changed by this patch.
