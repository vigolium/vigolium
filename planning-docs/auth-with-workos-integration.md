# Authentication with WorkOS Integration

## Overview

Integrate WorkOS AuthKit for Google OAuth login in the Vigolium dashboard. The Next.js frontend handles the full OAuth flow and session management; the Go backend verifies JWTs statelessly.

## Architecture

```
Browser
  │
  ▼
Next.js (platform/vigolium-dashboard/)
  ├── AuthKit SDK handles login/logout/callback
  ├── Session stored in encrypted HTTP-only cookies
  └── Attaches access token (JWT) to all API calls
        │
        ▼
Go Backend (pkg/server/)
  ├── JWT verification middleware
  ├── Extracts user identity from claims
  └── Enforces authorization
```

## WorkOS Setup

1. Create a WorkOS account at https://workos.com
2. Enable **User Management** and configure **Google OAuth** as a connection
3. Note the following credentials:
   - `WORKOS_API_KEY`
   - `WORKOS_CLIENT_ID`
   - `WORKOS_COOKIE_PASSWORD` (32+ character secret for session encryption)

## Next.js Frontend Implementation

### 1. Install dependencies

```bash
cd platform/vigolium-dashboard
npm install @workos-inc/authkit-nextjs
```

### 2. Environment variables

```env
# .env.local
WORKOS_API_KEY=sk_live_...
WORKOS_CLIENT_ID=client_...
WORKOS_COOKIE_PASSWORD=a-32-char-or-longer-secret-for-cookie-encryption
NEXT_PUBLIC_WORKOS_REDIRECT_URI=http://localhost:3000/callback
```

### 3. Auth callback route

Create `app/callback/route.ts`:

```typescript
import { handleAuth } from "@workos-inc/authkit-nextjs";

export const GET = handleAuth();
```

This handles the OAuth callback from WorkOS and sets the encrypted session cookie.

### 4. Middleware for session management

Create `middleware.ts` at the project root:

```typescript
import { authkitMiddleware } from "@workos-inc/authkit-nextjs";

export default authkitMiddleware();

export const config = {
  // Protect all routes except public ones
  matcher: [
    "/((?!_next/static|_next/image|favicon.ico|public/).*)",
  ],
};
```

### 5. Sign-in / Sign-out buttons

```typescript
import { getSignInUrl, getSignUpUrl, signOut } from "@workos-inc/authkit-nextjs";

// In a server component:
const signInUrl = await getSignInUrl();
const signUpUrl = await getSignUpUrl();

// Sign out (server action):
await signOut();
```

### 6. Getting user session in server components

```typescript
import { withAuth } from "@workos-inc/authkit-nextjs";

export default async function DashboardPage() {
  const { user, accessToken } = await withAuth();

  // user.id, user.email, user.firstName, user.lastName
  // accessToken is the JWT to send to the Go backend
}
```

### 7. Attaching JWT to Go backend API calls

In the API client or fetch wrapper used by the dashboard:

```typescript
import { withAuth } from "@workos-inc/authkit-nextjs";

async function apiClient(endpoint: string, options: RequestInit = {}) {
  const { accessToken } = await withAuth();

  return fetch(`${process.env.VIGOLIUM_API_URL}${endpoint}`, {
    ...options,
    headers: {
      ...options.headers,
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
  });
}
```

## Go Backend Implementation

### 1. JWT verification middleware

The Go backend does not need the WorkOS SDK. It only verifies the JWT signature and extracts claims. WorkOS issues JWTs signed with RS256 — the public key (JWKS) is fetched from WorkOS.

Add a middleware in `pkg/server/`:

```go
package server

import (
    "crypto/rsa"
    "encoding/json"
    "fmt"
    "net/http"
    "strings"
    "sync"
    "time"

    "github.com/gofiber/fiber/v2"
    "github.com/golang-jwt/jwt/v5"
    "github.com/MicahParks/keyfunc/v2"
)

// Dependencies: github.com/golang-jwt/jwt/v5, github.com/MicahParks/keyfunc/v2

type AuthMiddleware struct {
    jwks *keyfunc.JWKS
}

func NewAuthMiddleware(workosClientID string) (*AuthMiddleware, error) {
    // WorkOS JWKS endpoint
    jwksURL := "https://api.workos.com/sso/jwks/" + workosClientID
    jwks, err := keyfunc.Get(jwksURL, keyfunc.Options{
        RefreshInterval: time.Hour,
    })
    if err != nil {
        return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
    }
    return &AuthMiddleware{jwks: jwks}, nil
}

func (a *AuthMiddleware) Handler() fiber.Handler {
    return func(c *fiber.Ctx) error {
        authHeader := c.Get("Authorization")
        if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
            return c.Status(401).JSON(fiber.Map{"error": "missing authorization header"})
        }

        tokenString := strings.TrimPrefix(authHeader, "Bearer ")

        token, err := jwt.Parse(tokenString, a.jwks.Keyfunc,
            jwt.WithValidMethods([]string{"RS256"}),
        )
        if err != nil || !token.Valid {
            return c.Status(401).JSON(fiber.Map{"error": "invalid token"})
        }

        claims, ok := token.Claims.(jwt.MapClaims)
        if !ok {
            return c.Status(401).JSON(fiber.Map{"error": "invalid claims"})
        }

        // Set user info in context for downstream handlers
        c.Locals("user_id", claims["sub"])
        c.Locals("user_email", claims["email"])

        return c.Next()
    }
}
```

### 2. Register middleware on protected routes

In the server setup (e.g., `pkg/server/server.go`):

```go
authMw, err := NewAuthMiddleware(cfg.WorkOSClientID)
if err != nil {
    log.Fatal("auth middleware init failed", zap.Error(err))
}

// Public routes (no auth)
app.Get("/api/health", healthHandler)

// Protected routes
api := app.Group("/api", authMw.Handler())
api.Get("/scans", listScansHandler)
api.Post("/scans", createScanHandler)
// ... other protected endpoints
```

### 3. Configuration

Add to `vigolium-configs.yaml`:

```yaml
server:
  auth:
    enabled: true
    workos_client_id: "client_..."  # or via VIGOLIUM_WORKOS_CLIENT_ID env var
```

## Data Model Considerations

### User association

Once auth is in place, associate data with users:

- Option A: Use the WorkOS `user.id` (from JWT `sub` claim) directly as a foreign key. Simple, no local user table needed.
- Option B: Create a local `users` table that maps WorkOS user IDs to internal user records. More flexible — allows storing preferences, roles, etc.

**Recommendation:** Start with Option A. Add a local users table later if you need roles or user-specific settings.

### Project access control

Currently projects are scoped by `project_uuid`. With auth, you'll want to control which users can access which projects. Options:

- Simple: Single-tenant — all authenticated users see all projects
- Later: Add a `project_members` join table for per-project access control

## Implementation Order

1. **WorkOS account setup** — Create account, enable Google OAuth, get credentials
2. **Next.js AuthKit integration** — Install SDK, add callback route, middleware, sign-in UI
3. **Go JWT middleware** — Add JWKS-based token verification to the Fiber server
4. **Wire up API calls** — Ensure the dashboard sends the JWT on all backend requests
5. **Test end-to-end** — Login → session → API call → verified user in Go handler
6. **Optional: local users table** — If you need roles or user preferences beyond what WorkOS provides

## Notes

- WorkOS free tier covers up to 1M monthly active users
- AuthKit handles the hosted login page — no need to build a custom login UI unless you want to
- The Go backend never touches WorkOS directly — it only validates JWTs, keeping it fully stateless
- For local development, use `http://localhost:3000/callback` as the redirect URI in WorkOS dashboard
