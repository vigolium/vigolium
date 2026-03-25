# GitHub Connect — Next.js Dashboard Integration

## Overview

Move GitHub OAuth integration from the Go backend to the Next.js dashboard (`platform/vigolium-dashboard/`). All GitHub secrets (Client ID, Client Secret) and OAuth tokens live in the dashboard's database. The Go scanner receives only an ephemeral token-injected clone URL per scan request — it never stores GitHub credentials.

This aligns with the SaaS architecture where the dashboard is the control plane (WorkOS auth, Stripe billing, GitHub connect) and the Go scanner is a stateless scanning engine.

## Prerequisites

- **WorkOS auth implemented** (see `auth-with-workos-integration.md`) — need authenticated users
- **Dashboard is server-rendered** — not static export (required for server actions, API routes)
- **Dashboard database set up** (see `stripe-payment-integration.md`) — Prisma + PostgreSQL

## Architecture

```
User Browser
  │
  ▼
Next.js Dashboard (server-rendered)
  ├── WorkOS Auth (user identity)
  ├── GitHub OAuth (server actions)
  │     ├── OAuth flow (redirect → GitHub → callback)
  │     ├── Token storage (dashboard Postgres DB)
  │     ├── Repo listing & branch listing (proxy GitHub API)
  │     └── Clone trigger → sends token-injected URL to Go
  │
  └── Scan request with source ──────────────────────►  Go Scanner
        {                                                  ├── Receives clone URL
          "clone_url": "https://x-access-token:           ├── Clones to temp dir
              ghp_xxx@github.com/org/repo.git",           ├── Runs scan
          "source_label": "github.com/org/repo"           ├── Returns results
        }                                                  └── No token stored

Go Scanner (zero GitHub secrets)
  ├── pkg/gitutil/clone.go (already exists, kept as-is)
  ├── Accepts token-injected clone URLs in scan requests
  ├── Clones repo ephemerally for the scan
  └── Never persists GitHub tokens
```

### Why move to Next.js?

1. **Zero secrets in Go** — The scanner deploys to customer-premise, CI runners, and environments where OAuth secrets should not exist
2. **Single secret store** — WorkOS, Stripe, and GitHub credentials all live in one place (dashboard env vars + DB)
3. **Consistent auth model** — GitHub connection is tied to WorkOS user identity, not Go's simple auth
4. **SaaS control plane** — The dashboard manages all user-facing integrations

### How the Go scanner stays uninvolved

The dashboard sends a **token-injected clone URL** in the scan/agent request body. The Go scanner's existing `pkg/gitutil/clone.go` already handles these URLs — it clones, scans, and the token is never persisted. This is the same mechanism that was used before, but now the token comes from the dashboard instead of Go's DB.

For agent API requests, the existing `source` field carries the clone URL or local path. No Go API changes needed.

## GitHub OAuth App Setup

1. Go to https://github.com/settings/developers → **OAuth Apps** → **New OAuth App**
2. Set:
   - **Application name**: `Vigolium`
   - **Homepage URL**: `https://your-dashboard-domain.com`
   - **Authorization callback URL**: `https://your-dashboard-domain.com/api/github/callback`
3. Note the **Client ID** and generate a **Client Secret**
4. For local development: register a separate OAuth App with `http://localhost:3000/api/github/callback`

## Database Schema

Add to the existing Prisma schema (from `stripe-payment-integration.md`):

```prisma
// GitHub OAuth connections — one per user
model GitHubConnection {
  id           String   @id @default(cuid())
  userId       String   @unique @map("user_id")  // WorkOS user ID
  githubUserId Int      @map("github_user_id")
  githubLogin  String   @map("github_login")
  accessToken  String   @map("access_token")      // encrypted at rest
  scopes       String   @default("repo,read:user")
  createdAt    DateTime @default(now()) @map("created_at")
  updatedAt    DateTime @updatedAt @map("updated_at")

  user User @relation(fields: [userId], references: [id])

  @@map("github_connections")
}
```

Update the `User` model to add the relation:

```prisma
model User {
  // ... existing fields from stripe plan ...
  githubConnection GitHubConnection?
}
```

Note: Removed `project_uuid` scoping — in the SaaS model, a GitHub connection belongs to a user, not a project. All projects under a user can access their connected repos.

## Environment Variables

```env
# .env.local
GITHUB_CLIENT_ID=Ov23li...
GITHUB_CLIENT_SECRET=secret_...
```

No `NEXT_PUBLIC_` prefix — these are server-side only.

## Next.js Implementation

### 1. GitHub OAuth Library

Create `src/lib/github.ts`:

```typescript
const GITHUB_API = "https://api.github.com";
const GITHUB_OAUTH = "https://github.com/login/oauth";

export function getAuthorizeURL(state: string): string {
  const params = new URLSearchParams({
    client_id: process.env.GITHUB_CLIENT_ID!,
    redirect_uri: `${process.env.NEXT_PUBLIC_APP_URL}/api/github/callback`,
    scope: "repo,read:user",
    state,
  });
  return `${GITHUB_OAUTH}/authorize?${params}`;
}

export async function exchangeCode(code: string): Promise<string> {
  const res = await fetch(`${GITHUB_OAUTH}/access_token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify({
      client_id: process.env.GITHUB_CLIENT_ID,
      client_secret: process.env.GITHUB_CLIENT_SECRET,
      code,
    }),
  });
  const data = await res.json();
  if (data.error) throw new Error(data.error_description || data.error);
  return data.access_token;
}

export async function getGitHubUser(token: string) {
  const res = await fetch(`${GITHUB_API}/user`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error("Failed to fetch GitHub user");
  return res.json() as Promise<{ id: number; login: string }>;
}

export async function listRepos(token: string, page = 1, perPage = 30, query?: string) {
  const url = query
    ? `${GITHUB_API}/search/repositories?q=${encodeURIComponent(query)}+user:@me&per_page=${perPage}&page=${page}`
    : `${GITHUB_API}/user/repos?sort=updated&per_page=${perPage}&page=${page}`;
  const res = await fetch(url, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error("Failed to list repos");
  const data = await res.json();
  return query ? data.items : data;
}

export async function listBranches(token: string, owner: string, repo: string) {
  const res = await fetch(`${GITHUB_API}/repos/${owner}/${repo}/branches`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error("Failed to list branches");
  return res.json();
}

// Inject token into clone URL for private repo access
export function tokenizeCloneURL(cloneURL: string, token: string): string {
  return cloneURL.replace("https://", `https://x-access-token:${token}@`);
}
```

### 2. OAuth Callback — Route Handler

Create `src/app/api/github/callback/route.ts`:

```typescript
import { NextRequest, NextResponse } from "next/server";
import { withAuth } from "@workos-inc/authkit-nextjs";
import { exchangeCode, getGitHubUser } from "@/lib/github";
import { prisma } from "@/lib/prisma";
import { cookies } from "next/headers";

export async function GET(req: NextRequest) {
  const code = req.nextUrl.searchParams.get("code");
  const state = req.nextUrl.searchParams.get("state");

  if (!code || !state) {
    return NextResponse.json({ error: "Missing code or state" }, { status: 400 });
  }

  // Validate state from cookie
  const cookieStore = await cookies();
  const storedState = cookieStore.get("github_oauth_state")?.value;
  if (state !== storedState) {
    return NextResponse.json({ error: "Invalid state" }, { status: 400 });
  }
  cookieStore.delete("github_oauth_state");

  // Get authenticated user
  const { user } = await withAuth({ ensureSignedIn: true });

  // Exchange code for token
  const accessToken = await exchangeCode(code);
  const ghUser = await getGitHubUser(accessToken);

  // Upsert GitHub connection
  await prisma.gitHubConnection.upsert({
    where: { userId: user.id },
    create: {
      userId: user.id,
      githubUserId: ghUser.id,
      githubLogin: ghUser.login,
      accessToken,
    },
    update: {
      githubUserId: ghUser.id,
      githubLogin: ghUser.login,
      accessToken,
    },
  });

  // Redirect back to dashboard (close popup or redirect)
  return NextResponse.redirect(new URL("/settings?github=connected", req.url));
}
```

### 3. Server Actions

Create `src/app/actions/github.ts`:

```typescript
"use server";

import { withAuth } from "@workos-inc/authkit-nextjs";
import { prisma } from "@/lib/prisma";
import {
  getAuthorizeURL,
  listRepos,
  listBranches,
  tokenizeCloneURL,
} from "@/lib/github";
import { cookies } from "next/headers";
import { randomBytes } from "crypto";

export async function getGitHubAuthURL(): Promise<string> {
  await withAuth({ ensureSignedIn: true });
  const state = randomBytes(16).toString("hex");

  // Store state in cookie for CSRF validation
  const cookieStore = await cookies();
  cookieStore.set("github_oauth_state", state, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    maxAge: 600, // 10 minutes
    sameSite: "lax",
  });

  return getAuthorizeURL(state);
}

export async function getGitHubStatus() {
  const { user } = await withAuth({ ensureSignedIn: true });
  const conn = await prisma.gitHubConnection.findUnique({
    where: { userId: user.id },
  });
  return {
    connected: !!conn,
    githubLogin: conn?.githubLogin ?? null,
    connectedAt: conn?.createdAt.toISOString() ?? null,
  };
}

export async function disconnectGitHub() {
  const { user } = await withAuth({ ensureSignedIn: true });
  await prisma.gitHubConnection.delete({
    where: { userId: user.id },
  });
  return { disconnected: true };
}

export async function fetchGitHubRepos(page = 1, query?: string) {
  const { user } = await withAuth({ ensureSignedIn: true });
  const conn = await prisma.gitHubConnection.findUnique({
    where: { userId: user.id },
  });
  if (!conn) throw new Error("GitHub not connected");
  return listRepos(conn.accessToken, page, 30, query);
}

export async function fetchGitHubBranches(owner: string, repo: string) {
  const { user } = await withAuth({ ensureSignedIn: true });
  const conn = await prisma.gitHubConnection.findUnique({
    where: { userId: user.id },
  });
  if (!conn) throw new Error("GitHub not connected");
  return listBranches(conn.accessToken, owner, repo);
}

// Returns a token-injected clone URL for the Go scanner
export async function getCloneURL(cloneURL: string): Promise<string> {
  const { user } = await withAuth({ ensureSignedIn: true });
  const conn = await prisma.gitHubConnection.findUnique({
    where: { userId: user.id },
  });
  if (!conn) throw new Error("GitHub not connected");
  return tokenizeCloneURL(cloneURL, conn.accessToken);
}
```

### 4. Scan Integration

Update the `startScan` server action (from Stripe plan) to handle GitHub repos:

```typescript
// src/app/actions/scan.ts
"use server";

import { deductCredit } from "./credits";
import { getCloneURL } from "./github";
import { withAuth } from "@workos-inc/authkit-nextjs";

export async function startAgentScan(config: {
  mode: "swarm" | "pipeline" | "autopilot";
  target: string;
  source?: { cloneURL: string; branch?: string; label?: string };
  // ... other scan config
}) {
  const { accessToken } = await withAuth({ ensureSignedIn: true });

  // 1. Deduct credit
  const scanUuid = crypto.randomUUID();
  const ok = await deductCredit(scanUuid);
  if (!ok) return { error: "Insufficient credits" };

  // 2. Build source URL with token if GitHub repo
  let source: string | undefined;
  if (config.source?.cloneURL) {
    source = await getCloneURL(config.source.cloneURL);
    // Token-injected URL like: https://x-access-token:ghp_xxx@github.com/org/repo.git
  }

  // 3. Send to Go scanner API
  const res = await fetch(`${process.env.VIGOLIUM_API_URL}/api/agent/run/${config.mode}`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      target: config.target,
      source,  // Go scanner clones this URL, never stores the token
      source_label: config.source?.label,
    }),
  });

  if (!res.ok) {
    // TODO: refund credit on failure
    return { error: "Failed to start scan" };
  }

  return { success: true, scanUuid };
}
```

### 5. Frontend Components

Reuse the existing component patterns from `GitHubConnect.tsx` and `RepoBrowserModal.tsx`, but rewire them to call server actions instead of Go API endpoints:

**GitHubConnect component:**
- "Connect GitHub" → calls `getGitHubAuthURL()` server action → opens popup
- Status display → calls `getGitHubStatus()` server action
- "Disconnect" → calls `disconnectGitHub()` server action

**RepoBrowserModal component:**
- Repo list → calls `fetchGitHubRepos()` server action
- Branch list → calls `fetchGitHubBranches()` server action
- "Select" → returns `clone_url` + `branch` to parent form (no clone yet — cloning happens at scan time)

**Key change from current implementation:** No "Clone & Select" step in the modal. Instead, the modal just returns the selected repo's `clone_url` and branch. Cloning happens when the scan starts — the dashboard calls `getCloneURL()` to inject the token, then sends it to Go. This avoids premature cloning and disk usage.

## What Changes in Go

### Removed (all GitHub secrets and OAuth logic)

| File | Action |
|------|--------|
| `pkg/server/github.go` | **Delete** — GitHubService, OAuth, API proxy |
| `pkg/server/handlers_github.go` | **Delete** — All GitHub HTTP handlers |
| `internal/config/github.go` | **Delete** — GitHubConfig struct |
| `pkg/server/routes.go` | **Remove** GitHub route registrations |
| `pkg/database/models.go` | **Remove** GitHubConnection model |
| `pkg/database/repository.go` | **Remove** GitHub CRUD methods |
| `pkg/database/db.go` | **Remove** github_connections table DDL |
| `internal/config/loader.go` | **Remove** GitHub field from Settings struct |

### Kept (generic git utilities)

| File | Status |
|------|--------|
| `pkg/gitutil/clone.go` | **Keep** — Generic git cloning, used by scanner for token-injected URLs |

### No changes needed

The Go scanner already accepts token-injected clone URLs via the `source` field in agent API requests. The `pkg/gitutil/clone.go` handles `https://x-access-token:TOKEN@github.com/...` URLs. No Go API changes required.

## Implementation Order

1. **Prisma schema** — Add `GitHubConnection` model, run migration
2. **GitHub OAuth library** — `src/lib/github.ts`
3. **OAuth callback route** — `src/app/api/github/callback/route.ts`
4. **Server actions** — `src/app/actions/github.ts`
5. **Rewire frontend components** — Update `GitHubConnect.tsx` and `RepoBrowserModal.tsx` to use server actions
6. **Wire into scan flow** — `startAgentScan()` injects token into clone URL
7. **Remove Go GitHub code** — Delete files and clean up references
8. **Test end-to-end** — Connect GitHub → browse repos → select → scan with source

## Security Considerations

- **GitHub tokens stored in dashboard DB only** — encrypted at rest (Prisma field-level encryption or DB-level)
- **Tokens never sent to Go for storage** — only injected into clone URLs per-request
- **Clone URLs with tokens are in-flight only** — Go clones and discards, never persists to DB
- **OAuth state validated via httpOnly cookie** — CSRF protection
- **All GitHub API calls server-side** — tokens never exposed to browser
- **Scope minimization** — `repo,read:user` is the default; can narrow to `public_repo` if only public repos needed
