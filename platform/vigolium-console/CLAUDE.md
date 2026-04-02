# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Vigolium Console is the unified Next.js web frontend for the Vigolium vulnerability scanner. It supports two build modes controlled by the `NEXT_PUBLIC_BUILD_MODE` environment variable:

- **`cloud`** (default) — Full Next.js server with WorkOS authentication, Stripe billing, API proxy, and team management. This is the SaaS/cloud deployment.
- **`static`** — Static export (`next export`) that attaches to the Vigolium Go binary. Uses client-side AuthGate for authentication, talks directly to the Go backend. This is the self-hosted/workbench deployment.

## Development Commands

```bash
# Cloud mode (console)
bun run dev              # Start dev server on port 5002 (reads API key from vigolium config)
bun run dev:noauth       # Start without authentication (sets VIGOLIUM_SKIP_AUTH=true)
bun run dev:clean        # Clear .next cache and start fresh
bun run build            # Production build (cloud)
bun run build:prod       # Clean production build (cloud)
bun run start            # Start production server on port 5002

# Static mode (workbench)
bun run dev:workbench         # Start dev server on port 3002 (static mode, direct to Go backend)
bun run dev:workbench:clean   # Clear .next cache and start fresh (static mode)
bun run build:workbench       # Static export to dist/
bun run preview:workbench     # Serve dist/ locally

bun run lint             # ESLint via next lint
```

**Prerequisites**: For cloud mode, copy `.env.example` to `.env` and configure. The scan server must be running at `VIGOLIUM_SCAN_SERVER` (default `http://localhost:9002`). For local development without WorkOS/Stripe, use `bun run dev:noauth`. For static/workbench mode, only the Go backend is needed.

## Architecture

### Build Mode (`src/lib/buildMode.ts`)

The `NEXT_PUBLIC_BUILD_MODE` env var controls the build mode. Import `isStaticBuild` or `isCloudBuild` from `@/lib/buildMode` to branch behavior at runtime. Key differences:

| Aspect | Static (workbench) | Cloud (console) |
|--------|-------------------|-----------------|
| Output | `next export` (static HTML/CSS/JS) | Full Next.js server |
| Auth | Client-side AuthGate (bearer token) | WorkOS middleware |
| API routing | Browser → Go backend directly | Browser → Next.js proxy → Go backend |
| Navigation | Flat list with modules/extensions/database | Grouped with projects/billing |
| Settings tabs | config, projects, theme, about | profile, team, theme |
| Billing | None | Stripe credits |

### API Proxy Pattern (Cloud Mode)

In cloud mode, browser requests never reach the scan server directly. All API calls flow through a Next.js API route:

```
Browser (React) → /api/proxy/[...path] → Vigolium Scan Server
```

The proxy (`src/app/api/proxy/[...path]/route.ts`) injects the server-side `Authorization` header and performs credit checks on scan-triggering endpoints (returning HTTP 402 if insufficient credits). In skip-auth mode, credits are unlimited.

### Direct Backend Access (Static Mode)

In static mode, the browser communicates directly with the Go backend. The API client includes `Authorization: Bearer` headers from localStorage. The `AuthGate` component (`src/components/shared/AuthGate.tsx`) handles login via API key or username/access_code.

### API Layer (`src/api/`)

- **`client.ts`**: Centralized HTTP client. Branches on `isStaticBuild` for URL construction (direct vs proxy) and auth headers. All requests include `X-Project-UUID` header from localStorage for multi-tenancy.
- **`types.ts`**: TypeScript interfaces mirroring Go backend structs (findings, HTTP records, scans, agent requests, etc.).
- **`hooks.ts`**: 70+ React Query hooks with project-scoped query keys, conditional refetch intervals (e.g., scan status polls every 5s while running), and automatic cache invalidation on mutations.

### Dual-Theme Design System (`src/designs/`)

Every page has two parallel implementations in `dark/` and `light/`. Route pages conditionally render based on theme:

```tsx
const { themeId } = useTheme();
return themeId === 'dark' ? <DarkPage /> : <LightPage />;
```

Color schemes (30+ options) are defined in `src/lib/colorSchemes.ts` and applied as CSS custom properties (`--v-bg`, `--v-accent`, etc.) at runtime.

### Global Contexts (`src/contexts/`)

Three contexts wrap the app in `layout.tsx`:

- **ProjectContext**: Manages active project UUID. Changing projects invalidates all React Query caches.
- **ThemeContext**: Controls dark/light mode and color scheme selection. Persists to localStorage.
- **ToastContext**: App-wide toast notifications with auto-dismiss.

### Authentication

- **Cloud mode**: Uses WorkOS AuthKit (`@workos-inc/authkit-nextjs`). Middleware in `src/middleware.ts` enforces auth on all routes except `/callback` and `/api/billing/webhook`. Setting `VIGOLIUM_SKIP_AUTH=true` bypasses all auth and billing checks.
- **Static mode**: Uses `AuthGate` component wrapping the app in `layout.tsx`. Supports API key and username/access_code login against the Go backend's `/server-info` and `/api/auth/login` endpoints.

### Billing & Team (Cloud Only)

- Credits stored as Stripe customer metadata, mapped via WorkOS organization ID.
- Team management through WorkOS organization memberships.
- GitHub integration via OAuth App for repo access and source cloning.

### Route Structure

Pages use Next.js App Router with `[[...id]]` optional catch-all segments for detail views. Key routes: `/` (dashboard), `/findings`, `/http-records`, `/scan`, `/agentic-scan`, `/scope`, `/config`, `/ingest`, `/modules`, `/extensions`, `/source-repos`, `/database`, `/oast-interactions`, `/settings`.

Cloud-only routes: `/billing`, `/projects`, `/team`, `/login`. These redirect to `/` in static mode.

## Key Patterns

- **Build mode branching**: Use `isStaticBuild`/`isCloudBuild` from `@/lib/buildMode` — never check `process.env.NEXT_PUBLIC_BUILD_MODE` directly in components.
- **Project scoping**: All data is scoped by `project_uuid` — stored in localStorage, sent as header, included in React Query keys.
- **Server-side secrets**: API keys, Stripe keys, WorkOS keys are server-side only (Next.js API routes). Never import `src/lib/stripe.ts`, `src/lib/billing.ts`, or `src/lib/workos-server.ts` from client components.
- **Static export safety**: When adding imports to client components, ensure they don't pull in server-side modules — this will break `build:workbench`.
- **ag-grid**: Used for data-heavy tables (findings, HTTP records, OAST interactions).
- **Recharts**: Used for dashboard charts and statistics.

## Tech Stack

Next.js 16 (App Router, Turbopack dev), React 19, TypeScript 5.9, TailwindCSS 4, React Query 5, ag-grid, Recharts, Lucide React icons, WorkOS AuthKit, Stripe SDK.
