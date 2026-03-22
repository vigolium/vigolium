# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Vigolium Console is the Next.js web frontend for the Vigolium vulnerability scanner. It communicates with the Vigolium scan server (Go backend) through a server-side proxy that handles authentication and credit gating.

## Development Commands

```bash
bun run dev          # Start dev server on port 5002 (reads API key from vigolium config)
bun run dev:noauth   # Start without authentication (sets VIGOLIUM_SKIP_AUTH=true)
bun run dev:clean    # Clear .next cache and start fresh
bun run build        # Production build
bun run lint         # ESLint via next lint
```

**Prerequisites**: Copy `.env.example` to `.env` and configure. The scan server must be running at `VIGOLIUM_SCAN_SERVER` (default `http://localhost:9002`). For local development without WorkOS/Stripe, use `bun run dev:noauth`.

## Architecture

### API Proxy Pattern

Browser requests never reach the scan server directly. All API calls flow through a Next.js API route:

```
Browser (React) → /api/proxy/[...path] → Vigolium Scan Server
```

The proxy (`src/app/api/proxy/[...path]/route.ts`) injects the server-side `Authorization` header and performs credit checks on scan-triggering endpoints (returning HTTP 402 if insufficient credits). In skip-auth mode, credits are unlimited.

### API Layer (`src/api/`)

- **`client.ts`**: Centralized HTTP client. All requests include `X-Project-UUID` header from localStorage for multi-tenancy. In dev, requests go directly to `localhost:9002`; in production, through the proxy.
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

Uses WorkOS AuthKit (`@workos-inc/authkit-nextjs`). Middleware in `src/middleware.ts` enforces auth on all routes except `/callback` and `/api/billing/webhook`. Setting `VIGOLIUM_SKIP_AUTH=true` bypasses all auth and billing checks with a hardcoded admin user.

### Billing & Team

- Credits stored as Stripe customer metadata, mapped via WorkOS organization ID.
- Team management through WorkOS organization memberships.
- GitHub integration via OAuth App for repo access and source cloning.

### Route Structure

Pages use Next.js App Router with `[[...id]]` optional catch-all segments for detail views. Key routes: `/` (dashboard), `/findings`, `/http-records`, `/scan`, `/agents`, `/scope`, `/config`, `/ingest`, `/modules`, `/extensions`, `/source-repos`, `/billing`, `/team`, `/settings`.

## Key Patterns

- **Project scoping**: All data is scoped by `project_uuid` — stored in localStorage, sent as header, included in React Query keys.
- **Server-side secrets**: API keys, Stripe keys, WorkOS keys are server-side only (Next.js API routes). Never import `src/lib/stripe.ts`, `src/lib/billing.ts`, or `src/lib/workos-server.ts` from client components.
- **ag-grid**: Used for data-heavy tables (findings, HTTP records, OAST interactions).
- **Recharts**: Used for dashboard charts and statistics.

## Tech Stack

Next.js 16 (App Router, Turbopack dev), React 19, TypeScript 5.9, TailwindCSS 4, React Query 5, ag-grid, Recharts, Lucide React icons, WorkOS AuthKit, Stripe SDK.
