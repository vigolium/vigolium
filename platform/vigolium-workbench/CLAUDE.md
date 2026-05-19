# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Vigolium Workbench is the static-export Next.js UI that ships embedded inside the Vigolium Go binary. It talks directly to the Go backend over the REST API; there is no Next.js server, no proxy layer, no SaaS/billing/auth-provider integration.

The cloud SaaS console lives in a separate, private repository and is not built from this tree.

## Development Commands

```bash
bun install              # First-time setup
bun run dev              # Dev server on port 3002, points at Go backend at http://localhost:9002
bun run dev:clean        # Clear dist/ and start fresh
bun run build            # Static export → dist/
bun run preview          # Serve dist/ locally
bun run lint             # ESLint via next lint
bun run test             # Vitest unit tests
```

The Go monorepo's `make update-ui` runs `bun run build` here and copies `dist/*` into `public/ui/` of the Go binary, so the dashboard is served by the Go server with no Node.js dependency at runtime.

## Architecture

### Build target

- `next.config.ts` is locked to `output: 'export'`, `distDir: 'dist'`, `trailingSlash: true` — produces a fully static HTML/CSS/JS bundle.
- No API routes, no middleware, no server actions. Anything that needed those lives in the cloud-console repo.

### Runtime API access

The browser talks directly to the Go scan server. The base URL comes from `NEXT_PUBLIC_API_BASE_URL` (set in dev to `http://localhost:9002`; in production the static bundle is served from the same origin as the API and uses relative URLs).

`src/api/client.ts` injects `Authorization: Bearer <token>` from localStorage and `X-Project-UUID` from `ProjectContext`. Auth is handled by `src/components/shared/AuthGate.tsx` (API key or username + access_code against the Go backend's `/server-info` and `/api/auth/login`).

### Build mode constants

`src/lib/buildMode.ts` exports `BUILD_MODE = 'static'`, `isStaticBuild = true`, `isCloudBuild = false`. Cloud branches that originated from the unified codebase are dead-stripped at build time. New code should not branch on these.

### Dual-theme design system

Every page has parallel `dark/` and `light/` implementations under `src/designs/`. Route pages render conditionally based on `useTheme().themeId`. Color schemes live in `src/lib/colorSchemes.ts` and apply as CSS custom properties.

### Global contexts

`src/contexts/`:
- `ProjectContext` — active project UUID, sent as `X-Project-UUID` header on every API call. Changing project invalidates all React Query caches.
- `ThemeContext` — dark/light + color scheme.
- `ToastContext` — app-wide notifications.

### Routes

App Router, `[[...id]]` optional catch-alls for detail views:
`/`, `/findings`, `/http-records`, `/scan`, `/agentic-scan`, `/scope`, `/config`, `/ingest`, `/modules`, `/extensions`, `/database`, `/oast-interactions`, `/settings`, `/unauthorized`.

## Tech Stack

Next.js 16 (App Router, Turbopack dev), React 19, TypeScript 5.9, TailwindCSS 4, React Query 5, ag-grid, Lucide React icons.

## Key patterns

- **Project scoping**: All data scoped by `project_uuid`. Mutations that invalidate project-scoped queries must use the `projectKey(...)` helper, not bare `['scans']` etc., or invalidation silently no-ops.
- **No server-side imports**: Anything under `src/lib/` that originated as a Next.js server-only module has been removed. If you find yourself reaching for `next/server`, you're solving a cloud-console problem in the wrong repo.
- **ag-grid**: Used for data-heavy tables (findings, HTTP records, OAST interactions).

## Relationship to the Go monorepo

This package lives at `platform/vigolium-workbench/` inside the main `vigolium` Go repo. The Go binary embeds the build output via `public/ui/`. To refresh the embedded UI after editing here:

```bash
make update-ui   # from repo root
```

That target runs `bun run build` here and copies `dist/*` → `public/ui/`.
