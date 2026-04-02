# Vigolium Console

Unified web frontend for the Vigolium vulnerability scanner. Supports two build modes:

- **Workbench** (static) — Self-hosted UI that attaches to the Vigolium Go binary. Static HTML/CSS/JS export with client-side authentication.
- **Cloud Console** — SaaS deployment with WorkOS authentication, Stripe billing, team management, and API proxy.

## Tech Stack

- **Next.js 16** (App Router, Turbopack)
- **React 19** + **TypeScript 5.9**
- **Tailwind CSS 4** (via `@tailwindcss/postcss`)
- **TanStack React Query** for data fetching
- **AG Grid** for data tables
- **Recharts** for charts
- **Lucide React** for icons
- **Bun** as the package manager / runtime
- **WorkOS AuthKit** + **Stripe** (cloud mode only)

## Getting Started

### Prerequisites

- [Bun](https://bun.sh/) (or Node.js 20+)
- A running Vigolium server (`vigolium server` on port 9002 by default)

### Install

```bash
bun install
```

### Workbench (Static / Self-Hosted)

```bash
bun run dev:workbench          # Dev server on http://localhost:3002
bun run build:workbench        # Static export to dist-workbench/
bun run preview:workbench      # Serve dist-workbench/ locally
```

The `dist-workbench/` directory can be served by any static file server or embedded into the Vigolium binary. Connects directly to the Go backend at `NEXT_PUBLIC_API_BASE_URL` (default `http://localhost:9002`).

### Cloud Console

```bash
bun run dev                    # Dev server on http://localhost:5002 (reads API key from vigolium config)
bun run dev:noauth             # Dev without WorkOS/Stripe auth
bun run build:console          # Production server build
bun run start                  # Start production server on port 5002
```

For cloud mode, copy `.env.example` to `.env` and configure WorkOS, Stripe, and GitHub OAuth credentials.

### Build Both

```bash
bun run build:all              # Build workbench (dist-workbench/) then console (.next/)
```

Both dev servers can run simultaneously — they use separate build directories (`.next` for cloud, `.next-workbench` for static):

```bash
bun run dev                    # Cloud on :5002
bun run dev:workbench          # Workbench on :3002 (in another terminal)
```

## Build Modes

The `NEXT_PUBLIC_BUILD_MODE` environment variable controls the build mode:

| | Workbench (`static`) | Cloud Console (`cloud`, default) |
|---|---|---|
| **Output** | `dist-workbench/` (static HTML/CSS/JS) | `.next/` (Next.js server) |
| **Auth** | Client-side AuthGate (API key / credentials) | WorkOS middleware |
| **API routing** | Browser → Go backend directly | Browser → Next.js proxy → Go backend |
| **Billing** | None | Stripe credits |
| **Team mgmt** | None | WorkOS organizations |
| **Navigation** | Flat list with modules/extensions/database | Grouped with projects/billing |
| **Settings tabs** | Config, Projects, Theme, About | Profile, Team, Theme |

## Project Structure

```
src/
  app/                    # Next.js App Router pages
    api/                  # Server API routes (cloud mode only, *.cloud.ts)
    page.tsx              # Dashboard (home)
    findings/             # Findings list + detail
    http-records/         # HTTP traffic records
    scan/                 # Native scan launcher
    agentic-scan/         # Agentic scan launcher
    oast-interactions/    # OAST interaction log
    modules/              # Scanner modules overview
    extensions/           # JavaScript extensions
    scope/                # Scope configuration
    ingest/               # Traffic ingestion
    source-repos/         # Source repositories
    database/             # Database explorer
    settings/             # Settings (tabs vary by build mode)
    billing/              # Billing (cloud only)
    projects/             # Projects (cloud only)
    login/                # Login page (cloud only)
  api/                    # API client, types, React Query hooks
  components/shared/      # Shared components (AuthGate)
  contexts/               # React contexts (Project, Theme, Toast)
  designs/
    dark/                 # Dark theme page components
    light/                # Light theme page components
  lib/                    # Utilities, constants, formatters, build mode
```

## Configuration

### Workbench Mode

The UI connects to the Vigolium API at `http://localhost:9002` by default. Override via:

- **Environment variable**: `NEXT_PUBLIC_API_BASE_URL`
- **Runtime**: The URL and API token can be set in the browser (stored in `localStorage`)

### Cloud Mode

Server-side environment variables (see `.env.example`):

| Variable | Purpose |
|---|---|
| `VIGOLIUM_SCAN_SERVER` | Go backend URL (default `http://localhost:9002`) |
| `VIGOLIUM_AUTH_API_KEY` | Bearer token for scan server |
| `VIGOLIUM_SKIP_AUTH` | Set `true` to bypass auth/billing in dev |
| `WORKOS_API_KEY` | WorkOS API key |
| `WORKOS_CLIENT_ID` | WorkOS client ID |
| `WORKOS_COOKIE_PASSWORD` | Session cookie encryption (32+ chars) |
| `STRIPE_SECRET_KEY` | Stripe API key |
| `STRIPE_WEBHOOK_SECRET` | Stripe webhook signing secret |
| `GITHUB_CLIENT_ID` | GitHub OAuth app client ID |
| `GITHUB_CLIENT_SECRET` | GitHub OAuth app secret |

## Scripts

| Script | Description |
|---|---|
| `bun run dev` | Cloud mode dev server on :5002 |
| `bun run dev:noauth` | Cloud mode without auth |
| `bun run dev:clean` | Clean `.next` cache then start cloud dev |
| `bun run dev:workbench` | Workbench dev server on :3002 |
| `bun run dev:workbench:clean` | Clean `.next-workbench` cache then start workbench dev |
| `bun run build` | Cloud production build |
| `bun run build:prod` | Clean cloud production build |
| `bun run build:console` | Cloud production build (alias) |
| `bun run build:workbench` | Static export to `dist-workbench/` |
| `bun run build:all` | Build workbench then console |
| `bun run preview:workbench` | Serve `dist-workbench/` locally |
| `bun run start` | Start cloud production server on :5002 |
| `bun run lint` | Run ESLint |

## Architecture Notes

- **Dual theme system**: Every page has parallel implementations in `designs/dark/` and `designs/light/`. Color schemes (30+) are applied as CSS custom properties at runtime.
- **API routes**: Server-only route handlers use the `.cloud.ts` extension and are automatically excluded from static exports via `pageExtensions` in `next.config.ts`.
- **Build mode helper**: Import `isStaticBuild` / `isCloudBuild` from `@/lib/buildMode` to branch behavior — never check the env var directly in components.
- **Separate build dirs**: Workbench uses `.next-workbench/`, cloud uses `.next/` — both dev servers can run simultaneously.
