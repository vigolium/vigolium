# Vigolium Workbench

Hands-on operator interface for the Vigolium vulnerability scanner. Connects to the Vigolium REST API server to display scan findings, HTTP traffic records, module status, OAST interactions, and server configuration.

## Tech Stack

- **Next.js 15** (App Router, static export via `output: 'export'`)
- **React 19** + **TypeScript**
- **Tailwind CSS 4** (via `@tailwindcss/postcss`)
- **TanStack React Query** for data fetching
- **AG Grid** for data tables
- **Recharts** for charts
- **Lucide React** for icons
- **Bun** as the package manager / runtime

## Getting Started

### Prerequisites

- [Bun](https://bun.sh/) (or Node.js 20+)
- A running Vigolium server (`vigolium server` on port 9002 by default)

### Install & Run

```bash
bun install
bun run dev          # http://localhost:3000
```

If you hit ENOENT errors from a stale `.next` cache (common after `bun run build`):

```bash
bun run dev:clean    # cleans .next then starts dev server
```

### Build for Production

```bash
bun run build        # static export to out/
bun run build:prod   # clean build to dist/
```

The `dist/` (or `out/`) directory can be served by any static file server or embedded into the Vigolium binary.

## Project Structure

```
src/
  app/                  # Next.js App Router pages
    page.tsx            # Dashboard (home)
    findings/           # Findings list
    http-records/       # HTTP traffic records
    oast-interactions/  # OAST interaction log
    modules/            # Scanner modules overview
    config/             # Server configuration
    ingest/             # Traffic ingestion
    scan/               # Scan launcher
  api/                  # API client, types, React Query hooks
  components/shared/    # Shared components (AuthGate, etc.)
  contexts/             # React contexts (ThemeContext)
  designs/
    dark/               # Dark theme components
    light/              # Light theme components
  lib/                  # Utilities, constants, formatters
```

## Configuration

The dashboard connects to the Vigolium API at `http://localhost:9002` by default. Override via:

- **Environment variable**: `NEXT_PUBLIC_API_BASE_URL`
- **Runtime**: The URL and API token can be set in the browser via the config page (stored in `localStorage`)

## Scripts

| Script | Description |
|---|---|
| `bun run dev` | Start dev server with Turbopack |
| `bun run dev:clean` | Clean `.next` cache then start dev server |
| `bun run build` | Static export to `out/` |
| `bun run build:prod` | Clean build, static export to `dist/` |
| `bun run start` | Serve production build (not used with static export) |
| `bun run lint` | Run ESLint |
