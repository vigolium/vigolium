# Vigolium Workbench

Static-export Next.js UI embedded into the Vigolium Go binary. Ships as a fully self-contained dashboard that the Go server serves at `/ui` — no Node.js runtime needed in production.

## Quick start

```bash
bun install
bun run dev      # http://localhost:3002, talks to Go backend at http://localhost:9002
```

## Build

```bash
bun run build    # → dist/
bun run preview  # serve dist/ locally
```

The Go monorepo's `make update-ui` runs the build here and copies `dist/*` into `public/ui/` of the Go binary.

## Test

```bash
bun run test     # vitest unit tests
bun run lint     # next lint
```

## Architecture

- **No server.** `next.config.ts` exports `output: 'export'`. There are no API routes, no middleware, no server actions.
- **Direct API access.** Browser talks to the Go REST API via `NEXT_PUBLIC_API_BASE_URL`. Auth is `AuthGate` (API key or username + access_code) against the Go backend.
- **Project-scoped.** All data is keyed by `project_uuid` (sent as `X-Project-UUID` header). Switching projects invalidates all React Query caches.
- **Dual themes.** `src/designs/{dark,light}/` parallel implementations; runtime swap via `ThemeContext`.

## Tech stack

Next.js 16 · React 19 · TypeScript · TailwindCSS 4 · React Query · ag-grid · Lucide.

## See also

The cloud SaaS console (WorkOS auth, Polar billing, Convex, team management) is a separate repository — it is intentionally not part of this tree, to keep secrets and SaaS infrastructure out of the open-source Go monorepo.
