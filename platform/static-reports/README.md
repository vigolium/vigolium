# Vigolium Report Generator

Self-contained, single-file HTML report generator for Vigolium scan results. Built with React and compiled into one portable HTML file — no server required.

## Tech Stack

- **Bun** — runtime & package manager
- **Vite** + **vite-plugin-singlefile** — builds everything into a single HTML file
- **React 19** — UI rendering
- **Tailwind CSS 4** — styling
- **Recharts** — charts (bar, pie, line)
- **AG Grid** — data table with sorting, filtering, pagination
- **IBM Plex Mono** — typeface

## Quick Start

```bash
# Install dependencies
bun install

# Dev server (hot reload)
bun run dev

# Production build → dist/index.html
bun run build
```

## How It Works

1. Place your JSONL scan data in `data/sample.jsonl`
2. Run `bun run build` — the `prebuild` script embeds the JSONL into `src/data.json`, then Vite compiles everything into a single `dist/index.html`
3. Open the HTML file in any browser

The built report also supports drag-and-drop: users can load a different JSONL file directly in the browser.

## Project Structure

```
static-reports/
├── src/
│   ├── App.tsx              # Main app with summary, charts, data table
│   ├── main.tsx             # React entry point
│   ├── types.ts             # TypeScript types for scan records
│   ├── components/          # UI components (Header, Charts, DataTable, etc.)
│   ├── styles/              # Tailwind config and custom CSS
│   └── utils/               # Data parsing and chart theme
├── scripts/
│   └── embed-data.ts        # JSONL → JSON build script
├── data/
│   └── sample.jsonl         # Input scan data
├── dist/
│   └── report-template.html # Pre-built report
├── index.html               # Vite entry point
├── vite.config.ts
├── tsconfig.json
└── package.json
```

## Input Format

The generator expects JSONL where each line is a JSON object with HTTP request/response data. See `data/sample.jsonl` for the expected schema.
