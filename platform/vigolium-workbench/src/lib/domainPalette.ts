/**
 * Domain palette — fixed-hue tokens for concepts the product talks about
 * constantly: severity, HTTP method, status class, confidence, protocol.
 *
 * These are deliberately NOT swapped by the scheme switcher: analysts build
 * muscle memory around color in log views and scatter plots, so re-binding
 * them would confuse the read.
 *
 * The actual hex values live in :root inside src/app/globals.css under
 * --sev-*, --m-*, --s-*xx, --c-*. The TS values below resolve to those
 * vars, so SVG fills, ag-grid renderers, and React inline styles all
 * point at the same source of truth.
 */

export const SEVERITY_COLORS: Record<string, string> = {
  critical: 'var(--sev-critical)',
  high: 'var(--sev-high)',
  medium: 'var(--sev-medium)',
  low: 'var(--sev-low)',
  suspect: 'var(--sev-suspect)',
  info: 'var(--sev-info)',
};

export const METHOD_COLORS: Record<string, string> = {
  GET: 'var(--m-get)',
  POST: 'var(--m-post)',
  PUT: 'var(--m-put)',
  PATCH: 'var(--m-patch)',
  DELETE: 'var(--m-delete)',
  HEAD: 'var(--m-head)',
  OPTIONS: 'var(--m-options)',
};

export const STATUS_COLORS: Record<string, string> = {
  '2xx': 'var(--s-2xx)',
  '3xx': 'var(--s-3xx)',
  '4xx': 'var(--s-4xx)',
  '5xx': 'var(--s-5xx)',
};

export const CONFIDENCE_COLORS: Record<string, string> = {
  certain: 'var(--c-certain)',
  firm: 'var(--c-firm)',
  tentative: 'var(--c-tentative)',
};

export const PROTOCOL_COLORS: Record<string, string> = {
  dns: 'var(--m-post)',
  http: 'var(--m-put)',
  https: 'var(--m-get)',
  ldap: 'var(--m-options)',
  smtp: 'var(--m-patch)',
  ftp: 'var(--m-options)',
};

export const MODULE_TYPE_COLORS: Record<string, string> = {
  active: 'var(--m-post)',
  passive: 'var(--m-options)',
};

/**
 * Generic chart palette for non-domain categorical data (e.g. top modules,
 * content types). Resolves to the scheme accents so it follows the theme.
 */
export const CHART_COLORS = [
  'var(--v-secondary)',
  'var(--v-success)',
  'var(--v-tertiary)',
  'var(--v-error)',
  'var(--m-patch)',
];

export const AG_GRID_THEME = 'ag-theme-vigolium';
