export const EDITORIAL_COLORS = {
  cream: '#f6edda',
  creamDark: '#ede4d1',
  charcoal: '#005661',
  charcoalLight: '#004d57',
  accent: '#0078c8',
  green: '#00b368',
  red: '#e34e1c',
  gold: '#f49725',
  magenta: '#ff5792',
  border: '#bbc3c4',
  borderLight: '#d4e8e2',
  muted: '#708e8e',
} as const;

export const SEVERITY_COLORS: Record<string, string> = {
  critical: '#E53935',
  high: '#EF5350',
  medium: '#FFA726',
  low: '#FFD54F',
  suspect: '#AB47BC',
  info: '#42A5F5',
};

export const METHOD_COLORS: Record<string, string> = {
  GET: '#00b368',
  POST: '#0078c8',
  PUT: '#f49725',
  PATCH: '#004d57',
  DELETE: '#e34e1c',
  HEAD: '#708e8e',
  OPTIONS: '#00b368',
};

export const STATUS_COLORS: Record<string, string> = {
  '2xx': '#00b368',
  '3xx': '#f49725',
  '4xx': '#e34e1c',
  '5xx': '#ff5792',
};

export const CONFIDENCE_COLORS: Record<string, string> = {
  certain: '#00b368',
  firm: '#005661',
  tentative: '#f49725',
};

export const PROTOCOL_COLORS: Record<string, string> = {
  dns: '#0078c8', http: '#00b368', https: '#f49725',
  ldap: '#ff5792', smtp: '#e34e1c', ftp: '#00bdd6',
};

export const CHART_COLORS = ['#0078c8', '#00b368', '#f49725', '#e34e1c', '#ff5792'];

export const MODULE_TYPE_COLORS: Record<string, string> = {
  active: '#0078c8',
  passive: '#005661',
};

export const AG_GRID_THEME = 'ag-theme-light';
