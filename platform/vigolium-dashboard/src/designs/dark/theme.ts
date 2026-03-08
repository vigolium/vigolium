export const SEVERITY_COLORS: Record<string, string> = {
  critical: '#E53935',
  high: '#EF5350',
  medium: '#FFA726',
  low: '#FFD54F',
  suspect: '#AB47BC',
  info: '#42A5F5',
};

export const METHOD_COLORS: Record<string, string> = {
  GET: '#98bc37',
  POST: '#68a8e4',
  PUT: '#7fd962',
  PATCH: '#ff5c8f',
  DELETE: '#ef2f27',
  HEAD: '#918175',
  OPTIONS: '#0aaeb3',
};

export const STATUS_COLORS: Record<string, string> = {
  '2xx': '#98bc37',
  '3xx': '#2be4d0',
  '4xx': '#7fd962',
  '5xx': '#ef2f27',
};

export const CONFIDENCE_COLORS: Record<string, string> = {
  certain: '#98bc37',
  firm: '#68a8e4',
  tentative: '#7fd962',
};

export const PROTOCOL_COLORS: Record<string, string> = {
  dns: '#68a8e4', http: '#7fd962', https: '#98bc37',
  ldap: '#2be4d0', smtp: '#ff5c8f', ftp: '#0aaeb3',
};

export const CHART_COLORS = ['#0094f0', '#00b368', '#f49725', '#e34e1c', '#ff5792'];

export const MODULE_TYPE_COLORS: Record<string, string> = {
  active: '#68a8e4',
  passive: '#2be4d0',
};

export const AG_GRID_THEME = 'ag-theme-dark';
