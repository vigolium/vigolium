export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'suspect', 'info'] as const;
export type Severity = (typeof SEVERITY_ORDER)[number];

export const SEVERITY_COLORS: Record<string, string> = {
  critical: '#E53935',
  high: '#EF5350',
  medium: '#FFA726',
  low: '#FFD54F',
  suspect: '#AB47BC',
  info: '#42A5F5',
};

export const SEVERITY_HOVER_COLORS: Record<string, string> = {
  critical: '#C62828',
  high: '#D32F2F',
  medium: '#FB8C00',
  low: '#FFB300',
  suspect: '#8E24AA',
  info: '#1E88E5',
};

export const METHOD_COLORS: Record<string, string> = {
  GET: '#22c55e',
  POST: '#3b82f6',
  PUT: '#f59e0b',
  PATCH: '#8b5cf6',
  DELETE: '#ef4444',
  HEAD: '#6b7280',
  OPTIONS: '#06b6d4',
};

export const CONFIDENCE_COLORS: Record<string, string> = {
  certain: '#22c55e',
  firm: '#3b82f6',
  tentative: '#f59e0b',
};

export const STATUS_COLORS: Record<string, string> = {
  '2xx': '#22c55e',
  '3xx': '#06b6d4',
  '4xx': '#f59e0b',
  '5xx': '#ef4444',
};

export function statusColorCategory(code: number): string {
  const cat = `${Math.floor(code / 100)}xx`;
  return STATUS_COLORS[cat] || '#6b7280';
}
