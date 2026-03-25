import type { Theme } from "./theme";

// --- Light theme (editorial) ---
const LIGHT = {
  charcoal: "#005661",
  charcoalLight: "#003b42",
  terracotta: "#e34e1c",
  olive: "#00b368",
  rose: "#ff5792",
  gold: "#f49725",
  cream: "#f6edda",
  border: "#bbc3c4",
  muted: "#8ca6a6",
} as const;

// --- Dark theme (Brogrammer) ---
const DARK = {
  charcoal: "#fce8c3",
  charcoalLight: "#baa67f",
  terracotta: "#7fd962",
  olive: "#519f50",
  rose: "#ef2f27",
  gold: "#fed06e",
  cream: "#1c1b19",
  border: "#383530",
  muted: "#918175",
} as const;

export function getColors(theme: Theme) {
  return theme === "dark" ? DARK : LIGHT;
}

const SEVERITY_LIGHT: Record<string, string> = {
  critical: "#ff4000",
  high: "#e34e1c",
  medium: "#ff8c00",
  low: "#0094f0",
  info: "#8ca6a6",
};

const SEVERITY_DARK: Record<string, string> = {
  critical: "#f75341",
  high: "#fbb829",
  medium: "#fed06e",
  low: "#68a8e4",
  info: "#918175",
};

export function getSeverityColors(theme: Theme): Record<string, string> {
  return theme === "dark" ? SEVERITY_DARK : SEVERITY_LIGHT;
}

// Default static export (light)
export const SEVERITY_COLORS = SEVERITY_LIGHT;

export function getStatusColors(theme: Theme): Record<string, string> {
  const c = getColors(theme);
  return {
    "2xx": c.olive,
    "3xx": c.gold,
    "4xx": c.terracotta,
    "5xx": c.rose,
  };
}

export function getMethodColors(theme: Theme): Record<string, string> {
  const c = getColors(theme);
  return {
    GET: c.olive,
    POST: c.terracotta,
    PUT: c.gold,
    DELETE: c.rose,
    PATCH: c.charcoalLight,
    HEAD: c.muted,
    OPTIONS: c.muted,
  };
}

export function getChartColors(theme: Theme): string[] {
  const c = getColors(theme);
  return [c.terracotta, c.olive, c.gold, c.rose, c.charcoalLight];
}

export function getConfidenceColors(theme: Theme): Record<string, string> {
  const c = getColors(theme);
  return {
    firm: c.terracotta,
    uncertain: c.gold,
  };
}

// Backward-compat static exports (light theme defaults, used by cell renderers that can't use hooks)
export const EDITORIAL_COLORS = LIGHT;
export const CHART_COLORS = [LIGHT.terracotta, LIGHT.olive, LIGHT.gold, LIGHT.rose, LIGHT.charcoalLight];
export const STATUS_COLORS = getStatusColors("light");
export const METHOD_COLORS = getMethodColors("light");
export const CONFIDENCE_COLORS = getConfidenceColors("light");
