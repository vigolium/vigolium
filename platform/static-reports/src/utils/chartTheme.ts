import type { Theme } from "./theme";

// --- Light theme (Blueprint Graphite) ---
const LIGHT = {
  charcoal: "#1a1a1a",
  charcoalLight: "#559e38",
  terracotta: "#a86a14",
  olive: "#406a30",
  rose: "#a82820",
  gold: "#d39220",
  cream: "#ece9df",
  border: "#c8c4b8",
  muted: "#6a6862",
} as const;

// --- Dark theme (Blueprint Graphite Dark) ---
const DARK = {
  charcoal: "#ece8db",
  charcoalLight: "#559e38",
  terracotta: "#d68a30",
  olive: "#88c068",
  rose: "#e85a48",
  gold: "#e8a050",
  cream: "#131210",
  border: "#34302a",
  muted: "#93887b",
} as const;

export function getColors(theme: Theme) {
  return theme === "dark" ? DARK : LIGHT;
}

const SEVERITY_LIGHT: Record<string, string> = {
  critical: "#c0392b",
  high: "#e67e22",
  medium: "#d4a017",
  low: "#5a9a30",
  suspect: "#8e5bb0",
  info: "#3a7ca5",
  "n/a": "#c8c4b8",
};

const SEVERITY_DARK: Record<string, string> = {
  critical: "#e85a48",
  high: "#ec7a48",
  medium: "#e8a050",
  low: "#9bc870",
  suspect: "#b29ce0",
  info: "#6cb0d8",
  "n/a": "#34302a",
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
    tentative: c.muted,
    uncertain: c.gold,
  };
}

// Backward-compat static exports (light theme defaults, used by cell renderers that can't use hooks)
export const EDITORIAL_COLORS = LIGHT;
export const CHART_COLORS = [LIGHT.terracotta, LIGHT.olive, LIGHT.gold, LIGHT.rose, LIGHT.charcoalLight];
export const STATUS_COLORS = getStatusColors("light");
export const METHOD_COLORS = getMethodColors("light");
export const CONFIDENCE_COLORS = getConfidenceColors("light");
