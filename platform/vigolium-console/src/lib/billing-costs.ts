/** Credit costs per scan endpoint. */
export const SCAN_COSTS: Record<string, number> = {
  '/api/scan-url': 1,
  '/api/scan-request': 1,
  '/api/scans/run': 5,
  '/api/scan-all-records': 10,
  '/api/scan-records': 2,
  '/api/agent/run/query': 2,
  '/api/agent/run/autopilot': 10,
  '/api/agent/run/pipeline': 15,
  '/api/agent/run/swarm': 20,
};

/** Resolve scan costs, allowing env-var JSON override. */
export function getScanCosts(): Record<string, number> {
  if (process.env.VIGOLIUM_CREDIT_COSTS) {
    try {
      return { ...SCAN_COSTS, ...JSON.parse(process.env.VIGOLIUM_CREDIT_COSTS) };
    } catch {
      // ignore malformed JSON
    }
  }
  return SCAN_COSTS;
}

/** Get credit cost for a given API path. Returns 0 if path is not gated. */
export function getCostForPath(path: string): number {
  const costs = getScanCosts();
  // Exact match first
  if (costs[path] !== undefined) return costs[path];
  // Prefix match (for /api/agent/run/*)
  for (const [pattern, cost] of Object.entries(costs)) {
    if (path.startsWith(pattern)) return cost;
  }
  return 0;
}

/** Human-readable scan type labels for the billing UI. */
export const SCAN_LABELS: Record<string, string> = {
  '/api/scan-url': 'URL Scan',
  '/api/scan-request': 'Request Scan',
  '/api/scans/run': 'Full Scan',
  '/api/scan-all-records': 'Scan All Records',
  '/api/scan-records': 'Scan Selected Records',
  '/api/agent/run/query': 'Agent Query',
  '/api/agent/run/autopilot': 'Agent Autopilot',
  '/api/agent/run/pipeline': 'Agent Pipeline',
  '/api/agent/run/swarm': 'Agent Swarm',
};
