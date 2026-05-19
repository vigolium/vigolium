import type {
  ExportEnvelope,
  ExportData,
  ScanRecord,
  HttpRecord,
  Finding,
  ModuleRecord,
  ScanSummary,
} from "../types";

export function parseExport(lines: string[]): ExportData {
  const data: ExportData = {
    scans: [],
    httpRecords: [],
    findings: [],
    modules: [],
  };

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const envelope = JSON.parse(trimmed) as ExportEnvelope;
      switch (envelope.type) {
        case "scan":
          data.scans.push(envelope.data as unknown as ScanRecord);
          break;
        case "http_record":
          data.httpRecords.push(envelope.data as unknown as HttpRecord);
          break;
        case "finding":
          data.findings.push(envelope.data as unknown as Finding);
          break;
        case "module":
          data.modules.push(envelope.data as unknown as ModuleRecord);
          break;
      }
    } catch {
      // skip malformed lines
    }
  }

  return data;
}

export function formatDuration(ms: number): string {
  const totalSeconds = Math.floor(ms / 1000);
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  if (minutes === 0) return `${seconds}s`;
  return `${minutes}m ${seconds}s`;
}

export function computeSummary(data: ExportData): ScanSummary {
  const scan = data.scans[0];
  const activeModules = data.modules.filter((m) => m.type === "active" && m.enabled).length;
  const passiveModules = data.modules.filter((m) => m.type === "passive" && m.enabled).length;
  const uniqueDomains = new Set(data.httpRecords.map((r) => r.hostname)).size;

  const severityCounts = countBySeverity(data.findings);

  if (scan) {
    return {
      totalRequests: scan.total_requests || data.httpRecords.length,
      totalFindings: data.findings.length,
      criticalCount: severityCounts.critical || 0,
      highCount: severityCounts.high || 0,
      mediumCount: severityCounts.medium || 0,
      lowCount: severityCounts.low || 0,
      infoCount: severityCounts.info || 0,
      scanDuration: formatDuration(scan.duration_ms),
      target: scan.target || "Unknown",
      status: scan.status,
      activeModules,
      passiveModules,
      uniqueDomains,
    };
  }

  return {
    totalRequests: data.httpRecords.length,
    totalFindings: data.findings.length,
    criticalCount: severityCounts.critical || 0,
    highCount: severityCounts.high || 0,
    mediumCount: severityCounts.medium || 0,
    lowCount: severityCounts.low || 0,
    infoCount: severityCounts.info || 0,
    scanDuration: "N/A",
    target: uniqueDomains > 0 ? data.httpRecords[0].hostname : "Unknown",
    status: "completed",
    activeModules,
    passiveModules,
    uniqueDomains,
  };
}

function countBySeverity(findings: Finding[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const f of findings) {
    const s = f.severity.toLowerCase();
    counts[s] = (counts[s] || 0) + 1;
  }
  return counts;
}

// --- Chart data helpers ---

export function findingsBySeverity(findings: Finding[]): { severity: string; count: number }[] {
  const order = ["critical", "high", "medium", "low", "info", "n/a"];
  const counts = countBySeverity(findings);
  return order
    .filter((s) => (counts[s] || 0) > 0)
    .map((severity) => ({ severity, count: counts[severity] || 0 }));
}

export function findingsByModule(findings: Finding[]): { module: string; count: number }[] {
  const map = new Map<string, number>();
  for (const f of findings) {
    const key = f.module_short || f.module_name;
    map.set(key, (map.get(key) || 0) + 1);
  }
  return Array.from(map.entries())
    .map(([module, count]) => ({ module, count }))
    .sort((a, b) => b.count - a.count);
}

export interface ModuleFindingSummary {
  module: string;
  severity: string;
  count: number;
}

const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4, "n/a": 5 };

export function findingsByModuleWithSeverity(findings: Finding[]): ModuleFindingSummary[] {
  const map = new Map<string, { severity: string; count: number }>();
  for (const f of findings) {
    const key = f.module_short || f.module_name;
    const existing = map.get(key);
    if (existing) {
      existing.count++;
      // keep the highest severity
      if ((SEVERITY_RANK[f.severity] ?? 99) < (SEVERITY_RANK[existing.severity] ?? 99)) {
        existing.severity = f.severity;
      }
    } else {
      map.set(key, { severity: f.severity, count: 1 });
    }
  }
  return Array.from(map.entries())
    .map(([module, { severity, count }]) => ({ module, severity, count }))
    .sort((a, b) => (SEVERITY_RANK[a.severity] ?? 99) - (SEVERITY_RANK[b.severity] ?? 99) || a.module.localeCompare(b.module));
}

export function httpByStatusCode(records: HttpRecord[]): { status: string; count: number }[] {
  const map = new Map<string, number>();
  for (const r of records) {
    const key = `${Math.floor(r.status_code / 100)}xx`;
    map.set(key, (map.get(key) || 0) + 1);
  }
  return Array.from(map.entries())
    .map(([status, count]) => ({ status, count }))
    .sort((a, b) => a.status.localeCompare(b.status));
}

export function httpByStatusCodeExact(records: HttpRecord[]): { status: string; count: number }[] {
  const map = new Map<number, number>();
  for (const r of records) {
    const code = r.status_code || 0;
    map.set(code, (map.get(code) || 0) + 1);
  }
  return Array.from(map.entries())
    .map(([code, count]) => ({ status: code === 0 ? "—" : String(code), count }))
    .sort((a, b) => b.count - a.count);
}

export function httpByMethod(records: HttpRecord[]): { method: string; count: number }[] {
  const map = new Map<string, number>();
  for (const r of records) {
    map.set(r.method, (map.get(r.method) || 0) + 1);
  }
  return Array.from(map.entries())
    .map(([method, count]) => ({ method, count }))
    .sort((a, b) => b.count - a.count);
}

export function httpByDomain(records: HttpRecord[]): { domain: string; count: number }[] {
  const map = new Map<string, number>();
  for (const r of records) {
    map.set(r.hostname, (map.get(r.hostname) || 0) + 1);
  }
  return Array.from(map.entries())
    .map(([domain, count]) => ({ domain, count }))
    .sort((a, b) => b.count - a.count);
}

export function httpByContentType(records: HttpRecord[]): { type: string; count: number }[] {
  const map = new Map<string, number>();
  for (const r of records) {
    const ct = r.response_content_type ? r.response_content_type.split(";")[0].trim() : "unknown";
    map.set(ct, (map.get(ct) || 0) + 1);
  }
  return Array.from(map.entries())
    .map(([type, count]) => ({ type, count }))
    .sort((a, b) => b.count - a.count);
}

export function findingsByConfidence(findings: Finding[]): { confidence: string; count: number }[] {
  const map = new Map<string, number>();
  for (const f of findings) {
    map.set(f.confidence, (map.get(f.confidence) || 0) + 1);
  }
  return Array.from(map.entries())
    .map(([confidence, count]) => ({ confidence, count }))
    .sort((a, b) => b.count - a.count);
}

export interface TimeBucket {
  label: string;
  count: number;
}

/**
 * Buckets findings into ≤ `bucketCount` equal time slices between the
 * earliest and latest `found_at` timestamp. Returns bucket labels (short
 * time-of-day) + counts. Empty result when no timestamps are usable.
 */
export function findingsOverTime(findings: Finding[], bucketCount = 10): TimeBucket[] {
  const times: number[] = [];
  for (const f of findings) {
    if (!f.found_at) continue;
    const t = new Date(f.found_at).getTime();
    if (!isNaN(t)) times.push(t);
  }
  if (times.length === 0) return [];

  const min = Math.min(...times);
  const max = Math.max(...times);
  const range = max - min;

  // All within the same second — single bucket
  if (range === 0) {
    return [{ label: new Date(min).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }), count: times.length }];
  }

  const n = Math.min(bucketCount, Math.max(2, times.length));
  const step = range / n;
  const buckets: TimeBucket[] = [];
  for (let i = 0; i < n; i++) {
    const start = min + step * i;
    const label = new Date(start).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    buckets.push({ label, count: 0 });
  }
  for (const t of times) {
    let idx = Math.floor((t - min) / step);
    if (idx >= n) idx = n - 1;
    buckets[idx].count++;
  }
  return buckets;
}

export interface ConfidenceCounts {
  certain: number;
  firm: number;
  tentative: number;
  suspect: number;
}

export function confidenceCounts(findings: Finding[]): ConfidenceCounts {
  const out: ConfidenceCounts = { certain: 0, firm: 0, tentative: 0, suspect: 0 };
  for (const f of findings) {
    const c = (f.confidence || "").toLowerCase();
    if (c === "certain") out.certain++;
    else if (c === "firm") out.firm++;
    else if (c === "tentative") out.tentative++;
    else if (c === "suspect" || c === "uncertain") out.suspect++;
  }
  return out;
}

export function severityCounts(findings: Finding[]): Record<string, number> {
  return countBySeverity(findings);
}
