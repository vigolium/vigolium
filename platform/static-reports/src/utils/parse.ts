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
  const order = ["critical", "high", "medium", "low", "info"];
  const counts = countBySeverity(findings);
  return order
    .filter((s) => (counts[s] || 0) > 0)
    .map((severity) => ({ severity, count: counts[severity] || 0 }));
}

export function findingsByModule(findings: Finding[]): { module: string; count: number }[] {
  const map = new Map<string, number>();
  for (const f of findings) {
    map.set(f.module_name, (map.get(f.module_name) || 0) + 1);
  }
  return Array.from(map.entries())
    .map(([module, count]) => ({ module, count }))
    .sort((a, b) => b.count - a.count);
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
