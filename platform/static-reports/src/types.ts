// Vigolium JSONL export envelope
export interface ExportEnvelope {
  type: "scan" | "http_record" | "finding" | "module" | "oast_interaction" | "source_repo" | "scope";
  data: Record<string, unknown>;
}

// --- Record Types ---

export interface ScanRecord {
  uuid: string;
  name: string | null;
  description: string | null;
  status: string;
  target: string | null;
  modules: string | null;
  threads: number;
  scan_source: string | null;
  scan_mode: string | null;
  started_at: string;
  finished_at: string | null;
  duration_ms: number;
  total_requests: number;
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  error_message: string | null;
  created_at: string;
}

export interface HttpRecord {
  // Identity
  uuid: string;
  // Request
  scheme: string;
  hostname: string;
  port: number;
  ip: string;
  method: string;
  path: string;
  url: string;
  http_version: string;
  request_headers: Record<string, string[]>;
  request_content_type: string | null;
  request_content_length: number;
  request_body: string | null;
  // Set by the HTML report generator when the body was capped/dropped to keep
  // the embedded payload small (the full body is in the JSONL export).
  request_body_trimmed?: boolean;
  request_body_note?: string | null;
  request_authorization: string | null;
  request_hash: string;
  parameters: Record<string, string[]> | null;
  raw_request: string | null;
  // Response
  status_code: number;
  status_phrase: string;
  response_http_version: string;
  response_headers: Record<string, string[]>;
  response_content_type: string | null;
  response_content_length: number;
  response_title: string | null;
  response_body: string | null;
  // Set by the HTML report generator when the body was capped/dropped to keep
  // the embedded payload small (the full body is in the JSONL export).
  response_body_trimmed?: boolean;
  response_body_note?: string | null;
  response_hash: string;
  response_time_ms: number;
  response_words: number;
  has_response: boolean;
  raw_response: string | null;
  // Metadata
  source: string | null;
  remarks: string[] | null;
  risk_score: number;
  sent_at: string;
  received_at: string;
  created_at: string;
}

export interface Finding {
  id: number;
  project_uuid?: string;
  http_record_uuids: string[] | null;
  scan_uuid: string | null;
  agent_run_uuid?: string | null;
  url?: string | null;
  hostname?: string | null;
  module_id: string;
  module_name: string;
  module_type?: string | null;
  finding_source: string | null;
  module_short?: string | null;
  description: string | null;
  severity: string;
  confidence: string;
  tags: string[] | null;
  status?: string | null;
  remediation?: string | null;
  cwe_id?: string | null;
  cvss_score?: number;
  source_file?: string | null;
  repo_name?: string | null;
  matched_at: string[] | null;
  extracted_results: string[] | null;
  additional_evidence: string[] | null;
  request: string | null;
  response: string | null;
  finding_hash: string;
  found_at: string;
  created_at: string;
}

export interface ModuleRecord {
  id: string;
  name: string;
  type: string;
  description: string;
  severity: string;
  enabled: boolean;
  scan_scope: string;
}

// --- Parsed export data ---

export interface ExportData {
  scans: ScanRecord[];
  httpRecords: HttpRecord[];
  findings: Finding[];
  modules: ModuleRecord[];
}

// --- Stats ---

export interface ScanSummary {
  totalRequests: number;
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  scanDuration: string;
  target: string;
  status: string;
  activeModules: number;
  passiveModules: number;
  uniqueDomains: number;
}
