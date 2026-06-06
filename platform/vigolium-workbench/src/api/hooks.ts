import { useQuery, useMutation, useQueryClient, keepPreviousData } from '@tanstack/react-query';
import { useEffect } from 'react';
import {
  apiGet, apiPost, apiPut, apiPatch, apiDelete, apiUpload, getProjectUUID, setDemoMode, assertNotDemo, withDemoKey,
} from './client';
import { isStaticBuild } from '@/lib/buildMode';
import { isTerminalAgentStatus } from './types';
import type {
  Project,
  CreateProjectRequest,
  UpdateProjectRequest,
  DeleteProjectResponse,
  StatsResponse,
  ServerInfoResponse,
  ScanStatusResponse,
  ScanResponse,
  Finding,
  HTTPRecord,
  OASTInteraction,
  ModulesResponse,
  PaginatedResponse,
  FindingsQueryParams,
  HttpRecordsQueryParams,
  OASTInteractionsQueryParams,
  ConfigResponse,
  ConfigUpdateResponse,
  ConfigEntry,
  ScanURLRequest,
  ScanRequestRequest,
  RunScanRequest,
  ScanAllRecordsRequest,
  RepoUploadResponse,
  IngestRequest,
  IngestResponse,
  Scan,
  ScansQueryParams,
  ScanRecordsRequest,
  DeleteScanResponse,
  DeleteOASTInteractionResponse,
  DeleteFindingResponse,
  DeleteHttpRecordResponse,
  ExtensionsResponse,
  Extension,
  ExtensionEditResponse,
  ExtensionDocsResponse,
  AgentRunResponse,
  AgentRunStatusResponse,
  AgentSession,
  AgentSessionDetail,
  AgentSessionsQueryParams,
  ScanLogsResponse,
  ScanLogsQueryParams,
  DbTablesResponse,
  DbColumnsResponse,
  DbRecordsResponse,
  DbRecordsQueryParams,
  DbMutationResponse,
  CurrentUser,
  DemoStatusResponse,
  CreditBalance,
  CheckoutRequest,
  CheckoutResponse,
  PaymentHistoryItem,
  PortalResponse,
  TeamMember,
  InviteMemberRequest,
  ProjectStats,
} from './types';

/** Prefix query keys with current project UUID so switching projects invalidates all data. */
function projectKey(...parts: unknown[]): unknown[] {
  return [getProjectUUID() ?? 'default', ...parts];
}

// Demo session status (cloud only) — tells the UI whether the visitor is in demo mode
export function useDemoStatus() {
  return useQuery({
    queryKey: ['demo-status'],
    queryFn: async () => {
      const res = await fetch(withDemoKey('/api/demo/status'));
      if (!res.ok) return { active: false, feature_enabled: false } as DemoStatusResponse;
      return res.json() as Promise<DemoStatusResponse>;
    },
    staleTime: 60_000,
  });
}

// Current user from WorkOS session (server-side)
export function useCurrentUser() {
  const query = useQuery({
    queryKey: ['current-user'],
    queryFn: async () => {
      const res = await fetch(withDemoKey('/api/auth/me'));
      if (!res.ok) {
        // Org membership gate: redirect to unauthorized page
        if (res.status === 403) {
          const data = await res.json().catch(() => ({}));
          if (data.error === 'no_organization') {
            window.location.href = '/unauthorized';
            return null;
          }
        }
        return null;
      }
      return res.json() as Promise<CurrentUser>;
    },
    staleTime: 5 * 60_000,
    enabled: !isStaticBuild,
  });

  // Keep the API client's demo flag in sync so mutations are gated client-side
  useEffect(() => {
    setDemoMode(query.data?.role === 'demo');
  }, [query.data?.role]);

  return query;
}

// Project CRUD hooks (not project-scoped — they manage projects themselves)
//
// In cloud mode the proxy answers these from Convex; in static mode they go
// straight to the scanner. Stats are fetched separately via `useProjectStats`
// per uuid — the listing intentionally doesn't include them so the Convex
// query stays cheap.
export function useProjects() {
  return useQuery({
    queryKey: ['projects'],
    queryFn: () => apiGet<Project[]>('/api/projects'),
  });
}

export function useProject(uuid: string | null) {
  return useQuery({
    queryKey: ['project', uuid],
    queryFn: () => apiGet<Project>(`/api/projects/${uuid}`),
    enabled: uuid !== null,
  });
}

export function useProjectStats(uuid: string | null) {
  return useQuery({
    queryKey: ['project-stats', uuid],
    queryFn: () => apiGet<ProjectStats>(`/api/projects/${uuid}/stats`),
    enabled: uuid !== null,
    staleTime: 30_000,
  });
}

export function useCreateProject() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (req: CreateProjectRequest) =>
      apiPost<Project>('/api/projects', req),
    // Await the refetch so mutateAsync doesn't resolve until ['projects'] is
    // populated with the new project. Otherwise the caller navigates while
    // the cache still holds the stale (empty) list, and ProjectContext's
    // bounce effect sees projects.length === 0 and redirects to
    // /select-project — breaking the create-then-go-to-app flow.
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ['projects'] });
    },
  });
}

export function useUpdateProject() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ uuid, ...body }: UpdateProjectRequest & { uuid: string }) =>
      apiPut<Project>(`/api/projects/${uuid}`, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['projects'] });
      qc.invalidateQueries({ queryKey: ['project'] });
    },
  });
}

export function useDeleteProject() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (uuid: string) =>
      apiDelete<DeleteProjectResponse>(`/api/projects/${uuid}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['projects'] });
    },
  });
}

export function useStats() {
  return useQuery({
    queryKey: projectKey('stats'),
    queryFn: () => apiGet<StatsResponse>('/api/stats'),
    refetchInterval: 30_000,
  });
}

export function useServerInfo() {
  return useQuery({
    queryKey: ['server-info'],
    queryFn: () => apiGet<ServerInfoResponse>('/server-info'),
    refetchInterval: 60_000,
  });
}

export function useScanStatus() {
  const query = useQuery({
    queryKey: projectKey('scan-status'),
    queryFn: () => apiGet<ScanStatusResponse>('/api/scan/status'),
    refetchInterval: (query) => {
      return query.state.data?.running ? 5_000 : 60_000;
    },
  });
  return query;
}

export function useFindings(params: FindingsQueryParams) {
  return useQuery({
    queryKey: projectKey('findings', params),
    queryFn: () =>
      apiGet<PaginatedResponse<Finding>>('/api/findings', params as Record<string, string | number | undefined>),
    placeholderData: keepPreviousData,
  });
}

export function useHttpRecords(params: HttpRecordsQueryParams) {
  return useQuery({
    queryKey: projectKey('http-records', params),
    queryFn: () =>
      apiGet<PaginatedResponse<HTTPRecord>>('/api/http-records', params as Record<string, string | number | undefined>),
    placeholderData: keepPreviousData,
  });
}

export function useModules(search?: string) {
  return useQuery({
    queryKey: ['modules', search],
    queryFn: async () => {
      const res = await apiGet<ModulesResponse>('/api/modules', search ? { search } : undefined);
      return res.modules ?? [];
    },
    staleTime: 5 * 60_000,
  });
}

export function useCancelScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => apiDelete<ScanResponse>('/api/scan'),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: projectKey('scan-status') });
    },
  });
}

// Config hooks
export function useConfig(filter?: string) {
  return useQuery({
    queryKey: ['config', filter],
    queryFn: () => apiGet<ConfigResponse>('/api/config', filter ? { filter } : undefined),
    staleTime: 30_000,
  });
}

export function useUpdateConfig() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (entries: ConfigEntry[]) =>
      apiPost<ConfigUpdateResponse>(
        '/api/config',
        Object.fromEntries(entries.map(({ key, value }) => [key, value])),
      ),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['config'] });
    },
  });
}

// Single-item detail hooks
export function useFinding(id: number | null) {
  return useQuery({
    queryKey: projectKey('finding', id),
    queryFn: () => apiGet<Finding>(`/api/findings/${id}`),
    enabled: id !== null,
    staleTime: 30_000,
  });
}

export function useOASTInteractions(params: OASTInteractionsQueryParams) {
  return useQuery({
    queryKey: projectKey('oast-interactions', params),
    queryFn: () =>
      apiGet<PaginatedResponse<OASTInteraction>>('/api/oast-interactions', params as Record<string, string | number | undefined>),
    placeholderData: keepPreviousData,
  });
}

export function useOASTInteraction(id: number | null) {
  return useQuery({
    queryKey: projectKey('oast-interaction', id),
    queryFn: () => apiGet<OASTInteraction>(`/api/oast-interactions/${id}`),
    enabled: id !== null,
    staleTime: 30_000,
  });
}

export function useDeleteOASTInteraction() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiDelete<DeleteOASTInteractionResponse>(`/api/oast-interactions/${id}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: projectKey('oast-interactions') });
      qc.invalidateQueries({ queryKey: projectKey('stats') });
    },
  });
}

export function useDeleteFinding() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiDelete<DeleteFindingResponse>(`/api/findings/${id}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: projectKey('findings') });
      qc.invalidateQueries({ queryKey: projectKey('stats') });
    },
  });
}

export function useUpdateFindingStatus() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, status }: { id: number; status: string }) =>
      apiPatch<Finding>(`/api/findings/${id}/status`, { status }),
    onSuccess: (updated) => {
      qc.invalidateQueries({ queryKey: projectKey('findings') });
      qc.invalidateQueries({ queryKey: projectKey('finding', updated?.id) });
      qc.invalidateQueries({ queryKey: projectKey('stats') });
    },
  });
}

export function useDeleteHttpRecord() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (uuid: string) =>
      apiDelete<DeleteHttpRecordResponse>(`/api/http-records/${uuid}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: projectKey('http-records') });
      qc.invalidateQueries({ queryKey: projectKey('stats') });
    },
  });
}

export function useHttpRecord(uuid: string | null) {
  return useQuery({
    queryKey: projectKey('http-record', uuid),
    queryFn: () => apiGet<HTTPRecord>(`/api/http-records/${uuid}`),
    enabled: uuid !== null,
    staleTime: 30_000,
  });
}

// Scan URL/Request hooks
export function useScanURL() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (req: ScanURLRequest) => apiPost<ScanResponse>('/api/scan-url', req),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: projectKey('scan-status') });
    },
  });
}

export function useScanRequest() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (req: ScanRequestRequest) => apiPost<ScanResponse>('/api/scan-request', req),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: projectKey('scan-status') });
    },
  });
}

export function useRunScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (req: RunScanRequest) => apiPost<ScanResponse>('/api/scans/run', req),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: projectKey('scan-status') });
      qc.invalidateQueries({ queryKey: projectKey('scans') });
    },
  });
}

export function useScanAllRecords() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (req: ScanAllRecordsRequest) => apiPost<ScanResponse>('/api/scan-all-records', req),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: projectKey('scan-status') });
      qc.invalidateQueries({ queryKey: projectKey('scans') });
    },
  });
}

export function useUploadRepo() {
  return useMutation({
    mutationFn: (file: File) => apiUpload<RepoUploadResponse>('/api/repos/upload', file),
  });
}

// Scan history hooks
//
// Polls every 30s only while at least one row is in a non-terminal state.
// Idle history pages (everything completed) refetch on window focus instead.
export function useScans(params: ScansQueryParams) {
  return useQuery({
    queryKey: projectKey('scans', params),
    queryFn: () =>
      apiGet<PaginatedResponse<Scan>>('/api/scans', params as Record<string, string | number | undefined>),
    placeholderData: keepPreviousData,
    refetchInterval: (query) => {
      const data = query.state.data as PaginatedResponse<Scan> | undefined;
      if (!data?.data) return false;
      const hasRunning = data.data.some(
        (s) => s.status === 'running' || s.status === 'pending' || s.status === 'paused',
      );
      return hasRunning ? 30_000 : false;
    },
  });
}

export function useDeleteScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (uuid: string) => apiDelete<DeleteScanResponse>(`/api/scans/${uuid}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: projectKey('scans') });
      qc.invalidateQueries({ queryKey: projectKey('scan-status') });
      qc.invalidateQueries({ queryKey: projectKey('stats') });
    },
  });
}

export function useStopScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (uuid: string) => apiPost<ScanResponse>(`/api/scans/${uuid}/stop`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: projectKey('scans') });
      qc.invalidateQueries({ queryKey: projectKey('scan-status') });
    },
  });
}

export function usePauseScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (uuid: string) => apiPost<ScanResponse>(`/api/scans/${uuid}/pause`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: projectKey('scans') });
      qc.invalidateQueries({ queryKey: projectKey('scan-status') });
    },
  });
}

export function useResumeScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (uuid: string) => apiPost<ScanResponse>(`/api/scans/${uuid}/resume`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: projectKey('scans') });
      qc.invalidateQueries({ queryKey: projectKey('scan-status') });
    },
  });
}

export function useScanLogs(uuid: string | null, params?: ScanLogsQueryParams, isRunning?: boolean) {
  return useQuery({
    queryKey: projectKey('scan-logs', uuid, params),
    queryFn: () =>
      apiGet<ScanLogsResponse>(`/api/scans/${uuid}/logs`, params as Record<string, string | number | undefined>),
    enabled: uuid !== null,
    refetchInterval: isRunning ? 5_000 : false,
  });
}

// Selective scan hooks
export function useScanRecords() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (req: ScanRecordsRequest) => apiPost<ScanResponse>('/api/scan-records', req),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: projectKey('scan-status') });
      qc.invalidateQueries({ queryKey: projectKey('scans') });
    },
  });
}

// Ingest hooks
export function useIngestHttp() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (req: IngestRequest) => apiPost<IngestResponse>('/api/ingest-http', req),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: projectKey('http-records') });
      qc.invalidateQueries({ queryKey: projectKey('stats') });
    },
  });
}

// Extension hooks
export function useExtensions(params?: { type?: string; search?: string }) {
  return useQuery({
    queryKey: ['extensions', params],
    queryFn: () =>
      apiGet<ExtensionsResponse>('/api/extensions', params as Record<string, string | number | undefined>),
  });
}

export function useExtension(fileName: string | null) {
  return useQuery({
    queryKey: ['extension', fileName],
    queryFn: () => apiGet<Extension>(`/api/extensions/${fileName}`),
    enabled: fileName !== null,
    staleTime: 30_000,
  });
}

export function useUpdateExtension() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ fileName, content }: { fileName: string; content: string }) =>
      apiPut<ExtensionEditResponse>(`/api/extensions/${fileName}`, { content }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['extensions'] });
      qc.invalidateQueries({ queryKey: ['extension'] });
    },
  });
}

export function useExtensionDocs(search?: string) {
  return useQuery({
    queryKey: ['extension-docs', search],
    queryFn: () =>
      apiGet<ExtensionDocsResponse>('/api/extensions/docs', search ? { search } : undefined),
    staleTime: 5 * 60_000,
  });
}

// Agent hooks
//
// Polls only while at least one session is running; otherwise refetches on
// window focus.
export function useAgentSessions(params: AgentSessionsQueryParams) {
  return useQuery({
    queryKey: projectKey('agent-sessions', params),
    queryFn: () => apiGet<PaginatedResponse<AgentSession>>('/api/agent/sessions', params as Record<string, string | number | undefined>),
    placeholderData: keepPreviousData,
    refetchInterval: (query) => {
      const data = query.state.data as PaginatedResponse<AgentSession> | undefined;
      if (!data?.data) return false;
      const hasActive = data.data.some((s) => !isTerminalAgentStatus(s.status));
      return hasActive ? 30_000 : false;
    },
  });
}

export function useAgentSessionDetail(uuid: string | null) {
  return useQuery({
    queryKey: projectKey('agent-session-detail', uuid),
    queryFn: () => apiGet<AgentSessionDetail>(`/api/agent/sessions/${uuid}`),
    enabled: uuid !== null,
    // Poll while the run is still active. Keying off "not terminal" (rather than
    // just "running") keeps polling through the transient "cancelling" state so
    // the UI sees the final "cancelled".
    refetchInterval: (query) =>
      isTerminalAgentStatus(query.state.data?.status) ? false : 5_000,
  });
}

export function useAgentRunStatus(runId: string | null) {
  return useQuery({
    queryKey: projectKey('agent-run-status', runId),
    queryFn: () => apiGet<AgentRunStatusResponse>(`/api/agent/status/${runId}`),
    enabled: runId !== null,
    // Poll until the run reaches a terminal status (covers running, cancelling,
    // pending, etc.) so a cancel resolves to its final state in the UI.
    refetchInterval: (query) =>
      isTerminalAgentStatus(query.state.data?.status) ? false : 3_000,
  });
}

export function useStartAutopilotRun() {
  return useMutation({
    mutationFn: (body: { prompt: string }) =>
      apiPost<AgentRunResponse>('/api/agent/run/autopilot', body),
  });
}

// Starts any agent run (autopilot/audit/swarm/query) in async mode — the POST
// returns a run UUID immediately and the caller observes it via the run-status
// poll + the session's runtime.log tail. Invalidates the sessions list so the
// new run shows up without waiting for the next poll.
export function useStartAgentRun() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ endpoint, body }: { endpoint: string; body: Record<string, unknown> }) =>
      apiPost<AgentRunResponse>(endpoint, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: projectKey('agent-sessions') });
    },
  });
}

// Cancels an in-flight agent run by UUID (POST /api/agent/scans/:uuid/cancel).
// The run unwinds and its finalization records the terminal "cancelled" status,
// which the status poll picks up.
export function useCancelAgentRun() {
  return useMutation({
    mutationFn: (runId: string) =>
      apiPost<AgentRunResponse>(`/api/agent/scans/${runId}/cancel`),
  });
}

// --- Generic Database API hooks ---

export function useDbTables() {
  return useQuery({
    queryKey: ['db-tables'],
    queryFn: () => apiGet<DbTablesResponse>('/api/db/tables'),
  });
}

export function useDbColumns(table: string | null) {
  return useQuery({
    queryKey: ['db-columns', table],
    queryFn: () => apiGet<DbColumnsResponse>(`/api/db/tables/${table}/columns`),
    enabled: table !== null,
  });
}

export function useDbRecord(table: string | null, id: string | null) {
  return useQuery({
    queryKey: projectKey('db-record', table, id),
    queryFn: () => apiGet<import('./types').DbSingleRecordResponse>(`/api/db/tables/${table}/records/${id}`),
    enabled: table !== null && id !== null,
  });
}

export function useDbRecords(table: string | null, params: DbRecordsQueryParams) {
  return useQuery({
    queryKey: projectKey('db-records', table, params),
    queryFn: () =>
      apiGet<DbRecordsResponse>(`/api/db/tables/${table}/records`, params as Record<string, string | number | undefined>),
    enabled: table !== null,
    placeholderData: keepPreviousData,
  });
}

export function useDbCreateRecord() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ table, data }: { table: string; data: Record<string, unknown> }) =>
      apiPost<DbMutationResponse>(`/api/db/tables/${table}/records`, data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['db-records'] });
      qc.invalidateQueries({ queryKey: ['db-tables'] });
    },
  });
}

export function useDbUpdateRecord() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ table, id, data }: { table: string; id: string; data: Record<string, unknown> }) =>
      apiPut<DbMutationResponse>(`/api/db/tables/${table}/records/${id}`, data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['db-records'] });
    },
  });
}

export function useDbDeleteRecord() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ table, id }: { table: string; id: string }) =>
      apiDelete<DbMutationResponse>(`/api/db/tables/${table}/records/${id}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['db-records'] });
      qc.invalidateQueries({ queryKey: ['db-tables'] });
    },
  });
}

// --- Billing hooks ---
// These call /api/billing/* directly (Next.js API routes, not proxied to scan server)

export function useCredits() {
  return useQuery({
    queryKey: ['billing', 'credits'],
    queryFn: async () => {
      const res = await fetch(withDemoKey('/api/billing/credits'));
      if (!res.ok) throw new Error('Failed to fetch credits');
      return res.json() as Promise<CreditBalance>;
    },
    staleTime: 30_000,
    refetchInterval: 60_000,
    enabled: !isStaticBuild,
  });
}

export function useCreateCheckout() {
  return useMutation({
    mutationFn: async (req: CheckoutRequest) => {
      assertNotDemo('/api/billing/checkout');
      const res = await fetch(withDemoKey('/api/billing/checkout'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(req),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error || 'Checkout failed');
      }
      return res.json() as Promise<CheckoutResponse>;
    },
  });
}

export function usePaymentHistory() {
  return useQuery({
    queryKey: ['billing', 'history'],
    queryFn: async () => {
      const res = await fetch(withDemoKey('/api/billing/history'));
      if (!res.ok) throw new Error('Failed to fetch history');
      return res.json() as Promise<PaymentHistoryItem[]>;
    },
  });
}

export function useCreatePortalSession() {
  return useMutation({
    mutationFn: async () => {
      assertNotDemo('/api/billing/portal');
      const res = await fetch(withDemoKey('/api/billing/portal'), { method: 'POST' });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error || 'Portal session failed');
      }
      return res.json() as Promise<PortalResponse>;
    },
  });
}

export interface RedeemVoucherResponse {
  code: string;
  credits: number;
  balance: number;
}

export function useRedeemVoucher() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (code: string) => {
      assertNotDemo('/api/billing/redeem');
      const res = await fetch(withDemoKey('/api/billing/redeem'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error || 'Voucher redemption failed');
      }
      return res.json() as Promise<RedeemVoucherResponse>;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['billing'] });
      qc.invalidateQueries({ queryKey: ['current-user'] });
    },
  });
}

// --- On-demand audit hooks ---

export interface OnDemandAuditUploadResponse {
  source: string;
  bucket: string;
  key: string;
  size: number;
  filename: string;
  project_uuid: string;
}

export interface OnDemandAuditSubmitResponse {
  id: string;
  agentic_scan_uuid: string;
  scan_uuid: string;
  project_uuid: string;
  execution: string;
  status: string;
  queued_at: string;
  cost: number;
  remaining_credits: number;
}

export function useOnDemandAuditUpload() {
  return useMutation({
    mutationFn: async (file: File) => {
      assertNotDemo('/api/on-demand-audit/upload');
      const projectUuid = getProjectUUID();
      if (!projectUuid) {
        throw new Error('No project selected — pick one from the project switcher.');
      }
      const form = new FormData();
      form.append('file', file);
      const res = await fetch(withDemoKey('/api/on-demand-audit/upload'), {
        method: 'POST',
        headers: { 'X-Project-UUID': projectUuid },
        body: form,
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error || 'Upload failed');
      }
      return res.json() as Promise<OnDemandAuditUploadResponse>;
    },
  });
}

export function useOnDemandAuditSubmit() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: { source: string }) => {
      assertNotDemo('/api/on-demand-audit/submit');
      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      const projectUuid = getProjectUUID();
      if (projectUuid) headers['X-Project-UUID'] = projectUuid;
      const res = await fetch(withDemoKey('/api/on-demand-audit/submit'), {
        method: 'POST',
        headers,
        body: JSON.stringify(body),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error || 'Submit failed');
      }
      return res.json() as Promise<OnDemandAuditSubmitResponse>;
    },
    onSuccess: () => {
      // Refresh credit balance after the deduction.
      qc.invalidateQueries({ queryKey: ['billing', 'credits'] });
    },
  });
}

// --- Team hooks ---

export function useTeamMembers() {
  return useQuery({
    queryKey: ['team', 'members'],
    queryFn: async () => {
      const res = await fetch(withDemoKey('/api/team/members'));
      if (!res.ok) throw new Error('Failed to fetch members');
      return res.json() as Promise<TeamMember[]>;
    },
    enabled: !isStaticBuild,
  });
}

export function useInviteMember() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (req: InviteMemberRequest) => {
      assertNotDemo('/api/team/invite');
      const res = await fetch(withDemoKey('/api/team/invite'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(req),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error || 'Failed to invite');
      }
      return res.json();
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['team', 'members'] });
    },
  });
}

export function useRemoveMember() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (membershipId: string) => {
      assertNotDemo('/api/team/members');
      const res = await fetch(withDemoKey(`/api/team/members?membershipId=${membershipId}`), {
        method: 'DELETE',
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error || 'Failed to remove member');
      }
      return res.json();
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['team', 'members'] });
    },
  });
}

