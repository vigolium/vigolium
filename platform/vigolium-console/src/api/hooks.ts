import { useQuery, useMutation, useQueryClient, keepPreviousData } from '@tanstack/react-query';
import {
  apiGet, apiPost, apiPut, apiDelete, apiUpload, getProjectUUID,
} from './client';
import type {
  Project,
  ProjectWithStats,
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
  ScopeConfig,
  ScopeUpdateResponse,
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
  DeleteFindingsRequest,
  DeleteRecordsRequest,
  DeleteResponse,
  DeleteScanResponse,
  DeleteOASTInteractionResponse,
  SourceRepo,
  SourceReposQueryParams,
  DeleteSourceRepoResponse,
  DeleteFindingResponse,
  DeleteHttpRecordResponse,
  ExtensionsResponse,
  Extension,
  ExtensionEditResponse,
  ExtensionDocsResponse,
  AgentRunStatusResponse,
  AgentRunListResponse,
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
  CreditBalance,
  CheckoutRequest,
  CheckoutResponse,
  PaymentHistoryItem,
  PortalResponse,
  TeamMember,
  InviteMemberRequest,
} from './types';

/** Prefix query keys with current project UUID so switching projects invalidates all data. */
function projectKey(...parts: unknown[]): unknown[] {
  return [getProjectUUID() ?? 'default', ...parts];
}

// Current user from WorkOS session (server-side)
export function useCurrentUser() {
  return useQuery({
    queryKey: ['current-user'],
    queryFn: async () => {
      const res = await fetch('/api/auth/me');
      if (!res.ok) return null;
      return res.json() as Promise<CurrentUser>;
    },
    staleTime: 5 * 60_000,
  });
}

// Project CRUD hooks (not project-scoped — they manage projects themselves)
export function useProjects(owner?: string) {
  return useQuery({
    queryKey: ['projects', owner],
    queryFn: () =>
      apiGet<ProjectWithStats[]>('/api/projects', owner ? { owner } : undefined),
  });
}

export function useProject(uuid: string | null) {
  return useQuery({
    queryKey: ['project', uuid],
    queryFn: () => apiGet<Project>(`/api/projects/${uuid}`),
    enabled: uuid !== null,
  });
}

export function useCreateProject() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (req: CreateProjectRequest) =>
      apiPost<Project>('/api/projects', req),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['projects'] });
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
      return query.state.data?.running ? 5_000 : 15_000;
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

export function useTriggerScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (opts?: { force?: boolean; enable_modules?: string[] }) =>
      apiPost<ScanResponse>('/api/scan', opts),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scan-status'] });
    },
  });
}

export function useCancelScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => apiDelete<ScanResponse>('/api/scan'),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scan-status'] });
    },
  });
}

// Scope hooks
export function useScope() {
  return useQuery({
    queryKey: projectKey('scope'),
    queryFn: () => apiGet<ScopeConfig>('/api/scope'),
    staleTime: 60_000,
  });
}

export function useUpdateScope() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (scope: ScopeConfig) => apiPost<ScopeUpdateResponse>('/api/scope', scope),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scope'] });
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
    mutationFn: (entries: ConfigEntry[]) => apiPost<ConfigUpdateResponse>('/api/config', { entries }),
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
      qc.invalidateQueries({ queryKey: ['oast-interactions'] });
      qc.invalidateQueries({ queryKey: ['stats'] });
    },
  });
}

export function useSourceRepos(params: SourceReposQueryParams) {
  return useQuery({
    queryKey: projectKey('source-repos', params),
    queryFn: () =>
      apiGet<PaginatedResponse<SourceRepo>>('/api/source-repos', params as Record<string, string | number | undefined>),
    placeholderData: keepPreviousData,
  });
}

export function useSourceRepo(id: number | null) {
  return useQuery({
    queryKey: projectKey('source-repo', id),
    queryFn: () => apiGet<SourceRepo>(`/api/source-repos/${id}`),
    enabled: id !== null,
    staleTime: 30_000,
  });
}

export function useDeleteSourceRepo() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiDelete<DeleteSourceRepoResponse>(`/api/source-repos/${id}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['source-repos'] });
      qc.invalidateQueries({ queryKey: ['stats'] });
    },
  });
}

export function useDeleteFinding() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      apiDelete<DeleteFindingResponse>(`/api/findings/${id}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['findings'] });
      qc.invalidateQueries({ queryKey: ['stats'] });
    },
  });
}

export function useDeleteHttpRecord() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (uuid: string) =>
      apiDelete<DeleteHttpRecordResponse>(`/api/http-records/${uuid}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['http-records'] });
      qc.invalidateQueries({ queryKey: ['stats'] });
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
      qc.invalidateQueries({ queryKey: ['scan-status'] });
    },
  });
}

export function useScanRequest() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (req: ScanRequestRequest) => apiPost<ScanResponse>('/api/scan-request', req),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scan-status'] });
    },
  });
}

export function useRunScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (req: RunScanRequest) => apiPost<ScanResponse>('/api/scans/run', req),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scan-status'] });
      qc.invalidateQueries({ queryKey: ['scans'] });
    },
  });
}

export function useScanAllRecords() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (req: ScanAllRecordsRequest) => apiPost<ScanResponse>('/api/scan-all-records', req),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scan-status'] });
      qc.invalidateQueries({ queryKey: ['scans'] });
    },
  });
}

export function useUploadRepo() {
  return useMutation({
    mutationFn: (file: File) => apiUpload<RepoUploadResponse>('/api/repos/upload', file),
  });
}

// Scan history hooks
export function useScans(params: ScansQueryParams) {
  return useQuery({
    queryKey: projectKey('scans', params),
    queryFn: () =>
      apiGet<PaginatedResponse<Scan>>('/api/scans', params as Record<string, string | number | undefined>),
    placeholderData: keepPreviousData,
    refetchInterval: 15_000,
  });
}

export function useDeleteScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (uuid: string) => apiDelete<DeleteScanResponse>(`/api/scans/${uuid}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scans'] });
      qc.invalidateQueries({ queryKey: ['scan-status'] });
      qc.invalidateQueries({ queryKey: ['stats'] });
    },
  });
}

export function useStopScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (uuid: string) => apiPost<ScanResponse>(`/api/scans/${uuid}/stop`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scans'] });
      qc.invalidateQueries({ queryKey: ['scan-status'] });
    },
  });
}

export function usePauseScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (uuid: string) => apiPost<ScanResponse>(`/api/scans/${uuid}/pause`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scans'] });
      qc.invalidateQueries({ queryKey: ['scan-status'] });
    },
  });
}

export function useResumeScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (uuid: string) => apiPost<ScanResponse>(`/api/scans/${uuid}/resume`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scans'] });
      qc.invalidateQueries({ queryKey: ['scan-status'] });
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
      qc.invalidateQueries({ queryKey: ['scan-status'] });
      qc.invalidateQueries({ queryKey: ['scans'] });
    },
  });
}

// Bulk delete hooks
export function useDeleteFindings() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (req: DeleteFindingsRequest) => apiDelete<DeleteResponse>('/api/findings', req),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['findings'] });
      qc.invalidateQueries({ queryKey: ['stats'] });
    },
  });
}

export function useDeleteRecords() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (req: DeleteRecordsRequest) => apiDelete<DeleteResponse>('/api/http-records', req),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['http-records'] });
      qc.invalidateQueries({ queryKey: ['stats'] });
    },
  });
}

// Ingest hooks
export function useIngestHttp() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (req: IngestRequest) => apiPost<IngestResponse>('/api/ingest-http', req),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['http-records'] });
      qc.invalidateQueries({ queryKey: ['stats'] });
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
export function useAgentRuns() {
  return useQuery({
    queryKey: projectKey('agent-runs'),
    queryFn: () => apiGet<AgentRunListResponse>('/api/agent/status/list'),
    refetchInterval: 10_000,
  });
}

export function useAgentSessions(params: AgentSessionsQueryParams) {
  return useQuery({
    queryKey: projectKey('agent-sessions', params),
    queryFn: () => apiGet<PaginatedResponse<AgentSession>>('/api/agent/sessions', params as Record<string, string | number | undefined>),
    placeholderData: keepPreviousData,
    refetchInterval: 10_000,
  });
}

export function useAgentSessionDetail(uuid: string | null) {
  return useQuery({
    queryKey: projectKey('agent-session-detail', uuid),
    queryFn: () => apiGet<AgentSessionDetail>(`/api/agent/sessions/${uuid}`),
    enabled: uuid !== null,
    refetchInterval: (query) =>
      query.state.data?.status === 'running' ? 5_000 : false,
  });
}

export function useAgentRunStatus(runId: string | null) {
  return useQuery({
    queryKey: projectKey('agent-run-status', runId),
    queryFn: () => apiGet<AgentRunStatusResponse>(`/api/agent/status/${runId}`),
    enabled: runId !== null,
    refetchInterval: (query) => {
      return query.state.data?.status === 'running' ? 3_000 : false;
    },
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
      const res = await fetch('/api/billing/credits');
      if (!res.ok) throw new Error('Failed to fetch credits');
      return res.json() as Promise<CreditBalance>;
    },
    staleTime: 30_000,
    refetchInterval: 60_000,
  });
}

export function useCreateCheckout() {
  return useMutation({
    mutationFn: async (req: CheckoutRequest) => {
      const res = await fetch('/api/billing/checkout', {
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
      const res = await fetch('/api/billing/history');
      if (!res.ok) throw new Error('Failed to fetch history');
      return res.json() as Promise<PaymentHistoryItem[]>;
    },
  });
}

export function useCreatePortalSession() {
  return useMutation({
    mutationFn: async () => {
      const res = await fetch('/api/billing/portal', { method: 'POST' });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error || 'Portal session failed');
      }
      return res.json() as Promise<PortalResponse>;
    },
  });
}

// --- Team hooks ---

export function useTeamMembers() {
  return useQuery({
    queryKey: ['team', 'members'],
    queryFn: async () => {
      const res = await fetch('/api/team/members');
      if (!res.ok) throw new Error('Failed to fetch members');
      return res.json() as Promise<TeamMember[]>;
    },
  });
}

export function useInviteMember() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (req: InviteMemberRequest) => {
      const res = await fetch('/api/team/invite', {
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
      const res = await fetch(`/api/team/members?membershipId=${membershipId}`, {
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
