import { useQuery, useMutation, useQueryClient, keepPreviousData } from '@tanstack/react-query';
import {
  apiGet, apiPost, apiPut, apiDelete, apiUpload, getProjectUUID,
  getGitHubStatus, disconnectGitHub, sendGitHubCallback, cloneGitHubRepo, listGitHubRepos, listGitHubBranches,
} from './client';
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
  GitHubConnectionStatus,
  GitHubRepo,
  GitHubBranch,
  GitHubCloneRequest,
  GitHubCloneResponse,
} from './types';

/** Prefix query keys with current project UUID so switching projects invalidates all data. */
function projectKey(...parts: unknown[]): unknown[] {
  return [getProjectUUID() ?? 'default', ...parts];
}

// Project CRUD hooks (not project-scoped — they manage projects themselves)
export function useProjects(owner?: string) {
  return useQuery({
    queryKey: ['projects', owner],
    queryFn: () =>
      apiGet<Project[]>('/api/projects', owner ? { owner } : undefined),
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

// --- GitHub integration hooks ---

export function useGitHubStatus() {
  return useQuery({
    queryKey: projectKey('github-status'),
    queryFn: () => getGitHubStatus(),
  });
}

export function useGitHubRepos(params?: { page?: number; per_page?: number; q?: string }, enabled = true) {
  return useQuery({
    queryKey: projectKey('github-repos', params),
    queryFn: () => listGitHubRepos(params),
    enabled,
    placeholderData: keepPreviousData,
  });
}

export function useGitHubBranches(owner: string, repo: string, enabled = true) {
  return useQuery({
    queryKey: projectKey('github-branches', owner, repo),
    queryFn: () => listGitHubBranches(owner, repo),
    enabled: enabled && !!owner && !!repo,
  });
}

export function useGitHubCallback() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ code, state }: { code: string; state: string }) =>
      sendGitHubCallback(code, state),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: projectKey('github-status') });
    },
  });
}

export function useGitHubDisconnect() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => disconnectGitHub(),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: projectKey('github-status') });
    },
  });
}

export function useGitHubClone() {
  return useMutation({
    mutationFn: (payload: GitHubCloneRequest) => cloneGitHubRepo(payload),
  });
}
