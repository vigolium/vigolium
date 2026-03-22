'use client';

import { useState, useMemo } from 'react';
import { useRouter } from 'next/navigation';
import { Search, Plus, Check, Github, Unplug, Lock, Globe, Loader2, Zap } from 'lucide-react';
import { useProjects, useDeleteProject, useCreateProject, useGitHubStatus, useGitHubDisconnect, useGitHubRepos } from '@/api/hooks';
import type { ProjectWithStats } from '@/api/types';
import { useToast } from '@/contexts/ToastContext';
import { useProjectContext } from '@/contexts/ProjectContext';
import PageShell from './PageShell';

const DEFAULT_PROJECT_UUID = '00000000-0000-0000-0000-000000000001';

export default function ProjectsPage() {
  const { projectUUID, setProject } = useProjectContext();
  const { data: projectsList = [] } = useProjects();
  const deleteProjectMutation = useDeleteProject();
  const createProjectMutation = useCreateProject();
  const { toast } = useToast();
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [newProjectName, setNewProjectName] = useState('');
  const [newProjectDesc, setNewProjectDesc] = useState('');
  const [confirmDeleteUUID, setConfirmDeleteUUID] = useState<string | null>(null);
  const [projectSearch, setProjectSearch] = useState('');

  const filteredProjects = useMemo(() => {
    if (!projectSearch) return projectsList;
    const q = projectSearch.toLowerCase();
    return projectsList.filter((p: ProjectWithStats) =>
      p.name.toLowerCase().includes(q) || (p.description && p.description.toLowerCase().includes(q))
    );
  }, [projectsList, projectSearch]);

  const handleCreateProject = () => {
    if (!newProjectName.trim()) return;
    createProjectMutation.mutate({ name: newProjectName.trim(), description: newProjectDesc.trim() || undefined }, {
      onSuccess: (project) => {
        toast(`project "${project.name}" created`, 'success');
        setNewProjectName('');
        setNewProjectDesc('');
        setShowCreateForm(false);
        setProject(project.uuid);
      },
      onError: () => toast('error creating project', 'error'),
    });
  };

  const handleDeleteProject = (uuid: string) => {
    deleteProjectMutation.mutate(uuid, {
      onSuccess: () => {
        toast('project deleted', 'success');
        setConfirmDeleteUUID(null);
        if (projectUUID === uuid) setProject(null);
      },
      onError: () => toast('error deleting project', 'error'),
    });
  };

  return (
    <PageShell>
      <div className="px-4 py-4 space-y-3">
        {/* Header */}
        <div className="flex items-center justify-between gap-2">
          <span className="text-xs font-bold shrink-0" style={{ color: 'var(--v-text-muted)' }}>
            {projectsList.length} project{projectsList.length !== 1 ? 's' : ''}
          </span>
          <div className="flex items-center gap-2">
            <div className="flex items-center gap-1.5 border px-2 py-0.5" style={{ borderColor: 'var(--v-border)', backgroundColor: 'var(--v-surface)' }}>
              <Search className="w-3 h-3" style={{ color: 'var(--v-text-muted)' }} />
              <input
                type="text"
                value={projectSearch}
                onChange={(e) => setProjectSearch(e.target.value)}
                placeholder="search projects..."
                className="bg-transparent text-xs outline-none w-40"
                style={{ color: 'var(--v-text)' }}
              />
            </div>
            <button
              onClick={() => setShowCreateForm(!showCreateForm)}
              className="flex items-center gap-1 text-[10px] font-bold uppercase px-2 py-0.5 border transition-colors"
              style={{ borderColor: 'var(--v-accent)', color: 'var(--v-accent)' }}
            >
              <Plus className="w-3 h-3" /> new
            </button>
          </div>
        </div>

        {/* Create form */}
        {showCreateForm && (
          <div className="border p-3 space-y-2" style={{ borderColor: 'var(--v-accent)', backgroundColor: 'var(--v-surface)' }}>
            <input
              type="text"
              value={newProjectName}
              onChange={(e) => setNewProjectName(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleCreateProject()}
              placeholder="project name"
              className="w-full border text-xs px-2 py-1 focus:outline-none"
              style={{ backgroundColor: 'var(--v-bg)', borderColor: 'var(--v-border)', color: 'var(--v-text)' }}
              autoFocus
            />
            <input
              type="text"
              value={newProjectDesc}
              onChange={(e) => setNewProjectDesc(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleCreateProject()}
              placeholder="description (optional)"
              className="w-full border text-xs px-2 py-1 focus:outline-none"
              style={{ backgroundColor: 'var(--v-bg)', borderColor: 'var(--v-border)', color: 'var(--v-text)' }}
            />
            <div className="flex items-center gap-2">
              <button
                onClick={handleCreateProject}
                disabled={!newProjectName.trim() || createProjectMutation.isPending}
                className="text-[10px] font-bold uppercase px-2 py-0.5 border transition-colors disabled:opacity-40"
                style={{ borderColor: 'var(--v-success)', color: 'var(--v-success)' }}
              >
                {createProjectMutation.isPending ? 'creating...' : 'create'}
              </button>
              <button
                onClick={() => { setShowCreateForm(false); setNewProjectName(''); setNewProjectDesc(''); }}
                className="text-[10px] font-bold uppercase px-2 py-0.5 border transition-colors"
                style={{ borderColor: 'var(--v-border)', color: 'var(--v-text-muted)' }}
              >
                cancel
              </button>
            </div>
          </div>
        )}

        {/* Projects table */}
        <div className="border overflow-hidden" style={{ borderColor: 'var(--v-border)', backgroundColor: 'var(--v-bg)' }}>
          {/* Table header */}
          <div className="grid grid-cols-[1fr_1.2fr_60px_200px_50px_50px_80px_100px] px-3 py-1.5 border-b text-[10px] font-bold uppercase"
            style={{ borderColor: 'var(--v-border)', backgroundColor: 'var(--v-surface)', color: 'var(--v-text-muted)' }}>
            <span>Name</span>
            <span>Description</span>
            <span className="text-right">Records</span>
            <span className="text-right">Findings</span>
            <span className="text-right">Scans</span>
            <span className="text-right">Agents</span>
            <span className="text-right">Created</span>
            <span className="text-right">Actions</span>
          </div>

          {/* Table body */}
          <div className="overflow-y-auto" style={{ maxHeight: 'calc(100vh - 320px)' }}>
            {filteredProjects.map((project: ProjectWithStats) => {
              const isCurrent = projectUUID === project.uuid;
              const isDefault = project.uuid === DEFAULT_PROJECT_UUID;
              const s = project.stats;
              return (
                <div
                  key={project.uuid}
                  className="grid grid-cols-[1fr_1.2fr_60px_200px_50px_50px_80px_100px] px-3 py-1.5 border-b text-xs items-start transition-colors"
                  style={{
                    borderColor: 'var(--v-surface)',
                    backgroundColor: isCurrent ? 'color-mix(in srgb, var(--v-accent) 8%, transparent)' : undefined,
                  }}
                >
                  {/* Name */}
                  <div className="flex items-start gap-1 min-w-0 pr-2">
                    {isCurrent && <Check className="w-3 h-3 shrink-0 mt-0.5" style={{ color: 'var(--v-accent)' }} />}
                    <div className="min-w-0">
                      <span className="font-medium break-words leading-tight" style={{ color: isCurrent ? 'var(--v-accent)' : 'var(--v-text)' }}>
                        {project.name}
                      </span>
                      {isDefault && <span className="text-[9px] px-1 border ml-1 inline-block" style={{ borderColor: 'var(--v-border)', color: 'var(--v-text-muted)' }}>default</span>}
                    </div>
                  </div>
                  {/* Description */}
                  <span className="break-words leading-tight pr-2" style={{ color: 'var(--v-text-muted)' }}>{project.description || '-'}</span>
                  {/* Records */}
                  <span className="text-right tabular-nums" style={{ color: 'var(--v-text)' }}>{s?.http_records?.total ?? 0}</span>
                  {/* Findings */}
                  <div className="flex items-center justify-end gap-1.5 flex-wrap">
                    {s?.findings?.critical > 0 && <span className="text-[9px] px-1 py-0.5 border" style={{ color: 'var(--v-error)', borderColor: 'color-mix(in srgb, var(--v-error) 30%, transparent)' }}>C:{s.findings.critical}</span>}
                    {s?.findings?.high > 0 && <span className="text-[9px] px-1 py-0.5 border" style={{ color: '#f97316', borderColor: 'color-mix(in srgb, #f97316 30%, transparent)' }}>H:{s.findings.high}</span>}
                    {s?.findings?.medium > 0 && <span className="text-[9px] px-1 py-0.5 border" style={{ color: '#eab308', borderColor: 'color-mix(in srgb, #eab308 30%, transparent)' }}>M:{s.findings.medium}</span>}
                    {s?.findings?.low > 0 && <span className="text-[9px] px-1 py-0.5 border" style={{ color: 'var(--v-secondary)', borderColor: 'color-mix(in srgb, var(--v-secondary) 30%, transparent)' }}>L:{s.findings.low}</span>}
                    {s?.findings?.info > 0 && <span className="text-[9px] px-1 py-0.5 border" style={{ color: 'var(--v-text-muted)', borderColor: 'var(--v-border)' }}>I:{s.findings.info}</span>}
                    {(s?.findings?.total ?? 0) === 0 && <span style={{ color: 'var(--v-text-muted)' }}>0</span>}
                  </div>
                  {/* Scans */}
                  <span className="text-right tabular-nums" style={{ color: 'var(--v-text)' }}>{s?.scans ?? 0}</span>
                  {/* Agents */}
                  <span className="text-right tabular-nums" style={{ color: 'var(--v-text)' }}>{s?.agent_runs ?? 0}</span>
                  {/* Created */}
                  <span className="text-right text-[10px]" style={{ color: 'var(--v-text-muted)' }}>
                    {new Date(project.created_at).toLocaleDateString()}
                  </span>
                  {/* Actions */}
                  <div className="flex items-center justify-end gap-1">
                    {!isCurrent && (
                      <button
                        onClick={() => setProject(project.uuid)}
                        className="text-[10px] font-bold px-1"
                        style={{ color: 'var(--v-accent)' }}
                      >
                        [use]
                      </button>
                    )}
                    {!isDefault && (
                      confirmDeleteUUID === project.uuid ? (
                        <div className="flex items-center gap-0.5">
                          <button
                            onClick={() => handleDeleteProject(project.uuid)}
                            className="text-[10px] font-bold px-1"
                            style={{ color: 'var(--v-error)' }}
                          >
                            [yes]
                          </button>
                          <button
                            onClick={() => setConfirmDeleteUUID(null)}
                            className="text-[10px] font-bold px-1"
                            style={{ color: 'var(--v-text-muted)' }}
                          >
                            [no]
                          </button>
                        </div>
                      ) : (
                        <button
                          onClick={() => setConfirmDeleteUUID(project.uuid)}
                          className="text-[10px] font-bold px-1"
                          style={{ color: 'var(--v-text-muted)' }}
                        >
                          [del]
                        </button>
                      )
                    )}
                  </div>
                </div>
              );
            })}
            {filteredProjects.length === 0 && (
              <div className="px-3 py-4 text-xs" style={{ color: 'var(--v-text-muted)' }}>
                {projectSearch ? `no projects match "${projectSearch}"` : 'no projects found'}
              </div>
            )}
          </div>
        </div>
        {/* Github Integration */}
        <GitHubSection />
      </div>
    </PageShell>
  );
}

function GitHubSection() {
  const router = useRouter();
  const { data: status } = useGitHubStatus();
  const { data: reposData, isLoading: reposLoading } = useGitHubRepos(status?.connected === true);
  const disconnect = useGitHubDisconnect();
  const { toast } = useToast();
  const [repoSearch, setRepoSearch] = useState('');
  const [visibilityFilter, setVisibilityFilter] = useState<'all' | 'private' | 'public'>('all');
  const [showAll, setShowAll] = useState(false);

  const handleDisconnect = async () => {
    if (!confirm('Disconnect GitHub?')) return;
    try {
      await disconnect.mutateAsync();
      toast('GitHub disconnected', 'success');
    } catch (err) {
      toast(err instanceof Error ? err.message : 'Failed to disconnect', 'error');
    }
  };

  const repos = reposData?.repos ?? [];
  const filtered = repos.filter((r) => {
    if (repoSearch && !r.full_name.toLowerCase().includes(repoSearch.toLowerCase())) return false;
    if (visibilityFilter === 'private' && !r.private) return false;
    if (visibilityFilter === 'public' && r.private) return false;
    return true;
  });
  const displayed = showAll ? filtered : filtered.slice(0, 10);

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2">
        <Github className="w-4 h-4" style={{ color: 'var(--v-secondary)' }} />
        <h2 className="text-sm font-bold" style={{ color: 'var(--v-accent)' }}>Github Integration</h2>
      </div>
      <div
        className="flex items-center justify-between px-3 py-2 border rounded text-xs"
        style={{ borderColor: 'var(--v-border)' }}
      >
        {status?.connected ? (
          <>
            <span style={{ color: 'var(--v-success)' }}>
              Connected{status.username ? ` as @${status.username}` : ''}
            </span>
            <button
              onClick={handleDisconnect}
              className="flex items-center gap-1 transition-colors"
              style={{ color: 'var(--v-error)' }}
            >
              <Unplug className="w-3 h-3" /> Disconnect
            </button>
          </>
        ) : (
          <>
            <span style={{ color: 'var(--v-text-muted)' }}>Not connected</span>
            <a
              href="/api/github/install"
              className="flex items-center gap-1 px-2 py-0.5 border rounded transition-colors"
              style={{ borderColor: 'var(--v-accent)', color: 'var(--v-accent)' }}
            >
              <Github className="w-3 h-3" /> Connect GitHub
            </a>
          </>
        )}
      </div>

      {status?.connected && (
        <div className="space-y-2">
          <div className="flex items-center gap-2">
            <div className="flex items-center gap-1 flex-1 px-2 border rounded" style={{ borderColor: 'var(--v-border)' }}>
              <Search className="w-3 h-3 shrink-0" style={{ color: 'var(--v-text-muted)' }} />
              <input
                value={repoSearch}
                onChange={(e) => { setRepoSearch(e.target.value); setShowAll(false); }}
                placeholder="Search repositories..."
                className="w-full py-1 text-xs bg-transparent outline-none"
                style={{ color: 'var(--v-text)' }}
              />
            </div>
            {(['all', 'private', 'public'] as const).map((v) => (
              <button
                key={v}
                onClick={() => { setVisibilityFilter(v); setShowAll(false); }}
                className="px-2 py-1 text-[10px] border rounded transition-colors capitalize"
                style={{
                  borderColor: visibilityFilter === v ? 'var(--v-accent)' : 'var(--v-border)',
                  color: visibilityFilter === v ? 'var(--v-accent)' : 'var(--v-text-muted)',
                  backgroundColor: visibilityFilter === v ? 'color-mix(in srgb, var(--v-accent) 10%, transparent)' : 'transparent',
                }}
              >
                {v}
              </button>
            ))}
            <span className="text-[10px] shrink-0" style={{ color: 'var(--v-text-muted)' }}>
              {filtered.length} repos
            </span>
          </div>

          <div className="border overflow-hidden" style={{ borderColor: 'var(--v-border)' }}>
            <table className="w-full text-xs">
              <thead>
                <tr style={{ backgroundColor: 'color-mix(in srgb, var(--v-surface) 50%, transparent)' }}>
                  <th className="text-left px-3 py-2 font-bold" style={{ color: 'var(--v-text-muted)' }}>Repository</th>
                  <th className="text-left px-3 py-2 font-bold" style={{ color: 'var(--v-text-muted)' }}>Owner</th>
                  <th className="text-left px-3 py-2 font-bold" style={{ color: 'var(--v-text-muted)' }}>Visibility</th>
                  <th className="text-left px-3 py-2 font-bold" style={{ color: 'var(--v-text-muted)' }}>Default Branch</th>
                  <th className="text-right px-3 py-2 font-bold" style={{ color: 'var(--v-text-muted)' }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {reposLoading && (
                  <tr>
                    <td colSpan={5} className="px-3 py-4 text-center" style={{ color: 'var(--v-text-muted)' }}>
                      <Loader2 className="w-3 h-3 animate-spin inline mr-2" />Loading repositories...
                    </td>
                  </tr>
                )}
                {!reposLoading && filtered.length === 0 && (
                  <tr>
                    <td colSpan={5} className="px-3 py-4 text-center" style={{ color: 'var(--v-text-muted)' }}>
                      {repoSearch ? 'No repositories match' : 'No repositories found'}
                    </td>
                  </tr>
                )}
                {displayed.map((repo) => (
                  <tr key={repo.full_name} className="border-t" style={{ borderColor: 'var(--v-border)' }}>
                    <td className="px-3 py-1.5" style={{ color: 'var(--v-text)' }}>
                      <a
                        href={repo.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="hover:underline"
                        style={{ color: 'var(--v-accent)' }}
                      >
                        {repo.name}
                      </a>
                    </td>
                    <td className="px-3 py-1.5" style={{ color: 'var(--v-text-muted)' }}>{repo.owner}</td>
                    <td className="px-3 py-1.5">
                      <span className="inline-flex items-center gap-1" style={{ color: 'var(--v-text-muted)' }}>
                        {repo.private
                          ? <><Lock className="w-3 h-3" /> Private</>
                          : <><Globe className="w-3 h-3" /> Public</>
                        }
                      </span>
                    </td>
                    <td className="px-3 py-1.5" style={{ color: 'var(--v-text-muted)' }}>{repo.default_branch}</td>
                    <td className="px-3 py-1.5 text-right">
                      <button
                        onClick={() => router.push(`/agents?repo=${encodeURIComponent(repo.full_name)}`)}
                        className="inline-flex items-center gap-1 px-2 py-0.5 text-[10px] font-bold border rounded transition-colors"
                        style={{ borderColor: 'var(--v-accent)', color: 'var(--v-accent)' }}
                      >
                        <Zap className="w-3 h-3" /> Scan
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {!showAll && filtered.length > 10 && (
            <button
              onClick={() => setShowAll(true)}
              className="w-full text-center py-1.5 text-xs border rounded transition-colors"
              style={{ borderColor: 'var(--v-border)', color: 'var(--v-accent)' }}
            >
              Show all {filtered.length} repositories
            </button>
          )}
        </div>
      )}
    </div>
  );
}
