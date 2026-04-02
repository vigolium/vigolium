'use client';

import { useState, useMemo } from 'react';
import { useRouter } from 'next/navigation';
import { Search, Plus, Check, FolderOpen, ArrowRight, Lock } from 'lucide-react';
import { useProjects, useDeleteProject, useCreateProject } from '@/api/hooks';
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
        {/* Quick Project Selector */}
        <div className="space-y-2">
          <div className="flex items-center gap-2">
            <FolderOpen className="w-4 h-4" style={{ color: 'var(--v-secondary)' }} />
            <h2 className="text-sm font-bold" style={{ color: 'var(--v-accent)' }}>Quick Select</h2>
          </div>
          <div className="space-y-1">
            {projectsList.map((project: ProjectWithStats) => {
              const isCurrent = projectUUID === project.uuid;
              const restricted = (project.allowed_emails && project.allowed_emails.length > 0) ||
                (project.allowed_domains && project.allowed_domains.length > 0);
              return (
                <button
                  key={project.uuid}
                  onClick={() => !isCurrent && setProject(project.uuid)}
                  disabled={isCurrent}
                  className="w-full text-left border rounded px-3 py-2 text-xs transition-all duration-150 flex items-center justify-between"
                  style={{
                    borderColor: isCurrent ? 'var(--v-accent)' : 'var(--v-border)',
                    backgroundColor: isCurrent ? 'color-mix(in srgb, var(--v-accent) 8%, transparent)' : 'transparent',
                  }}
                >
                  <div className="flex items-center gap-2 min-w-0">
                    <FolderOpen className="w-3.5 h-3.5 shrink-0" style={{ color: isCurrent ? 'var(--v-accent)' : 'var(--v-text-muted)' }} />
                    <span className="truncate" style={{ color: isCurrent ? 'var(--v-accent)' : 'var(--v-text)' }}>
                      {project.name}
                    </span>
                    {restricted && <Lock className="w-3 h-3 shrink-0" style={{ color: 'var(--v-text-muted)' }} />}
                  </div>
                  {isCurrent ? (
                    <Check className="w-3 h-3 shrink-0" style={{ color: 'var(--v-accent)' }} />
                  ) : (
                    <span className="flex items-center gap-1 text-[10px] shrink-0" style={{ color: 'var(--v-text-muted)' }}>
                      select <ArrowRight className="w-3 h-3" />
                    </span>
                  )}
                </button>
              );
            })}
          </div>
        </div>
      </div>
    </PageShell>
  );
}
