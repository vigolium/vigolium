'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { FolderOpen, Plus, ArrowRight, Lock } from 'lucide-react';
import Layout from './Layout';
import { useProjectContext } from '@/contexts/ProjectContext';
import { useCurrentUser } from '@/api/hooks';
import type { Project } from '@/api/types';

export default function ProjectSelectorPage() {
  const router = useRouter();
  const { projects, isLoading, setProject, createProject } = useProjectContext();
  const { data: currentUser } = useCurrentUser();

  const [newName, setNewName] = useState('');
  const [newDescription, setNewDescription] = useState('');
  const [showDescription, setShowDescription] = useState(false);
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState('');

  const handleSelect = (project: Project) => {
    setProject(project.uuid);
    router.push('/');
  };

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    const name = newName.trim();
    if (!name) {
      setError('Project name is required');
      return;
    }
    setError('');
    setCreating(true);
    try {
      await createProject(name, newDescription.trim() || undefined);
      router.push('/');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create project');
    } finally {
      setCreating(false);
    }
  };

  const hasRestrictions = (p: Project) =>
    (p.allowed_emails && p.allowed_emails.length > 0) ||
    (p.allowed_domains && p.allowed_domains.length > 0);

  return (
    <Layout>
      <style>{`
        @keyframes logo-glow-orange {
          0%, 100% { filter: drop-shadow(0 0 6px rgba(210, 130, 50, 0.3)) drop-shadow(0 0 18px rgba(210, 130, 50, 0.1)); }
          50% { filter: drop-shadow(0 0 10px rgba(210, 130, 50, 0.5)) drop-shadow(0 0 28px rgba(210, 130, 50, 0.18)); }
        }
        .project-item {
          transition: all 0.2s ease, box-shadow 0.25s ease;
        }
        .project-item:hover {
          box-shadow: 0 0 10px rgba(210, 130, 50, 0.1), 0 0 20px rgba(210, 130, 50, 0.05);
        }
      `}</style>
      <div className="min-h-screen flex flex-col items-center justify-center px-4 py-12">
        <div className="w-full max-w-lg">
          {/* Header */}
          <div className="text-center mb-8">
            <img
              src="/vigolium-logo-minimal.png"
              alt="Vigolium"
              className="w-24 h-24 mx-auto mb-5"
              style={{ animation: 'logo-glow-orange 3s ease-in-out infinite' }}
            />
            {currentUser && (
              <p className="text-xs mb-2" style={{ color: 'var(--v-text-muted)' }}>
                Logged in as <span style={{ color: 'var(--v-text)' }}>{currentUser.email}</span>
              </p>
            )}
            <h1 className="text-lg font-bold tracking-wider" style={{ color: 'var(--v-accent)' }}>
              Select Project
            </h1>
          </div>

          {isLoading ? (
            <div className="text-center text-sm" style={{ color: 'var(--v-text-muted)' }}>
              Loading projects...
            </div>
          ) : projects.length > 0 ? (
            /* Project List */
            <div className="space-y-2">
              {projects.map((project) => (
                <button
                  key={project.uuid}
                  onClick={() => handleSelect(project)}
                  className="project-item w-full text-left border rounded px-4 py-3 group"
                  style={{
                    backgroundColor: 'var(--v-surface)',
                    borderColor: 'var(--v-border)',
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.borderColor = '#d28232';
                    e.currentTarget.style.backgroundColor = 'rgba(210, 130, 50, 0.04)';
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.borderColor = 'var(--v-border)';
                    e.currentTarget.style.backgroundColor = 'var(--v-surface)';
                  }}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2.5 min-w-0">
                      <FolderOpen className="w-4 h-4 flex-shrink-0" style={{ color: 'var(--v-text-muted)' }} />
                      <div className="min-w-0">
                        <div className="text-sm truncate" style={{ color: 'var(--v-text)' }}>
                          {project.name}
                        </div>
                        {project.description && (
                          <div className="text-[10px] truncate mt-0.5" style={{ color: 'var(--v-text-muted)' }}>
                            {project.description}
                          </div>
                        )}
                      </div>
                    </div>
                    <div className="flex items-center gap-1.5 flex-shrink-0 ml-3">
                      {hasRestrictions(project) && (
                        <Lock className="w-3 h-3" style={{ color: 'var(--v-text-muted)' }} />
                      )}
                      <span className="flex items-center gap-1 text-[10px]" style={{ color: 'var(--v-text-muted)' }}>
                        Select <ArrowRight className="w-3 h-3" />
                      </span>
                    </div>
                  </div>
                </button>
              ))}

              {/* Create new project below the list */}
              <div className="pt-3">
                <div className="flex items-center gap-3 mb-3">
                  <div className="flex-1 border-t" style={{ borderColor: 'var(--v-border)' }} />
                  <span className="text-[10px]" style={{ color: 'var(--v-text-muted)' }}>or create new</span>
                  <div className="flex-1 border-t" style={{ borderColor: 'var(--v-border)' }} />
                </div>
                <form onSubmit={handleCreate} className="space-y-2">
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={newName}
                      onChange={(e) => setNewName(e.target.value)}
                      placeholder="Project name"
                      className="flex-1 border rounded text-xs px-3 py-2.5 focus:outline-none transition-colors"
                      style={{
                        backgroundColor: 'var(--v-surface)',
                        borderColor: 'var(--v-border)',
                        color: 'var(--v-text)',
                      }}
                      onFocus={(e) => e.currentTarget.style.borderColor = 'var(--v-accent)'}
                      onBlur={(e) => e.currentTarget.style.borderColor = 'var(--v-border)'}
                    />
                    <button
                      type="submit"
                      disabled={creating}
                      className="px-3.5 py-2.5 border rounded text-xs font-medium transition-all duration-200 disabled:opacity-50"
                      style={{
                        backgroundColor: 'rgba(46, 139, 87, 0.08)',
                        borderColor: 'rgba(46, 139, 87, 0.35)',
                        color: '#2e8b57',
                      }}
                      onMouseEnter={(e) => {
                        e.currentTarget.style.backgroundColor = 'rgba(46, 139, 87, 0.15)';
                        e.currentTarget.style.borderColor = '#2e8b57';
                      }}
                      onMouseLeave={(e) => {
                        e.currentTarget.style.backgroundColor = 'rgba(46, 139, 87, 0.08)';
                        e.currentTarget.style.borderColor = 'rgba(46, 139, 87, 0.35)';
                      }}
                    >
                      <Plus className="w-3.5 h-3.5" />
                    </button>
                  </div>
                  {!showDescription ? (
                    <button
                      type="button"
                      onClick={() => setShowDescription(true)}
                      className="text-[10px] transition-colors hover:underline"
                      style={{ color: 'var(--v-text-muted)' }}
                    >
                      + Add description
                    </button>
                  ) : (
                    <input
                      type="text"
                      value={newDescription}
                      onChange={(e) => setNewDescription(e.target.value)}
                      placeholder="Description (optional)"
                      className="w-full border rounded text-xs px-3 py-2 focus:outline-none transition-colors"
                      style={{
                        backgroundColor: 'var(--v-surface)',
                        borderColor: 'var(--v-border)',
                        color: 'var(--v-text)',
                      }}
                      onFocus={(e) => e.currentTarget.style.borderColor = 'var(--v-accent)'}
                      onBlur={(e) => e.currentTarget.style.borderColor = 'var(--v-border)'}
                    />
                  )}
                </form>
              </div>
            </div>
          ) : (
            /* No projects — show create form */
            <div
              className="border rounded p-5"
              style={{ backgroundColor: 'var(--v-surface)', borderColor: 'var(--v-border)' }}
            >
              <p className="text-xs mb-4" style={{ color: 'var(--v-text-muted)' }}>
                No projects available. Create your first project to get started.
              </p>
              <form onSubmit={handleCreate} className="space-y-3">
                <div>
                  <label className="block text-[10px] mb-1" style={{ color: 'var(--v-text-muted)' }}>Name</label>
                  <input
                    type="text"
                    value={newName}
                    onChange={(e) => setNewName(e.target.value)}
                    placeholder="my-project"
                    className="w-full border rounded text-xs px-3 py-2.5 focus:outline-none transition-colors"
                    style={{
                      backgroundColor: 'var(--v-surface)',
                      borderColor: 'var(--v-border)',
                      color: 'var(--v-text)',
                    }}
                    onFocus={(e) => e.currentTarget.style.borderColor = 'var(--v-accent)'}
                    onBlur={(e) => e.currentTarget.style.borderColor = 'var(--v-border)'}
                  />
                </div>
                <div>
                  <label className="block text-[10px] mb-1" style={{ color: 'var(--v-text-muted)' }}>Description (optional)</label>
                  <input
                    type="text"
                    value={newDescription}
                    onChange={(e) => setNewDescription(e.target.value)}
                    placeholder="Web app audit"
                    className="w-full border rounded text-xs px-3 py-2.5 focus:outline-none transition-colors"
                    style={{
                      backgroundColor: 'var(--v-surface)',
                      borderColor: 'var(--v-border)',
                      color: 'var(--v-text)',
                    }}
                    onFocus={(e) => e.currentTarget.style.borderColor = 'var(--v-accent)'}
                    onBlur={(e) => e.currentTarget.style.borderColor = 'var(--v-border)'}
                  />
                </div>
                <button
                  type="submit"
                  disabled={creating}
                  className="w-full border rounded text-xs font-medium py-2.5 transition-all duration-200 disabled:opacity-50 flex items-center justify-center gap-2"
                  style={{
                    backgroundColor: 'rgba(46, 139, 87, 0.08)',
                    borderColor: 'rgba(46, 139, 87, 0.35)',
                    color: '#2e8b57',
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.backgroundColor = 'rgba(46, 139, 87, 0.15)';
                    e.currentTarget.style.borderColor = '#2e8b57';
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.backgroundColor = 'rgba(46, 139, 87, 0.08)';
                    e.currentTarget.style.borderColor = 'rgba(46, 139, 87, 0.35)';
                  }}
                >
                  <Plus className="w-3.5 h-3.5" />
                  {creating ? 'Creating...' : 'Create Project'}
                </button>
              </form>
            </div>
          )}

          {error && (
            <p className="text-xs mt-3 text-center" style={{ color: '#dc3545' }}>{error}</p>
          )}

          {/* Footer */}
          <div className="text-center mt-6">
            <a
              href="/api/auth/logout"
              className="text-[10px] transition-colors hover:underline"
              style={{ color: 'var(--v-text-muted)' }}
            >
              Sign out
            </a>
          </div>
        </div>
      </div>
    </Layout>
  );
}
