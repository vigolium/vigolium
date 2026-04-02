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
      setError('project name is required');
      return;
    }
    setError('');
    setCreating(true);
    try {
      await createProject(name, newDescription.trim() || undefined);
      router.push('/');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'failed to create project');
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
          0%, 100% { filter: drop-shadow(0 0 8px rgba(232, 160, 72, 0.35)) drop-shadow(0 0 20px rgba(232, 160, 72, 0.12)); }
          50% { filter: drop-shadow(0 0 14px rgba(232, 160, 72, 0.55)) drop-shadow(0 0 32px rgba(232, 160, 72, 0.22)); }
        }
        .project-item {
          transition: all 0.15s ease, box-shadow 0.25s ease;
        }
        .project-item:hover {
          box-shadow: 0 0 12px rgba(232, 160, 72, 0.12), 0 0 24px rgba(232, 160, 72, 0.06);
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
              <p className="text-xs text-[#918175] mb-2">
                logged in as <span className="text-[#fce8c3]">{currentUser.email}</span>
              </p>
            )}
            <h1 className="text-lg font-bold text-[#7fd962] tracking-wider">
              SELECT PROJECT
            </h1>
          </div>

          {isLoading ? (
            <div className="text-center text-[#918175] text-sm">
              <span className="text-[#e8a048] animate-pulse">&#9608;</span> loading projects...
            </div>
          ) : projects.length > 0 ? (
            /* Project List */
            <div className="space-y-1.5">
              {projects.map((project) => (
                <button
                  key={project.uuid}
                  onClick={() => handleSelect(project)}
                  className="project-item w-full text-left border border-[#2e2b26] bg-[#1c1b19] px-4 py-3 hover:border-[#e8a048]/40 hover:bg-[#e8a048]/5 group"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2.5 min-w-0">
                      <FolderOpen className="w-4 h-4 text-[#918175] group-hover:text-[#e8a048] flex-shrink-0 transition-colors" />
                      <div className="min-w-0">
                        <div className="text-sm text-[#fce8c3] group-hover:text-[#e8a048] truncate transition-colors">
                          {project.name}
                        </div>
                        {project.description && (
                          <div className="text-[10px] text-[#918175] truncate mt-0.5">
                            {project.description}
                          </div>
                        )}
                      </div>
                    </div>
                    <div className="flex items-center gap-1.5 flex-shrink-0 ml-3">
                      {hasRestrictions(project) && (
                        <Lock className="w-3 h-3 text-[#918175]" />
                      )}
                      <span className="flex items-center gap-1 text-[10px] text-[#918175] group-hover:text-[#e8a048] transition-colors">
                        select <ArrowRight className="w-3 h-3" />
                      </span>
                    </div>
                  </div>
                </button>
              ))}

              {/* Create new project below the list */}
              <div className="pt-3">
                <div className="flex items-center gap-3 mb-3">
                  <div className="flex-1 border-t border-[#2e2b26]" />
                  <span className="text-[10px] text-[#918175]">or create new</span>
                  <div className="flex-1 border-t border-[#2e2b26]" />
                </div>
                <form onSubmit={handleCreate} className="space-y-2">
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={newName}
                      onChange={(e) => setNewName(e.target.value)}
                      placeholder="project name"
                      className="flex-1 bg-[#1c1b19] border border-[#2e2b26] text-[#fce8c3] text-xs px-3 py-2.5 focus:outline-none focus:border-[#7fd962]/50 placeholder-[#918175]/60"
                    />
                    <button
                      type="submit"
                      disabled={creating}
                      className="px-3.5 py-2.5 border border-[#7fd962]/30 bg-[#7fd962]/8 text-[#7fd962] transition-all duration-150 hover:border-[#7fd962]/60 hover:bg-[#7fd962]/15 disabled:opacity-50"
                    >
                      <Plus className="w-3.5 h-3.5" />
                    </button>
                  </div>
                  {!showDescription ? (
                    <button
                      type="button"
                      onClick={() => setShowDescription(true)}
                      className="text-[10px] text-[#918175] hover:text-[#fce8c3] transition-colors"
                    >
                      + add description
                    </button>
                  ) : (
                    <input
                      type="text"
                      value={newDescription}
                      onChange={(e) => setNewDescription(e.target.value)}
                      placeholder="description (optional)"
                      className="w-full bg-[#1c1b19] border border-[#2e2b26] text-[#fce8c3] text-xs px-3 py-2 focus:outline-none focus:border-[#7fd962]/50 placeholder-[#918175]/60"
                    />
                  )}
                </form>
              </div>
            </div>
          ) : (
            /* No projects — show create form */
            <div className="border border-[#2e2b26] bg-[#1c1b19] p-5">
              <p className="text-xs text-[#918175] mb-4">
                no projects available. create your first project to get started.
              </p>
              <form onSubmit={handleCreate} className="space-y-3">
                <div>
                  <label className="block text-[#918175] text-[10px] mb-1">name</label>
                  <input
                    type="text"
                    value={newName}
                    onChange={(e) => setNewName(e.target.value)}
                    placeholder="my-project"
                    className="w-full bg-[#1c1b19] border border-[#2e2b26] text-[#fce8c3] text-xs px-3 py-2.5 focus:outline-none focus:border-[#7fd962]/50 placeholder-[#918175]/60"
                  />
                </div>
                <div>
                  <label className="block text-[#918175] text-[10px] mb-1">description (optional)</label>
                  <input
                    type="text"
                    value={newDescription}
                    onChange={(e) => setNewDescription(e.target.value)}
                    placeholder="web app audit"
                    className="w-full bg-[#1c1b19] border border-[#2e2b26] text-[#fce8c3] text-xs px-3 py-2.5 focus:outline-none focus:border-[#7fd962]/50 placeholder-[#918175]/60"
                  />
                </div>
                <button
                  type="submit"
                  disabled={creating}
                  className="w-full border border-[#7fd962]/30 bg-[#7fd962]/8 text-[#7fd962] text-sm py-2.5 hover:bg-[#7fd962]/15 hover:border-[#7fd962]/50 transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
                >
                  <Plus className="w-3.5 h-3.5" />
                  {creating ? 'creating...' : 'create project'}
                </button>
              </form>
            </div>
          )}

          {error && (
            <p className="text-[#e06c75] text-[10px] mt-3 text-center">{error}</p>
          )}

          {/* Footer */}
          <div className="text-center mt-6">
            <a
              href="/api/auth/logout"
              className="text-[10px] text-[#918175] hover:text-[#fce8c3] transition-colors"
            >
              sign out
            </a>
          </div>
        </div>
      </div>
    </Layout>
  );
}
