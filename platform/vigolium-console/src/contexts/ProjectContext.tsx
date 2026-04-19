'use client';

import { createContext, useContext, useState, useEffect, useCallback, useMemo, type ReactNode } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { getProjectUUID, setProjectUUID } from '@/api/client';
import { useProjects, useCreateProject, useDomainMap, useCurrentUser } from '@/api/hooks';
import { isCloudBuild } from '@/lib/buildMode';
import type { Project, DomainMap } from '@/api/types';

interface ProjectContextValue {
  projectUUID: string | null;
  projects: Project[];
  isLoading: boolean;
  setProject: (uuid: string | null) => void;
  createProject: (name: string, description?: string) => Promise<void>;
}

const ProjectContext = createContext<ProjectContextValue | undefined>(undefined);

/**
 * Given a domain map and user email, return the set of project UUIDs the user can access.
 * Returns null if there are no restrictions (domain map is empty or user has no email).
 */
function getAllowedProjectUUIDs(domainMap: DomainMap | undefined, email: string | undefined, convexProjects: string[] | undefined): Set<string> | null {
  // Convex project access takes precedence when available
  if (convexProjects !== undefined) {
    return new Set(convexProjects);
  }

  // Fall back to domain-map filtering
  if (!domainMap || !email) return null;

  const normalizedEmail = email.toLowerCase();
  const domain = '@' + normalizedEmail.split('@')[1];
  const allowed = new Set<string>();

  const emailMatches = domainMap.emails[normalizedEmail];
  if (emailMatches) {
    emailMatches.forEach((uuid) => allowed.add(uuid));
  }

  const domainMatches = domainMap.domains[domain];
  if (domainMatches) {
    domainMatches.forEach((uuid) => allowed.add(uuid));
  }

  return allowed;
}

export function ProjectProvider({ children }: { children: ReactNode }) {
  const [projectUUID, setProjectUUIDState] = useState<string | null>(null);
  const [mounted, setMounted] = useState(false);
  const queryClient = useQueryClient();
  const { data: allProjects = [], isLoading: projectsLoading } = useProjects();
  const createProjectMutation = useCreateProject();

  // In cloud mode, fetch domain map and user email for project filtering
  const { data: domainMap } = useDomainMap();
  const { data: currentUser } = useCurrentUser();
  const userEmail = isCloudBuild ? currentUser?.email : undefined;
  const convexProjects = isCloudBuild ? currentUser?.allowedProjects : undefined;

  const allowedUUIDs = useMemo(
    () => getAllowedProjectUUIDs(domainMap, userEmail, convexProjects),
    [domainMap, userEmail, convexProjects],
  );

  // Filter projects: show projects the user has access to + unrestricted projects
  const projects = useMemo(() => {
    if (!allowedUUIDs) return allProjects;

    return allProjects.filter((p) => {
      // User is explicitly allowed
      if (allowedUUIDs.has(p.uuid)) return true;
      // Project has no restrictions — open to anyone
      const hasRestrictions =
        (p.allowed_emails && p.allowed_emails.length > 0) ||
        (p.allowed_domains && p.allowed_domains.length > 0);
      return !hasRestrictions;
    });
  }, [allProjects, allowedUUIDs]);

  const isLoading = projectsLoading;

  useEffect(() => {
    setProjectUUIDState(getProjectUUID());
    setMounted(true);
  }, []);

  // Auto-switch to first allowed project if current selection is not accessible
  useEffect(() => {
    if (!mounted || projects.length === 0) return;
    const current = projectUUID;
    if (current && projects.some((p) => p.uuid === current)) return;
    // Current project not in filtered list — switch to first available
    const first = projects[0];
    if (first) {
      setProjectUUID(first.uuid);
      setProjectUUIDState(first.uuid);
    }
  }, [mounted, projects, projectUUID]);

  const setProject = useCallback(
    (uuid: string | null) => {
      const oldKey = getProjectUUID() ?? 'default';
      setProjectUUID(uuid);
      setProjectUUIDState(uuid);
      // Remove only queries scoped to the old project — new project queries will fetch fresh
      queryClient.removeQueries({ queryKey: [oldKey] });
    },
    [queryClient],
  );

  const createProject = useCallback(
    async (name: string, description?: string) => {
      const project = await createProjectMutation.mutateAsync({ name, description });
      setProject(project.uuid);
    },
    [createProjectMutation, setProject],
  );

  if (!mounted) return null;

  return (
    <ProjectContext.Provider
      value={{ projectUUID, projects, isLoading, setProject, createProject }}
    >
      {children}
    </ProjectContext.Provider>
  );
}

export function useProjectContext(): ProjectContextValue {
  const ctx = useContext(ProjectContext);
  if (!ctx) throw new Error('useProjectContext must be used within ProjectProvider');
  return ctx;
}
