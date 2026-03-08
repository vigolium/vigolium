'use client';

import { createContext, useContext, useState, useEffect, useCallback, type ReactNode } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { getProjectUUID, setProjectUUID } from '@/api/client';
import { useProjects, useCreateProject } from '@/api/hooks';
import type { Project } from '@/api/types';

interface ProjectContextValue {
  projectUUID: string | null;
  projects: Project[];
  isLoading: boolean;
  setProject: (uuid: string | null) => void;
  createProject: (name: string, description?: string) => Promise<void>;
}

const ProjectContext = createContext<ProjectContextValue | undefined>(undefined);

export function ProjectProvider({ children }: { children: ReactNode }) {
  const [projectUUID, setProjectUUIDState] = useState<string | null>(null);
  const [mounted, setMounted] = useState(false);
  const queryClient = useQueryClient();
  const { data: projects = [], isLoading } = useProjects();
  const createProjectMutation = useCreateProject();

  useEffect(() => {
    setProjectUUIDState(getProjectUUID());
    setMounted(true);
  }, []);

  const setProject = useCallback(
    (uuid: string | null) => {
      setProjectUUID(uuid);
      setProjectUUIDState(uuid);
      // Invalidate all queries so they refetch with the new project header
      queryClient.invalidateQueries();
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
