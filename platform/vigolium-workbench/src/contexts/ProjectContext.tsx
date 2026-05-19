'use client';

import { createContext, useContext, useState, useEffect, useCallback, useMemo, type ReactNode } from 'react';
import { usePathname, useRouter } from 'next/navigation';
import { useQueryClient } from '@tanstack/react-query';
import { ApiError, getProjectUUID, setProjectUUID } from '@/api/client';
import { useProjects, useCreateProject } from '@/api/hooks';
import { isCloudBuild, isStaticBuild } from '@/lib/buildMode';
import type { Project } from '@/api/types';

// Pre-auth surfaces — the user has no session yet, so /api/projects 403s and
// the "no usable project" bounce would loop them through /select-project →
// workos.com → /login?return_to=/select-project, hiding the actual login form.
// /on-demand-audit is also exempt: it's a public landing that handles its own
// auth state and auto-seeds the active project from currentUser.allowedProjects
// once the user signs in.
const AUTH_ENTRY_PATHS = new Set<string>([
  '/login',
  '/welcome',
  '/callback',
  '/unauthorized',
  '/on-demand-audit',
]);

interface ProjectContextValue {
  projectUUID: string | null;
  projects: Project[];
  isLoading: boolean;
  setProject: (uuid: string | null) => void;
  createProject: (name: string, description?: string) => Promise<void>;
}

const ProjectContext = createContext<ProjectContextValue | undefined>(undefined);

// Best-effort sync of the scanner row for a Convex-managed project. Called
// after every project switch in cloud mode so the scanner has a row keyed to
// the Convex UUID before any scoped query goes out. The endpoint is idempotent
// and returns 200 when the row already exists, so this is cheap.
//
// We don't surface failures via toast — the next scoped request will fail
// loud anyway — but we DO log to the console so a developer running the
// console without a scanner up sees why submits will eventually 502.
async function ensureScannerProject(uuid: string): Promise<void> {
  if (typeof window === 'undefined') return;
  const url = `${window.location.origin}/api/proxy/api/projects/${encodeURIComponent(uuid)}/ensure`;
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    });
    if (!res.ok) {
      const hint = res.status === 503
        ? ' — scan server is unreachable (is `bin/vigolium server` running on VIGOLIUM_SCAN_SERVER?)'
        : '';
      console.warn(
        `[vigolium] ensureScannerProject(${uuid}) failed: ${res.status} ${res.statusText}${hint}`,
      );
    }
  } catch (err) {
    console.warn(
      `[vigolium] ensureScannerProject(${uuid}) network error — scan server is unreachable (is \`bin/vigolium server\` running on VIGOLIUM_SCAN_SERVER?)`,
      err,
    );
  }
}

export function ProjectProvider({ children }: { children: ReactNode }) {
  const [projectUUID, setProjectUUIDState] = useState<string | null>(null);
  const [mounted, setMounted] = useState(false);
  const queryClient = useQueryClient();
  const router = useRouter();
  const pathname = usePathname();
  const { data, isLoading: projectsLoading, isError: projectsError } = useProjects();
  // Stabilize the projects ref. Without useMemo, `data: projects = []`
  // creates a fresh `[]` on every render whenever data is undefined (e.g.
  // while the listing is in error state), and any effect with `projects` in
  // its dep array re-fires every render — triggering Maximum-update-depth
  // loops once any setState lands.
  const projects = useMemo<Project[]>(() => data ?? [], [data]);
  const createProjectMutation = useCreateProject();

  useEffect(() => {
    setProjectUUIDState(getProjectUUID());
    setMounted(true);
  }, []);

  const setProject = useCallback(
    (uuid: string | null) => {
      const oldKey = getProjectUUID() ?? 'default';
      setProjectUUID(uuid);
      setProjectUUIDState(uuid);
      queryClient.removeQueries({ queryKey: [oldKey] });
      // Cloud mode: guarantee the scanner has a row for this Convex project
      // before any subsequent X-Project-UUID-bearing query goes out. Static
      // mode talks to the scanner directly and doesn't need this.
      if (uuid && isCloudBuild && !isStaticBuild) {
        void ensureScannerProject(uuid);
      }
    },
    [queryClient],
  );

  // Auto-switch to first project if current selection is not in the list.
  useEffect(() => {
    if (!mounted || projects.length === 0) return;
    if (projectUUID && projects.some((p) => p.uuid === projectUUID)) return;
    const first = projects[0];
    if (first) setProject(first.uuid);
  }, [mounted, projects, projectUUID, setProject]);

  // Cloud mode: bounce to /select-project whenever the user has no usable
  // project — listing is empty, OR listing failed (e.g. 403 from a stale
  // projectUUID gating a non-bootstrap path). Clear the stale UUID so the
  // next request doesn't keep tripping the gate.
  useEffect(() => {
    if (!isCloudBuild) return;
    if (!mounted || projectsLoading) return;
    if (AUTH_ENTRY_PATHS.has(pathname)) return;
    const noUsableProject = projectsError || projects.length === 0;
    if (!noUsableProject) return;
    if (projectUUID) {
      setProjectUUID(null);
      setProjectUUIDState(null);
    }
    if (pathname !== '/select-project') {
      router.replace('/select-project');
    }
  }, [mounted, projectsLoading, projectsError, projects.length, projectUUID, pathname, router]);

  const createProject = useCallback(
    async (name: string, description?: string) => {
      try {
        const project = await createProjectMutation.mutateAsync({ name, description });
        setProject(project.uuid);
      } catch (err) {
        // Any 403 here means the user is in a bad project-state (stale
        // localStorage, lost access, etc.) — drop them onto /select-project.
        if (err instanceof ApiError && err.code === 403) {
          setProjectUUID(null);
          setProjectUUIDState(null);
          if (pathname !== '/select-project' && !AUTH_ENTRY_PATHS.has(pathname)) {
            router.replace('/select-project');
          }
        }
        throw err;
      }
    },
    [createProjectMutation, setProject, pathname, router],
  );

  const value = useMemo<ProjectContextValue>(
    () => ({ projectUUID, projects, isLoading: projectsLoading, setProject, createProject }),
    [projectUUID, projects, projectsLoading, setProject, createProject],
  );

  // Render children immediately. The mounted flag still gates the side-effects
  // below (getProjectUUID(), the auto-switch and bounce-to-select-project
  // effects) so they don't run before localStorage is available — but we no
  // longer hide the entire app while waiting, which produced a blank-page
  // window on cold loads (e.g. browser back from a non-SPA route handler).
  return (
    <ProjectContext.Provider value={value}>
      {children}
    </ProjectContext.Provider>
  );
}

export function useProjectContext(): ProjectContextValue {
  const ctx = useContext(ProjectContext);
  if (!ctx) throw new Error('useProjectContext must be used within ProjectProvider');
  return ctx;
}
