/**
 * @vitest-environment happy-dom
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderHook, waitFor, act } from '@testing-library/react';
import type { ReactNode } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

// Mock the navigation hooks before any imports that depend on them.
const replaceMock = vi.fn();
let pathnameValue = '/findings';
vi.mock('next/navigation', () => ({
  useRouter: () => ({ replace: replaceMock, push: vi.fn(), back: vi.fn() }),
  usePathname: () => pathnameValue,
}));

// Mock the projects/createProject hooks so we control what the context sees.
// In cloud mode the data shape is the Convex-backed Project list — the context
// doesn't fetch from the scanner anymore, so this mock stands in for the
// /api/projects handler's response.
let projectsMock: {
  data: Array<{ uuid: string; name: string }>;
  isLoading: boolean;
  isError: boolean;
} = { data: [], isLoading: false, isError: false };

vi.mock('@/api/hooks', () => ({
  useProjects: () => projectsMock,
  useCreateProject: () => ({
    mutateAsync: vi.fn(async ({ name }: { name: string }) => ({
      uuid: 'created-uuid',
      name,
      description: '',
    })),
  }),
}));

import { ProjectProvider, useProjectContext } from '../ProjectContext';
import { setProjectUUID, getProjectUUID } from '@/api/client';

function wrapper({ children }: { children: ReactNode }) {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return (
    <QueryClientProvider client={qc}>
      <ProjectProvider>{children}</ProjectProvider>
    </QueryClientProvider>
  );
}

const projA = { uuid: 'aaa', name: 'A' };
const projB = { uuid: 'bbb', name: 'B' };

beforeEach(() => {
  replaceMock.mockReset();
  pathnameValue = '/findings';
  setProjectUUID(null);
  projectsMock = { data: [], isLoading: false, isError: false };
  // ensureScannerProject() POSTs in cloud mode — stub fetch so it doesn't
  // hit a real network in the test environment.
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('{}', { status: 200 }));
});

describe('ProjectContext', () => {
  it('exposes projects from useProjects', async () => {
    projectsMock = { data: [projA], isLoading: false, isError: false };
    setProjectUUID('aaa');
    const { result } = renderHook(() => useProjectContext(), { wrapper });

    await waitFor(() => {
      expect(result.current.projects).toHaveLength(1);
    });
    expect(result.current.projects[0].uuid).toBe('aaa');
    expect(result.current.projectUUID).toBe('aaa');
  });

  it('auto-switches to the first project when the stored UUID is not in the list', async () => {
    projectsMock = { data: [projA, projB], isLoading: false, isError: false };
    setProjectUUID('stale-uuid-not-in-list');

    const { result } = renderHook(() => useProjectContext(), { wrapper });

    await waitFor(() => {
      expect(result.current.projectUUID).toBe('aaa');
    });
    expect(getProjectUUID()).toBe('aaa');
  });

  it('keeps the current UUID when it IS in the list', async () => {
    projectsMock = { data: [projA, projB], isLoading: false, isError: false };
    setProjectUUID('bbb');

    const { result } = renderHook(() => useProjectContext(), { wrapper });

    await waitFor(() => {
      expect(result.current.projectUUID).toBe('bbb');
    });
    expect(replaceMock).not.toHaveBeenCalled();
  });

  it('setProject clears the old project queries and updates the UUID', async () => {
    projectsMock = { data: [projA, projB], isLoading: false, isError: false };
    setProjectUUID('aaa');

    const { result } = renderHook(() => useProjectContext(), { wrapper });
    await waitFor(() => expect(result.current.projectUUID).toBe('aaa'));

    act(() => result.current.setProject('bbb'));

    expect(getProjectUUID()).toBe('bbb');
    expect(result.current.projectUUID).toBe('bbb');
  });
});
