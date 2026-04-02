'use client';

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { useState } from 'react';
import { ThemeProvider } from '@/contexts/ThemeContext';
import { ToastProvider } from '@/contexts/ToastContext';
import { ProjectProvider } from '@/contexts/ProjectContext';
import { isStaticBuild } from '@/lib/buildMode';
import AuthGate from '@/components/shared/AuthGate';
import './globals.css';

const title = isStaticBuild ? 'Vigolium Workbench' : 'Vigolium Cloud Console';

export default function RootLayout({ children }: { children: React.ReactNode }) {
  const [queryClient] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            retry: isStaticBuild ? 1 : false,
            refetchOnWindowFocus: false,
            staleTime: 10_000,
          },
        },
      })
  );

  const inner = (
    <ProjectProvider><ThemeProvider><ToastProvider>{children}</ToastProvider></ThemeProvider></ProjectProvider>
  );

  return (
    <html lang="en">
      <head>
        <title>{title}</title>
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <link rel="icon" href="/favicon.ico" sizes="any" />
      </head>
      <body className="antialiased">
        <QueryClientProvider client={queryClient}>
          {isStaticBuild ? <AuthGate>{inner}</AuthGate> : inner}
        </QueryClientProvider>
      </body>
    </html>
  );
}
