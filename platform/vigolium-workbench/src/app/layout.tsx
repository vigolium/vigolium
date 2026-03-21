'use client';

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { useState } from 'react';
import { ThemeProvider } from '@/contexts/ThemeContext';
import { ToastProvider } from '@/contexts/ToastContext';
import { ProjectProvider } from '@/contexts/ProjectContext';
import AuthGate from '@/components/shared/AuthGate';
import './globals.css';

export default function RootLayout({ children }: { children: React.ReactNode }) {
  const [queryClient] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            retry: 1,
            refetchOnWindowFocus: false,
            staleTime: 10_000,
          },
        },
      })
  );

  return (
    <html lang="en">
      <head>
        <title>Vigolium Workbench</title>
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <link rel="icon" href="/favicon.ico" sizes="any" />
      </head>
      <body className="antialiased">
        <QueryClientProvider client={queryClient}>
          <AuthGate>
            <ProjectProvider><ThemeProvider><ToastProvider>{children}</ToastProvider></ThemeProvider></ProjectProvider>
          </AuthGate>
        </QueryClientProvider>
      </body>
    </html>
  );
}
