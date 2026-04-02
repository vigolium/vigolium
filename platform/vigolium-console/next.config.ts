import type { NextConfig } from 'next';

const isStatic = process.env.NEXT_PUBLIC_BUILD_MODE === 'static';

const nextConfig: NextConfig = {
  output: isStatic ? 'export' : undefined,
  // Use separate build directories so both dev servers can run simultaneously
  distDir: isStatic ? '.next-workbench' : '.next',
  trailingSlash: true,
  skipTrailingSlashRedirect: !isStatic,
  images: {
    unoptimized: true,
  },
  // In cloud mode, include .cloud.ts so API routes (route.cloud.ts) and
  // middleware (middleware.cloud.ts) are recognized by Next.js.
  // In static mode, only standard extensions are included — API routes and
  // middleware are excluded from the static export.
  pageExtensions: isStatic
    ? ['tsx', 'ts', 'jsx', 'js']
    : ['cloud.ts', 'cloud.tsx', 'tsx', 'ts', 'jsx', 'js'],
};

export default nextConfig;
