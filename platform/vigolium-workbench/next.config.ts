import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  allowedDevOrigins: ['host.docker.internal', 'local-testing.vigolium.com'],
  output: 'export',
  distDir: 'dist',
  trailingSlash: true,
  skipTrailingSlashRedirect: false,
  images: {
    unoptimized: true,
  },
};

export default nextConfig;
