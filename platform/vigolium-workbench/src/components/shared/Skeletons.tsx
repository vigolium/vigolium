'use client';

import type { CSSProperties, ReactNode } from 'react';

interface SkeletonProps {
  width?: number | string;
  height?: number | string;
  className?: string;
  style?: CSSProperties;
  rounded?: boolean;
}

export function Skeleton({ width, height = 12, className = '', style, rounded }: SkeletonProps) {
  return (
    <span
      className={`v-skeleton ${rounded ? 'rounded-full' : ''} ${className}`.trim()}
      style={{
        display: 'inline-block',
        width: typeof width === 'number' ? `${width}px` : width ?? '100%',
        height: typeof height === 'number' ? `${height}px` : height,
        ...style,
      }}
      aria-hidden="true"
    />
  );
}

interface TableSkeletonProps {
  rows?: number;
  columns?: Array<number | string>;
  showHeader?: boolean;
  className?: string;
}

export function TableSkeleton({
  rows = 10,
  columns = ['10%', '12%', '20%', '40%', '18%'],
  showHeader = true,
  className = '',
}: TableSkeletonProps) {
  return (
    <div className={`w-full ${className}`.trim()} aria-busy="true" aria-live="polite">
      {showHeader && (
        <div
          className="flex items-center gap-3 px-3 py-1.5 border-b"
          style={{ borderColor: 'var(--v-border)', backgroundColor: 'var(--v-surface)' }}
        >
          {columns.map((w, i) => (
            <Skeleton key={i} width={w} height={10} />
          ))}
        </div>
      )}
      {Array.from({ length: rows }).map((_, r) => (
        <div
          key={r}
          className="flex items-center gap-3 px-3 py-1.5 border-b"
          style={{
            borderColor: 'var(--v-border)',
            opacity: 1 - r * 0.05,
          }}
        >
          {columns.map((w, c) => (
            <Skeleton key={c} width={w} height={10} />
          ))}
        </div>
      ))}
    </div>
  );
}

interface ChartSkeletonProps {
  variant?: 'donut' | 'bar' | 'line';
  height?: number;
  label?: string;
  className?: string;
}

export function ChartSkeleton({
  variant = 'donut',
  height = 200,
  label,
  className = '',
}: ChartSkeletonProps) {
  if (variant === 'donut') {
    return (
      <div
        className={`flex items-center justify-center ${className}`.trim()}
        style={{ height }}
        aria-busy="true"
      >
        <div
          className="v-skeleton"
          style={{
            width: height * 0.7,
            height: height * 0.7,
            borderRadius: '9999px',
            mask: 'radial-gradient(circle, transparent 38%, black 40%)',
            WebkitMask: 'radial-gradient(circle, transparent 38%, black 40%)',
          }}
        />
        {label && (
          <span className="ml-3 text-xs" style={{ color: 'var(--v-text-muted)' }}>
            {label}
          </span>
        )}
      </div>
    );
  }
  if (variant === 'bar') {
    return (
      <div
        className={`flex items-end gap-1 ${className}`.trim()}
        style={{ height }}
        aria-busy="true"
      >
        {Array.from({ length: 12 }).map((_, i) => (
          <Skeleton
            key={i}
            width="100%"
            height={`${30 + ((i * 13) % 60)}%`}
            style={{ flex: 1 }}
          />
        ))}
      </div>
    );
  }
  return (
    <div className={`relative ${className}`.trim()} style={{ height }} aria-busy="true">
      <Skeleton width="100%" height="100%" />
    </div>
  );
}

interface CardSkeletonProps {
  lines?: number;
  title?: boolean;
  className?: string;
  children?: ReactNode;
}

export function CardSkeleton({ lines = 3, title = true, className = '', children }: CardSkeletonProps) {
  return (
    <div
      className={`p-3 border ${className}`.trim()}
      style={{ borderColor: 'var(--v-border)', backgroundColor: 'var(--v-surface)' }}
      aria-busy="true"
    >
      {title && <Skeleton width="40%" height={12} style={{ marginBottom: 8 }} />}
      {Array.from({ length: lines }).map((_, i) => (
        <div key={i} style={{ marginBottom: 6 }}>
          <Skeleton width={i === lines - 1 ? '60%' : '90%'} height={9} />
        </div>
      ))}
      {children}
    </div>
  );
}
