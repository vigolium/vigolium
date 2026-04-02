'use client';

import { useMemo } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  LayoutDashboard,
  ShieldAlert,
  Network,
  Radio,
  GitBranch,
  Blocks,
  Puzzle,
  Target,
  Import,
  Radar,
  Bot,
  SlidersHorizontal,
  Database,
  CreditCard,
  FolderKanban,
} from 'lucide-react';
import { isStaticBuild } from '@/lib/buildMode';
import { getHiddenPages } from '@/lib/nav-settings';

interface NavItem {
  href: string;
  label: string;
  icon: typeof LayoutDashboard;
  group: 'default' | 'blue' | 'orange';
}

/* ── Static/workbench mode: flat list ─────────────────────────────── */

const STATIC_NAV_ITEMS: NavItem[] = [
  { href: '/', label: 'DASHBOARD', icon: LayoutDashboard, group: 'default' },
  { href: '/findings', label: 'FINDINGS', icon: ShieldAlert, group: 'default' },
  { href: '/http-records', label: 'HTTP RECORDS', icon: Network, group: 'default' },
  { href: '/oast-interactions', label: 'OAST', icon: Radio, group: 'default' },
  { href: '/source-repos', label: 'REPOS', icon: GitBranch, group: 'default' },
  { href: '/modules', label: 'MODULES', icon: Blocks, group: 'blue' },
  { href: '/extensions', label: 'EXTENSIONS', icon: Puzzle, group: 'blue' },
  { href: '/scope', label: 'SCOPE', icon: Target, group: 'blue' },
  { href: '/ingest', label: 'INGEST', icon: Import, group: 'orange' },
  { href: '/scan', label: 'NATIVE SCAN', icon: Radar, group: 'orange' },
  { href: '/agentic-scan', label: 'AGENTIC SCAN', icon: Bot, group: 'orange' },
  { href: '/database', label: 'DATABASE', icon: Database, group: 'blue' },
  { href: '/settings', label: 'SETTINGS', icon: SlidersHorizontal, group: 'blue' },
];

/* ── Cloud/console mode: grouped nav ──────────────────────────────── */

const CLOUD_NAV_GROUPS: { label: string; items: NavItem[] }[] = [
  {
    label: 'Data',
    items: [
      { href: '/', label: 'DASHBOARD', icon: LayoutDashboard, group: 'default' },
      { href: '/findings', label: 'FINDINGS', icon: ShieldAlert, group: 'default' },
      { href: '/http-records', label: 'HTTP RECORDS', icon: Network, group: 'default' },
      { href: '/oast-interactions', label: 'OAST', icon: Radio, group: 'default' },
      { href: '/source-repos', label: 'REPOS', icon: GitBranch, group: 'default' },
    ],
  },
  {
    label: 'Scan',
    items: [
      { href: '/scope', label: 'SCOPE', icon: Target, group: 'blue' },
      { href: '/ingest', label: 'INGEST', icon: Import, group: 'orange' },
      { href: '/scan', label: 'NATIVE SCAN', icon: Radar, group: 'orange' },
      { href: '/agentic-scan', label: 'AGENTIC SCAN', icon: Bot, group: 'orange' },
    ],
  },
  {
    label: 'Admin',
    items: [
      { href: '/projects', label: 'PROJECTS', icon: FolderKanban, group: 'blue' },
      { href: '/billing', label: 'BILLING', icon: CreditCard, group: 'blue' },
      { href: '/settings', label: 'SETTINGS', icon: SlidersHorizontal, group: 'blue' },
    ],
  },
];

const GROUP_VAR: Record<string, string> = {
  default: '--v-accent',
  blue: '--v-secondary',
  orange: '--v-tertiary',
};

export default function Navigation() {
  const pathname = usePathname();

  // Filter hidden pages in cloud mode
  const filteredGroups = useMemo(() => {
    if (isStaticBuild) return CLOUD_NAV_GROUPS;
    const hidden = getHiddenPages();
    return CLOUD_NAV_GROUPS
      .map((group) => ({
        ...group,
        items: group.items.filter((item) => !hidden.has(item.href)),
      }))
      .filter((group) => group.items.length > 0);
  }, []);

  if (isStaticBuild) {
    return (
      <nav className="border-b" style={{ borderColor: 'var(--v-border)', backgroundColor: 'var(--v-bg)' }}>
        <div className="px-2 md:px-4 min-h-7 py-1 flex flex-wrap items-center text-xs leading-tight gap-y-1">
          <span style={{ color: 'var(--v-border)' }} className="mr-2 hidden md:inline">&gt;</span>
          {STATIC_NAV_ITEMS.map((item, i) => {
            const isActive = item.href === '/' ? pathname === '/' : pathname.startsWith(item.href);
            const colorVar = `var(${GROUP_VAR[item.group]})`;
            return (
              <span key={item.href} className="flex items-center">
                {i > 0 && <span style={{ color: 'var(--v-border)' }} className="mx-1 md:mx-2">|</span>}
                <Link
                  href={item.href}
                  className={`flex items-center gap-1 transition-colors whitespace-nowrap ${
                    isActive ? 'font-bold px-1.5 py-0.5 -my-0.5' : 'v-nav-link'
                  }`}
                  style={isActive ? {
                    color: colorVar,
                    backgroundColor: `color-mix(in srgb, ${colorVar} 10%, transparent)`,
                  } : undefined}
                  title={item.label}
                >
                  <item.icon className="w-3 h-3" />
                  {item.label}
                </Link>
              </span>
            );
          })}
        </div>
      </nav>
    );
  }

  return (
    <nav className="border-b" style={{ borderColor: 'var(--v-border)', backgroundColor: 'var(--v-bg)' }}>
      <div className="px-2 md:px-4 min-h-7 py-1 flex flex-wrap items-center text-xs leading-tight gap-y-1">
        {filteredGroups.map((group, gi) => (
          <div key={group.label} className="flex items-center">
            {gi > 0 && <span style={{ color: 'var(--v-border)' }} className="mx-2 md:mx-3 hidden md:inline">|</span>}
            <div className="flex items-center gap-0.5 md:gap-1">
              {group.items.map((item) => {
                const isActive = item.href === '/' ? pathname === '/' : pathname.startsWith(item.href);
                const colorVar = `var(${GROUP_VAR[item.group]})`;
                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    className={`flex items-center gap-1 transition-colors whitespace-nowrap px-1.5 py-0.5 ${
                      isActive ? 'font-bold' : 'v-nav-link'
                    }`}
                    style={isActive ? {
                      color: colorVar,
                      backgroundColor: `color-mix(in srgb, ${colorVar} 10%, transparent)`,
                    } : undefined}
                    title={item.label}
                  >
                    <item.icon className="w-3 h-3" />
                    <span className="hidden sm:inline">{item.label}</span>
                  </Link>
                );
              })}
            </div>
          </div>
        ))}
      </div>
    </nav>
  );
}
