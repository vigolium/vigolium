'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  LayoutDashboard,
  ShieldAlert,
  Network,
  Radio,
  GitBranch,
  Target,
  Import,
  Radar,
  Bot,
  SlidersHorizontal,
  CreditCard,
  Users,
} from 'lucide-react';

const NAV_ITEMS = [
  { href: '/', label: 'DASHBOARD', icon: LayoutDashboard, group: 'default' as const },
  { href: '/findings', label: 'FINDINGS', icon: ShieldAlert, group: 'default' as const },
  { href: '/http-records', label: 'HTTP RECORDS', icon: Network, group: 'default' as const },
  { href: '/oast-interactions', label: 'OAST', icon: Radio, group: 'default' as const },
  { href: '/source-repos', label: 'REPOS', icon: GitBranch, group: 'default' as const },
  { href: '/scope', label: 'SCOPE', icon: Target, group: 'blue' as const },
  { href: '/ingest', label: 'INGEST', icon: Import, group: 'orange' as const },
  { href: '/scan', label: 'NATIVE SCAN', icon: Radar, group: 'orange' as const },
  { href: '/agents', label: 'AGENTIC SCAN', icon: Bot, group: 'orange' as const },
  { href: '/team', label: 'TEAM', icon: Users, group: 'blue' as const },
  { href: '/billing', label: 'BILLING', icon: CreditCard, group: 'blue' as const },
  { href: '/settings', label: 'SETTINGS', icon: SlidersHorizontal, group: 'blue' as const },
];

const GROUP_VAR: Record<string, string> = {
  default: '--v-accent',
  blue: '--v-secondary',
  orange: '--v-tertiary',
};

export default function Navigation() {
  const pathname = usePathname();

  return (
    <nav className="border-b" style={{ borderColor: 'var(--v-border)', backgroundColor: 'var(--v-bg)' }}>
      <div className="px-2 md:px-4 min-h-7 py-1 flex flex-wrap items-center text-xs leading-tight gap-y-1">
        <span style={{ color: 'var(--v-border)' }} className="mr-2 hidden md:inline">&gt;</span>
        {NAV_ITEMS.map((item, i) => {
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
