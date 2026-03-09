'use client';

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
  Settings,
  Target,
  Import,
  Radar,
  Bot,
} from 'lucide-react';

const NAV_ITEMS = [
  { href: '/', label: 'DASHBOARD', icon: LayoutDashboard },
  { href: '/findings', label: 'FINDINGS', icon: ShieldAlert },
  { href: '/http-records', label: 'HTTP RECORDS', icon: Network },
  { href: '/oast-interactions', label: 'OAST', icon: Radio },
  { href: '/source-repos', label: 'REPOS', icon: GitBranch },
  { href: '/modules', label: 'MODULES', icon: Blocks },
  { href: '/extensions', label: 'EXTENSIONS', icon: Puzzle },
  { href: '/config', label: 'CONFIG', icon: Settings },
  { href: '/scope', label: 'SCOPE', icon: Target },
  { href: '/ingest', label: 'INGEST', icon: Import },
  { href: '/scan', label: 'SCAN', icon: Radar },
  { href: '/agents', label: 'AGENTS', icon: Bot },
];

export default function Navigation() {
  const pathname = usePathname();

  return (
    <nav className="border-b border-[#bbc3c4] bg-[#f6edda]">
      <div className="px-4 min-h-7 py-0.5 flex flex-wrap items-center text-xs leading-tight">
        <span className="text-[#bbc3c4] mr-2">&gt;</span>
        {NAV_ITEMS.map((item, i) => (
          <span key={item.href} className="flex items-center">
            {i > 0 && <span className="text-[#bbc3c4] mx-2">|</span>}
            <Link
              href={item.href}
              className={`flex items-center gap-1 transition-colors ${
                (item.href === '/' ? pathname === '/' : pathname.startsWith(item.href))
                  ? 'text-[#9333ea] font-bold bg-[#9333ea]/10 px-1.5 py-0.5 -my-0.5'
                  : 'text-[#708e8e] hover:text-[#005661]'
              }`}
            >
              <item.icon className="w-3 h-3" />
              {item.label}
            </Link>
          </span>
        ))}
      </div>
    </nav>
  );
}
