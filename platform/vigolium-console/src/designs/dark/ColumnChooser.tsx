'use client';

import { useState, useEffect, useRef } from 'react';
import { Columns } from 'lucide-react';

interface ColumnOption {
  field: string;
  label: string;
}

interface ColumnChooserProps {
  columns: ColumnOption[];
  hiddenColumns: Set<string>;
  onChange: (hidden: Set<string>) => void;
}

export default function ColumnChooser({ columns, hiddenColumns, onChange }: ColumnChooserProps) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [open]);

  const hasHidden = hiddenColumns.size > 0;

  const toggle = (field: string) => {
    const next = new Set(hiddenColumns);
    if (next.has(field)) {
      next.delete(field);
    } else {
      next.add(field);
    }
    onChange(next);
  };

  return (
    <div ref={ref} className="relative">
      <button
        onClick={() => setOpen((p) => !p)}
        className={`border text-xs px-2 py-0.5 transition-colors flex items-center gap-1 ${
          hasHidden
            ? 'border-[#7fd962]/50 text-[#7fd962] hover:text-[#fce8c3] bg-[#1c1b19]'
            : 'border-[#2e2b26] text-[#918175] hover:text-[#fce8c3] bg-[#1c1b19]'
        }`}
      >
        <Columns className="w-3 h-3" />
        columns
        <span className="text-[8px]">{'\u25be'}</span>
      </button>
      {open && (
        <div className="absolute top-full right-0 mt-0.5 bg-[#1c1b19] border border-[#2e2b26] z-50 min-w-[160px]">
          {columns.map((col) => (
            <label
              key={col.field}
              className="flex items-center gap-2 px-2 py-0.5 text-xs text-[#918175] hover:bg-[#272520] hover:text-[#fce8c3] cursor-pointer transition-colors"
            >
              <input
                type="checkbox"
                checked={!hiddenColumns.has(col.field)}
                onChange={() => toggle(col.field)}
                className="accent-[#7fd962]"
              />
              {col.label}
            </label>
          ))}
        </div>
      )}
    </div>
  );
}
