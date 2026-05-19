'use client';

import { useState, useEffect, useRef } from 'react';

interface DropdownProps {
  value: string;
  options: { value: string; label: string }[];
  onChange: (value: string) => void;
  icon?: React.ReactNode;
}

export default function Dropdown({ value, options, onChange, icon }: DropdownProps) {
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

  const activeLabel = options.find((o) => o.value === value)?.label || value;
  const isDefault = value === '' || value === options[0]?.value;

  return (
    <div ref={ref} className="relative">
      <button
        onClick={() => setOpen((p) => !p)}
        className={`border text-xs px-2 py-0.5 transition-colors flex items-center gap-1 ${
          isDefault
            ? 'border-[#bbc3c4] text-[#708e8e] hover:text-[#005661] bg-[#f6edda]'
            : 'border-[#0078c8]/50 text-[#0078c8] hover:text-[#005661] bg-[#f6edda]'
        }`}
      >
        {icon}
        {activeLabel}
        <span className="text-[8px]">{'\u25be'}</span>
      </button>
      {open && (
        <div className="absolute top-full left-0 mt-0.5 bg-[#f6edda] border border-[#bbc3c4] z-50 min-w-full">
          {options.map((opt) => (
            <button
              key={opt.value}
              onClick={() => { onChange(opt.value); setOpen(false); }}
              className={`block w-full text-left text-xs px-2 py-0.5 transition-colors ${
                opt.value === value
                  ? 'text-[#0078c8]'
                  : 'text-[#708e8e] hover:bg-[#ede4d1] hover:text-[#005661]'
              }`}
            >
              {opt.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
