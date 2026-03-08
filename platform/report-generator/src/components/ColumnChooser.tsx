import { useState, useRef, useEffect, useCallback } from "react";
import { ChevronDown, RotateCcw } from "lucide-react";

export interface ColumnOption {
  field: string;
  label: string;
}

interface Props {
  allColumns: ColumnOption[];
  visible: Set<string>;
  onChange: (visible: Set<string>) => void;
  defaults: Set<string>;
}

export default function ColumnChooser({ allColumns, visible, onChange, defaults }: Props) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  const handleOutsideClick = useCallback((e: MouseEvent) => {
    if (ref.current && !ref.current.contains(e.target as Node)) {
      setOpen(false);
    }
  }, []);

  useEffect(() => {
    if (open) {
      document.addEventListener("mousedown", handleOutsideClick);
      return () => document.removeEventListener("mousedown", handleOutsideClick);
    }
  }, [open, handleOutsideClick]);

  const toggle = (field: string) => {
    const next = new Set(visible);
    if (next.has(field)) {
      if (next.size > 1) next.delete(field);
    } else {
      next.add(field);
    }
    onChange(next);
  };

  const isDefault = visible.size === defaults.size && [...defaults].every((f) => visible.has(f));

  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        className="flex items-center gap-2 bg-cream border border-warm-border text-charcoal text-sm font-sans px-3 py-2 rounded-md hover:border-terracotta/40 transition-colors min-w-[120px] text-left"
      >
        <span className="flex-1 truncate">Columns ({visible.size})</span>
        <ChevronDown size={14} className={`text-text-muted shrink-0 transition-transform ${open ? "rotate-180" : ""}`} />
      </button>
      {open && (
        <div className="absolute right-0 z-50 mt-1 w-56 bg-cream border border-warm-border rounded-md shadow-lg overflow-hidden">
          {!isDefault && (
            <button
              type="button"
              onClick={() => onChange(new Set(defaults))}
              className="w-full flex items-center gap-2 px-3 py-2 text-xs font-sans text-terracotta hover:bg-cream-dark transition-colors border-b border-warm-border"
            >
              <RotateCcw size={12} />
              Reset to defaults
            </button>
          )}
          <div className="max-h-72 overflow-y-auto">
            {allColumns.map((col) => (
              <label
                key={col.field}
                className="flex items-center gap-2 px-3 py-1.5 text-sm font-sans text-charcoal hover:bg-cream-dark cursor-pointer transition-colors"
              >
                <input
                  type="checkbox"
                  checked={visible.has(col.field)}
                  onChange={() => toggle(col.field)}
                  className="accent-terracotta rounded"
                />
                <span className="truncate">{col.label}</span>
              </label>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
