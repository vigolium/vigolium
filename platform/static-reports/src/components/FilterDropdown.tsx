import { useState, useRef, useEffect, useCallback } from "react";
import { ChevronDown } from "lucide-react";

interface Option {
  value: string;
  label: string;
}

interface Props {
  value: string;
  onChange: (value: string) => void;
  options: Option[];
  placeholder?: string;
  shortLabel?: string;
}

export default function FilterDropdown({ value, onChange, options, placeholder, shortLabel }: Props) {
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

  const selectedLabel = options.find((o) => o.value === value)?.label ?? placeholder ?? value;
  const isDefault = value === "all" || value === options[0]?.value;

  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        className="flex items-center gap-1 sm:gap-1.5 bg-cream border border-warm-border text-charcoal text-[11px] sm:text-xs font-sans px-1.5 sm:px-2.5 py-1 sm:py-1.5 rounded-md hover:border-terracotta/40 transition-colors min-w-0 sm:min-w-[100px] text-left"
      >
        {shortLabel && isDefault ? (
          <>
            <span className="flex-1 truncate lg:hidden">{shortLabel}</span>
            <span className="flex-1 truncate hidden lg:inline">{selectedLabel}</span>
          </>
        ) : (
          <span className="flex-1 truncate">{selectedLabel}</span>
        )}
        <ChevronDown size={12} className={`text-text-muted shrink-0 transition-transform ${open ? "rotate-180" : ""}`} />
      </button>
      {open && (
        <div className="absolute z-50 mt-1 w-full min-w-[160px] bg-cream border border-warm-border rounded-md shadow-lg overflow-hidden">
          {options.map((opt) => (
            <button
              key={opt.value}
              type="button"
              onClick={() => { onChange(opt.value); setOpen(false); }}
              className={`w-full text-left px-2.5 py-1.5 text-xs font-sans transition-colors ${
                opt.value === value
                  ? "bg-terracotta/10 text-terracotta font-semibold"
                  : "text-charcoal hover:bg-cream-dark"
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
