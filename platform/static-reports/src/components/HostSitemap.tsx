import { useState } from "react";
import { Map, ChevronDown, ChevronUp, Search } from "lucide-react";

interface Props {
  hosts: { host: string; count: number }[];
  selectedHosts: Set<string>;
  onToggleHost: (host: string) => void;
  onClear: () => void;
}

export default function HostSitemap({ hosts, selectedHosts, onToggleHost, onClear }: Props) {
  const [open, setOpen] = useState(false);
  const [searchText, setSearchText] = useState("");

  const filteredHosts = searchText
    ? hosts.filter(({ host }) => host.toLowerCase().includes(searchText.toLowerCase()))
    : hosts;

  const handleToggle = () => {
    const next = !open;
    setOpen(next);
    if (!next) setSearchText("");
  };

  return (
    <div className="border border-warm-border rounded-md mb-4 overflow-hidden">
      <button
        onClick={handleToggle}
        className="flex items-center gap-2 w-full px-3 py-2 text-xs font-sans font-semibold text-text-muted hover:text-charcoal transition-colors"
      >
        <Map size={13} />
        <span>Sitemap</span>
        <span className="text-[10px] px-1.5 py-0.5 rounded bg-warm-border text-text-muted">
          {hosts.length}
        </span>
        {selectedHosts.size > 0 && (
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-terracotta/10 text-terracotta">
            {selectedHosts.size} selected
          </span>
        )}
        <div className="flex-1" />
        {open ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
      </button>

      {open && (
        <div className="px-3 pb-3 space-y-2">
          <div className="relative">
            <Search size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-text-muted" />
            <input
              type="text"
              value={searchText}
              onChange={(e) => setSearchText(e.target.value)}
              placeholder="Filter hosts..."
              className="w-full bg-cream border border-warm-border text-charcoal text-xs font-sans pl-7 pr-3 py-1 rounded-md focus:outline-none focus:border-terracotta/50 placeholder:text-text-muted"
            />
          </div>
          <div className="flex gap-2 overflow-x-auto">
            {filteredHosts.map(({ host, count }) => {
              const active = selectedHosts.has(host);
              return (
                <button
                  key={host}
                  onClick={() => onToggleHost(host)}
                  className={`shrink-0 px-2.5 py-1 rounded text-xs font-sans font-medium border transition-colors ${
                    active
                      ? "bg-terracotta/10 text-terracotta border-terracotta/30"
                      : "bg-cream border-warm-border text-text-muted hover:text-charcoal hover:border-terracotta/30"
                  }`}
                >
                  {host} <span className="opacity-60">({count})</span>
                </button>
              );
            })}
            {selectedHosts.size > 0 && (
              <button
                onClick={onClear}
                className="shrink-0 px-2 py-1 rounded text-xs font-sans font-medium text-text-muted hover:text-charcoal transition-colors"
              >
                Clear
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
