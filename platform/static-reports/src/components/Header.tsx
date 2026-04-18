import { BarChart3, Globe, Shield, ExternalLink, BookOpen } from "lucide-react";
import ThemeSwitcher from "./ThemeSwitcher";

const logoUrl = "data:image/png;base64,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";

export type TabId = "statistics" | "traffic" | "findings";

interface Props {
  activeTab?: TabId;
  onTabChange?: (tab: TabId) => void;
  findingsCount?: number;
  trafficCount?: number;
  reportTitle?: string;
  generatedAt?: string;
}

const tabs: { id: TabId; label: string; icon: typeof BarChart3; iconOnly?: boolean }[] = [
  { id: "statistics", label: "Statistics", icon: BarChart3 },
  { id: "findings", label: "Findings", icon: Shield },
  { id: "traffic", label: "Traffic", icon: Globe, iconOnly: true },
];

export default function Header({ activeTab, onTabChange, findingsCount = 0, trafficCount = 0, reportTitle, generatedAt }: Props) {
  const date = generatedAt || new Date().toLocaleDateString("en-US", {
    weekday: "long",
    year: "numeric",
    month: "long",
    day: "numeric",
  });

  return (
    <header className="px-2 sm:px-4 flex items-stretch gap-0 border-b border-warm-border">
      <a
        href="/"
        onClick={(e) => {
          e.preventDefault();
          onTabChange?.("statistics");
          history.replaceState(null, "", window.location.pathname + window.location.search);
        }}
        className="flex items-center gap-1.5 sm:gap-2.5 py-2 sm:py-2.5 no-underline shrink-0"
      >
        <img src={logoUrl} alt="Vigolium" className="w-7 h-7 logo-glow" />
        <h1 className="font-serif text-sm font-bold text-charcoal tracking-tight">
          {reportTitle || "Vigolium Report"}
        </h1>
        <span className="hidden md:inline text-[11px] text-text-muted font-sans tracking-wide">
          {date}
        </span>
      </a>

      {activeTab && onTabChange && (
        <nav className="flex ml-2 sm:ml-4 gap-1.5 items-center">
          {tabs.map(({ id, label, icon: Icon, iconOnly }) => {
            const isActive = activeTab === id;
            const count = id === "findings" ? findingsCount : id === "traffic" ? trafficCount : 0;
            const hasData = count > 0;
            return (
              <button
                key={id}
                onClick={() => onTabChange(id)}
                aria-label={hasData ? `${label} (${count})` : label}
                {...(iconOnly ? { "data-tooltip": label } : {})}
                className={`group/tab flex items-center gap-1 sm:gap-1.5 px-2 sm:px-3 py-1.5 text-[11px] sm:text-xs font-sans font-semibold tracking-wide uppercase transition-colors relative whitespace-nowrap ${
                  !hasData
                    ? "text-text-muted/50 hover:text-text-muted"
                    : isActive
                    ? "text-charcoal"
                    : "text-text-muted hover:text-charcoal"
                }`}
              >
                <Icon size={13} />
                <span className={iconOnly ? "hidden lg:inline" : "hidden sm:inline"}>{label}</span>
                {hasData && (
                  <span className={`text-[10px] px-1.5 py-0.5 rounded inline-flex ${
                    isActive ? "bg-terracotta/10 text-terracotta" : "bg-warm-border text-text-muted"
                  }`}>
                    {count}
                  </span>
                )}
                {isActive && (
                  <span className="absolute bottom-0 left-0 right-0 h-0.5 bg-terracotta" />
                )}
              </button>
            );
          })}
        </nav>
      )}

      <div className="flex-1" />
      <div className="flex items-center gap-1 sm:gap-1.5 text-[11px] font-sans">
        <a href="https://www.vigolium.com/" aria-label="Website" data-tooltip="Website" className="flex items-center gap-1.5 h-7 px-1.5 lg:px-2 rounded border border-warm-border/60 text-text-muted hover:text-charcoal hover:border-warm-border transition-colors" target="_blank" rel="noopener noreferrer">
          <ExternalLink size={13} />
          <span className="hidden lg:inline">Website</span>
        </a>
        <a href="https://docs.vigolium.com/" aria-label="Docs" data-tooltip="Docs" className="flex items-center gap-1.5 h-7 px-1.5 lg:px-2 rounded border border-warm-border/60 text-text-muted hover:text-charcoal hover:border-warm-border transition-colors" target="_blank" rel="noopener noreferrer">
          <BookOpen size={13} />
          <span className="hidden lg:inline">Docs</span>
        </a>
        <ThemeSwitcher />
      </div>
    </header>
  );
}
