import { BarChart3, Globe, Shield, ExternalLink, BookOpen } from "lucide-react";
import ThemeSwitcher from "./ThemeSwitcher";
import logoUrl from "../assets/logo.png";

export type TabId = "statistics" | "traffic" | "findings";

interface Props {
  activeTab?: TabId;
  onTabChange?: (tab: TabId) => void;
  findingsCount?: number;
  trafficCount?: number;
  reportTitle?: string;
  generatedAt?: string;
}

const tabs: { id: TabId; label: string; icon: typeof BarChart3 }[] = [
  { id: "statistics", label: "Statistics", icon: BarChart3 },
  { id: "traffic", label: "HTTP Traffic", icon: Globe },
  { id: "findings", label: "Findings", icon: Shield },
];

export default function Header({ activeTab, onTabChange, findingsCount = 0, trafficCount = 0, reportTitle, generatedAt }: Props) {
  const date = generatedAt || new Date().toLocaleDateString("en-US", {
    weekday: "long",
    year: "numeric",
    month: "long",
    day: "numeric",
  });

  return (
    <header className="px-4 flex items-stretch gap-0 border-b border-warm-border">
      <div className="flex items-center gap-2.5 py-2.5">
        <img src={logoUrl} alt="Vigolium" className="w-7 h-7 logo-glow" />
        <h1 className="font-serif text-sm font-bold text-charcoal tracking-tight">
          {reportTitle || "Vigolium Report"}
        </h1>
        <span className="text-[11px] text-text-muted font-sans tracking-wide">
          {date}
        </span>
      </div>

      {activeTab && onTabChange && (
        <nav className="flex ml-4 gap-0">
          {tabs.map(({ id, label, icon: Icon }) => {
            const isActive = activeTab === id;
            const count = id === "findings" ? findingsCount : id === "traffic" ? trafficCount : 0;
            return (
              <button
                key={id}
                onClick={() => onTabChange(id)}
                className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-sans font-semibold tracking-wide uppercase transition-colors relative ${
                  isActive
                    ? "text-charcoal"
                    : "text-text-muted hover:text-charcoal"
                }`}
              >
                <Icon size={13} />
                {label}
                {count > 0 && (
                  <span className={`text-[10px] px-1.5 py-0.5 rounded ${
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
      <div className="flex items-center gap-1.5 text-[11px] font-sans">
        <a href="https://www.vigolium.com/" className="flex items-center gap-1.5 px-2 py-1 rounded border border-warm-border text-terracotta hover:text-charcoal hover:border-terracotta/40 transition-colors" target="_blank" rel="noopener noreferrer">
          <ExternalLink size={12} />
          Website
        </a>
        <a href="https://docs.vigolium.com/" className="flex items-center gap-1.5 px-2 py-1 rounded border border-warm-border text-terracotta hover:text-charcoal hover:border-terracotta/40 transition-colors" target="_blank" rel="noopener noreferrer">
          <BookOpen size={12} />
          Docs
        </a>
        <ThemeSwitcher />
      </div>
    </header>
  );
}
