import { BarChart3, Globe, Shield, FileText, BookOpen, Moon, Sun, Printer, Activity } from "lucide-react";
import { useTheme } from "../utils/theme";
import { LOGO_DATA_URL } from "../utils/logo";

export type TabId = "statistics" | "traffic" | "findings" | "report";

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
  { id: "report", label: "Full Report", icon: FileText },
  { id: "findings", label: "Findings", icon: Shield },
  { id: "traffic", label: "Traffic", icon: Activity },
];

function formatDate(value?: string): string {
  if (!value) {
    return new Date().toLocaleDateString(undefined, {
      weekday: "long",
      year: "numeric",
      month: "long",
      day: "numeric",
    });
  }
  const parsed = new Date(value);
  if (isNaN(parsed.getTime())) return value;
  return parsed.toLocaleDateString(undefined, {
    weekday: "long",
    year: "numeric",
    month: "long",
    day: "numeric",
  });
}

export default function Header({
  activeTab,
  onTabChange,
  findingsCount = 0,
  trafficCount = 0,
  reportTitle,
  generatedAt,
}: Props) {
  const { theme, toggle } = useTheme();
  const isDark = theme === "dark";

  return (
    <header className="topbar no-print">
      <div className="topbar-in">
        <a
          href="/"
          onClick={(e) => {
            e.preventDefault();
            onTabChange?.("statistics");
            history.replaceState(null, "", window.location.pathname + window.location.search);
          }}
          className="brand"
          style={{ textDecoration: "none" }}
        >
          <img src={LOGO_DATA_URL} alt="" className="mark" />
          {reportTitle || "Vigolium Report"}
        </a>

        {activeTab && onTabChange && (
          <nav>
            {tabs.map(({ id, label, icon: Icon }) => {
              const isActive = activeTab === id;
              const count = id === "findings" ? findingsCount : id === "traffic" ? trafficCount : 0;
              const showPill = (id === "findings" || id === "traffic") && count > 0;
              return (
                <button
                  key={id}
                  onClick={() => onTabChange(id)}
                  className={isActive ? "active" : ""}
                >
                  <Icon size={14} />
                  {label}
                  {showPill && <span className="pill">{count}</span>}
                </button>
              );
            })}
          </nav>
        )}

        {!activeTab && <div style={{ flex: 1 }} />}

        <div className="right">
          <a
            href="https://www.vigolium.com/"
            target="_blank"
            rel="noopener noreferrer"
            data-tooltip="Website"
          >
            <Globe size={14} />
            <span className="hidden lg:inline">Website</span>
          </a>
          <a
            href="https://docs.vigolium.com/"
            target="_blank"
            rel="noopener noreferrer"
            data-tooltip="Docs"
          >
            <BookOpen size={14} />
            <span className="hidden lg:inline">Docs</span>
          </a>
          <button
            className="theme-btn"
            onClick={toggle}
            aria-label={isDark ? "Switch to light mode" : "Switch to dark mode"}
            data-tooltip={isDark ? "Light mode" : "Dark mode"}
          >
            {isDark ? <Sun size={14} /> : <Moon size={14} />}
            <span className="hidden lg:inline">{isDark ? "Light" : "Dark"}</span>
          </button>
        </div>
      </div>
    </header>
  );
}
