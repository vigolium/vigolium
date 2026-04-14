import { Sun, Moon } from "lucide-react";
import { useTheme } from "../utils/theme";

export default function ThemeSwitcher() {
  const { theme, toggle } = useTheme();
  const isDark = theme === "dark";

  return (
    <button
      onClick={toggle}
      aria-label={isDark ? "Switch to light mode" : "Switch to dark mode"}
      className="flex items-center gap-1.5 px-2 py-1 rounded border border-warm-border text-text-muted hover:text-charcoal hover:border-terracotta/40 transition-colors text-[11px] font-sans"
      title={isDark ? "Switch to light mode" : "Switch to dark mode"}
    >
      {isDark ? <Sun size={12} /> : <Moon size={12} />}
      <span className="hidden sm:inline">{isDark ? "Light" : "Dark"}</span>
    </button>
  );
}
