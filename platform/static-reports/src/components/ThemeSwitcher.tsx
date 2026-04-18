import { Sun, Moon } from "lucide-react";
import { useTheme } from "../utils/theme";

export default function ThemeSwitcher() {
  const { theme, toggle } = useTheme();
  const isDark = theme === "dark";

  return (
    <button
      onClick={toggle}
      aria-label={isDark ? "Switch to light mode" : "Switch to dark mode"}
      className="flex items-center gap-1.5 h-7 px-1.5 lg:px-2 rounded border border-warm-border/60 text-text-muted hover:text-charcoal hover:border-warm-border transition-colors text-[11px] font-sans"
      data-tooltip={isDark ? "Light mode" : "Dark mode"}
    >
      {isDark ? <Sun size={13} /> : <Moon size={13} />}
      <span className="hidden lg:inline">{isDark ? "Light" : "Dark"}</span>
    </button>
  );
}
