import { Printer, Download, FileArchive } from "lucide-react";
import type { ReactNode } from "react";

interface TitleField {
  label: string;
  value: ReactNode;
}

type ActionIcon = "print" | "download" | "archive";

const ICONS: Record<ActionIcon, typeof Printer> = {
  print: Printer,
  download: Download,
  archive: FileArchive,
};

interface ButtonAction {
  label: string;
  icon?: ActionIcon;
  onClick: () => void;
}

interface LinkAction {
  label: string;
  icon?: ActionIcon;
  href: string;
  highlight?: boolean;
}

interface Props {
  title: string;
  subtitle?: ReactNode;
  eyebrow?: ReactNode;
  lede?: string;
  metaTitle?: string;
  titleBlock?: TitleField[];
  action?: ButtonAction;
  secondaryAction?: LinkAction;
}

export default function Hero({ title, subtitle, eyebrow, lede, metaTitle, titleBlock, action, secondaryAction }: Props) {
  const Icon = ICONS[action?.icon ?? "print"];
  const SecondaryIcon = ICONS[secondaryAction?.icon ?? "archive"];

  return (
    <section className="cartouche">
      <span className="reg tl" />
      <span className="reg tr" />
      <span className="reg bl" />
      <span className="reg br" />
      <div className="cartouche-main">
        {eyebrow && <div className="eyebrow">{eyebrow}</div>}
        <h1 className="cartouche-title">{title}</h1>
        {subtitle && <div className="cartouche-sub">{subtitle}</div>}
        {lede && <p className="cartouche-lede">{lede}</p>}
        {(action || secondaryAction) && (
          <div className="cartouche-actions">
            {action && (
              <button className="btn-pdf no-print" onClick={action.onClick}>
                <Icon size={14} />
                {action.label}
              </button>
            )}
            {secondaryAction && (
              <a
                className={`btn-pdf btn-pdf--accent no-print${secondaryAction.highlight ? " btn-pdf--filled" : ""}`}
                href={secondaryAction.href}
                target="_blank"
                rel="noopener noreferrer"
              >
                <SecondaryIcon size={14} />
                {secondaryAction.label}
              </a>
            )}
          </div>
        )}
      </div>
      {titleBlock && titleBlock.length > 0 && (
        <div className="cartouche-meta">
          <h4 className="cartouche-meta-title">{metaTitle || title}</h4>
          {titleBlock.map((f, i) => (
            <div key={i} className="cartouche-field">
              <span className="cartouche-field-k">{f.label}</span>
              <span className="cartouche-field-v">{f.value}</span>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
