import { type CSSProperties, type ReactNode } from "react";
import { type IconName } from "../Icon";
import Icon from "../Icon";

export interface SecurityPanelProps {
  children: ReactNode;
  title?: string;
  subtitle?: string;
  icon?: IconName;
  action?: ReactNode;
  variant?: "default" | "elevated" | "inspector" | "inline";
  className?: string;
  style?: CSSProperties;
  padding?: "none" | "sm" | "md" | "lg";
}

const VARIANT_CLASSES = {
  default: "panel",
  elevated: "panel-elevated",
  inspector: "panel-inspector",
  inline: "panel-inline",
};

const PADDING_CLASSES = {
  none: "p-none",
  sm: "p-sm",
  md: "p-md",
  lg: "p-lg",
};

export function SecurityPanel({
  children,
  title,
  subtitle,
  icon,
  action,
  variant = "default",
  className = "",
  style,
  padding = "md",
}: SecurityPanelProps) {
  return (
    <article
      className={`${VARIANT_CLASSES[variant]} ${PADDING_CLASSES[padding]} ${className}`}
      style={style}
    >
      {(title || icon || action) && (
        <div className="panel-header">
          <div className="panel-header-left">
            {icon && <Icon name={icon} size={16} className="panel-icon" />}
            {title && (
              <div className="panel-title-group">
                <h3 className="panel-title">{title}</h3>
                {subtitle && <p className="panel-subtitle">{subtitle}</p>}
              </div>
            )}
          </div>
          {action && <div className="panel-action">{action}</div>}
        </div>
      )}
      <div className="panel-body">{children}</div>
    </article>
  );
}

export interface PanelSectionProps {
  title: string;
  children: ReactNode;
  icon?: IconName;
  className?: string;
  collapsible?: boolean;
  defaultOpen?: boolean;
}

export function PanelSection({
  title,
  children,
  icon,
  className = "",
  collapsible = false,
  defaultOpen = true,
}: PanelSectionProps) {
  if (!collapsible) {
    return (
      <section className={`panel-section ${className}`}>
        <h4 className="panel-section-title">
          {icon && <Icon name={icon} size={13} />}
          {title}
        </h4>
        <div className="panel-section-body">{children}</div>
      </section>
    );
  }

  return (
    <details className={`panel-section collapsible ${className}`} open={defaultOpen}>
      <summary className="panel-section-summary">
        {icon && <Icon name={icon} size={13} />}
        <span>{title}</span>
        <Icon name="chevron-right" size={12} className="panel-section-chev" />
      </summary>
      <div className="panel-section-body">{children}</div>
    </details>
  );
}

export function PanelGrid({
  children,
  columns = "auto",
  gap = "md",
  className = "",
}: {
  children: ReactNode;
  columns?: number | "auto";
  gap?: "xs" | "sm" | "md" | "lg";
  className?: string;
}) {
  const columnStyle: CSSProperties = {
    gridTemplateColumns:
      columns === "auto" ? "repeat(auto-fit, minmax(200px, 1fr))" : `repeat(${columns}, 1fr)`,
    gap: `var(--s-${gap === "xs" ? 1 : gap === "sm" ? 2 : gap === "lg" ? 4 : 3})`,
  };

  return (
    <div className={`panel-grid ${className}`} style={columnStyle}>
      {children}
    </div>
  );
}

export function PanelRow({
  label,
  value,
  mono = false,
  trend,
  className = "",
}: {
  label: string;
  value: ReactNode;
  mono?: boolean;
  trend?: { value: number; label?: string };
  className?: string;
}) {
  return (
    <div className={`panel-row ${className}`}>
      <span className="panel-row-label">{label}</span>
      <div className="panel-row-value-group">
        <strong className={`panel-row-value ${mono ? "mono" : ""}`}>{value}</strong>
        {trend && (
          <span className={`panel-row-trend tone-${trend.value > 0 ? "danger" : trend.value < 0 ? "success" : "neutral"}`}>
            {trend.value > 0 ? "+" : ""}{trend.value}
            {trend.label && ` ${trend.label}`}
          </span>
        )}
      </div>
    </div>
  );
}

export function PanelKeyValue({
  items,
  className = "",
}: {
  items: Array<{ label: string; value: ReactNode; mono?: boolean }>;
  className?: string;
}) {
  return (
    <dl className={`panel-kv ${className}`}>
      {items.map((item, index) => (
        <div key={index} className="panel-kv-row">
          <dt className="panel-kv-label">{item.label}</dt>
          <dd className={`panel-kv-value ${item.mono ? "mono" : ""}`}>{item.value}</dd>
        </div>
      ))}
    </dl>
  );
}