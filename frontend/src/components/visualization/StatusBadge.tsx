import type { IconName } from "../Icon";
import Icon from "../Icon";

export type StatusVariant =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "info"
  | "success"
  | "warning"
  | "danger"
  | "neutral"
  | "simulated"
  | "inferred"
  | "observed"
  | "new"
  | "resolved"
  | "unchanged"
  | "partial"
  | "unknown";

export type StatusSize = "sm" | "md" | "lg";

export interface StatusBadgeProps {
  children: React.ReactNode;
  variant: StatusVariant;
  size?: StatusSize;
  showDot?: boolean;
  icon?: IconName;
  className?: string;
  title?: string;
}

const VARIANT_CLASSES: Record<StatusVariant, string> = {
  critical: "sev-critical-bg sev-critical-border",
  high: "sev-high-bg",
  medium: "sev-medium-bg",
  low: "sev-low-bg",
  info: "sev-info-bg",
  success: "status-success",
  warning: "status-warning",
  danger: "status-danger",
  neutral: "status-neutral",
  simulated: "state-simulated",
  inferred: "state-inferred",
  observed: "state-observed",
  new: "change-new",
  resolved: "change-resolved",
  unchanged: "change-unchanged",
  partial: "change-partial",
  unknown: "change-unknown",
};

const SIZE_CLASSES: Record<StatusSize, string> = {
  sm: "status-badge-sm",
  md: "",
  lg: "status-badge-lg",
};

export function StatusBadge({
  children,
  variant,
  size = "md",
  showDot = true,
  icon,
  className = "",
  title,
}: StatusBadgeProps) {
  const variantClass = VARIANT_CLASSES[variant] ?? "";
  const sizeClass = SIZE_CLASSES[size];
  const dotClass = showDot ? "" : "no-dot";

  return (
    <span
      className={`status-badge ${variantClass} ${sizeClass} ${dotClass} ${className}`.trim()}
      title={title}
    >
      {icon && <Icon name={icon} size={size === "sm" ? 9 : size === "lg" ? 13 : 11} />}
      {children}
    </span>
  );
}

export function SeverityBadge({
  severity,
  size = "md",
  showDot = true,
  className = "",
}: {
  severity: string;
  size?: StatusSize;
  showDot?: boolean;
  className?: string;
}) {
  const normalized = severity.toLowerCase();
  const variantMap: Record<string, StatusVariant> = {
    critical: "critical",
    high: "high",
    medium: "medium",
    low: "low",
    info: "info",
  };
  const variant = variantMap[normalized] ?? "neutral";

  return (
    <StatusBadge
      variant={variant}
      size={size}
      showDot={showDot}
      className={className}
      title={severity}
    >
      {severity.toUpperCase()}
    </StatusBadge>
  );
}

export function ChangeStatusBadge({
  status,
  size = "md",
  showDot = true,
  className = "",
}: {
  status: "new" | "resolved" | "unchanged" | "partial" | "unknown";
  size?: StatusSize;
  showDot?: boolean;
  className?: string;
}) {
  return (
    <StatusBadge
      variant={status}
      size={size}
      showDot={showDot}
      className={className}
      title={status}
    >
      {status.toUpperCase()}
    </StatusBadge>
  );
}

export function SimulationBadge({
  size = "md",
  className = "",
}: {
  size?: StatusSize;
  className?: string;
}) {
  return (
    <StatusBadge
      variant="simulated"
      size={size}
      showDot={true}
      icon="info"
      className={className}
      title="Simulated — read-only, no cloud changes"
    >
      SIMULATED
    </StatusBadge>
  );
}