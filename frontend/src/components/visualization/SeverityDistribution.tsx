import { type CSSProperties } from "react";
import { StatusBadge } from "./StatusBadge";

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface SeverityDistributionProps {
  severity: SeverityCounts;
  total?: number;
  showTotal?: boolean;
  showBars?: boolean;
  showCounts?: boolean;
  showLabels?: boolean;
  compact?: boolean;
  className?: string;
  animate?: boolean;
  "aria-label"?: string;
}

const SEVERITY_ROWS = [
  { key: "critical", label: "Critical", variant: "critical" as const },
  { key: "high", label: "High", variant: "high" as const },
  { key: "medium", label: "Medium", variant: "medium" as const },
  { key: "low", label: "Low", variant: "low" as const },
  { key: "info", label: "Info", variant: "info" as const },
] as const;

export function SeverityDistribution({
  severity,
  total,
  showTotal = true,
  showBars = true,
  showCounts = true,
  showLabels = true,
  compact = false,
  className = "",
  animate = true,
  "aria-label": ariaLabel,
}: SeverityDistributionProps) {
  const computedTotal = total ?? Object.values(severity).reduce((a, b) => a + b, 0);
  const max = Math.max(...Object.values(severity), 1);

  if (computedTotal === 0) {
    return (
      <div className={`severity-distribution empty ${className}`} role="status" aria-label={ariaLabel}>
        <StatusBadge variant="success" size="sm" showDot={true} icon="check">
          No findings
        </StatusBadge>
      </div>
    );
  }

  return (
    <div
      className={`severity-distribution ${compact ? "compact" : ""} ${className}`}
      role="img"
      aria-label={ariaLabel ?? `Findings by severity: ${SEVERITY_ROWS.map(r => `${severity[r.key as keyof SeverityCounts]} ${r.label}`).join(", ")}`}
    >
      {showLabels && (
        <div className="severity-header">
          {showTotal && (
            <StatusBadge variant="neutral" size="sm" showDot={false}>
              {computedTotal} total
            </StatusBadge>
          )}
        </div>
      )}

      <div className="severity-rows">
        {SEVERITY_ROWS.map((row) => {
          const value = severity[row.key];
          const width = value === 0 ? 0 : Math.max((value / max) * 100, value > 0 ? 4 : 0);

          const barStyle: CSSProperties = {
            width: `${width}%`,
            transition: animate
              ? `width var(--dur-slow) var(--ease-out)`
              : "none",
          };

          return (
            <div
              key={row.key}
              className={`sev-row ${compact ? "compact" : ""}`}
            >
              {showLabels && (
                <span className="sev-row-name">
                  <StatusBadge variant={row.variant} size="sm" showDot={true}>
                    {row.label}
                  </StatusBadge>
                </span>
              )}

              {showBars && (
                <span className="sev-row-track">
                  <span className={`sev-row-fill ${row.key}`} style={barStyle} />
                </span>
              )}

              {showCounts && (
                <span className="sev-row-count">{value}</span>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

export function SegmentedSeverityBar({
  severity,
  total,
  height = 10,
  width = "100%",
  className = "",
  animate = true,
  "aria-label": ariaLabel,
}: {
  severity: SeverityCounts;
  total?: number;
  height?: number;
  width?: string | number;
  className?: string;
  animate?: boolean;
  "aria-label"?: string;
}) {
  const computedTotal = total ?? Object.values(severity).reduce((a, b) => a + b, 0);

  if (computedTotal === 0) {
    return (
      <div
        className={`segmented-severity-bar empty ${className}`}
        style={{ width, height } as CSSProperties}
        role="img"
        aria-label={ariaLabel ?? "No findings"}
      >
        <div className="segmented-severity-segment success" style={{ width: "100%" }} />
      </div>
    );
  }

  return (
    <div
      className={`segmented-severity-bar ${className}`}
      style={{ width, height } as CSSProperties}
      role="img"
      aria-label={ariaLabel ?? `Findings by severity`}
    >
      <div className="segmented-severity-track" style={{ height } as CSSProperties}>
        {SEVERITY_ROWS.map((row, index) => {
          const value = severity[row.key];
          const percent = computedTotal > 0 ? (value / computedTotal) * 100 : 0;

          const segmentStyle: CSSProperties = {
            width: `${percent}%`,
            height: "100%",
            background: `var(--sev-${row.key})`,
            transition: animate
              ? `width var(--dur-slow) var(--ease-out)`
              : "none",
            borderRadius:
              index === 0
                ? `${height}px 0 0 ${height}px`
                : index === SEVERITY_ROWS.length - 1
                ? `0 ${height}px ${height}px 0`
                : 0,
          };

          return (
            <div
              key={row.key}
              className="segmented-severity-segment"
              style={segmentStyle}
              title={`${row.label}: ${value}`}
            />
          );
        })}
      </div>
    </div>
  );
}

export function SeverityLegend({
  severity,
  className = "",
}: {
  severity: SeverityCounts;
  className?: string;
}) {
  return (
    <div className={`severity-legend ${className}`}>
      {SEVERITY_ROWS.map((row) => {
        const value = severity[row.key];
        if (value === 0) return null;

        return (
          <span key={row.key} className="severity-legend-item">
            <StatusBadge variant={row.variant} size="sm" showDot={false}>
              {row.label.toUpperCase()}
            </StatusBadge>
            <span className="severity-legend-count">{value}</span>
          </span>
        );
      })}
    </div>
  );
}