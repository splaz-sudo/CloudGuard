import { type CSSProperties } from "react";
import { type IconName } from "../Icon";
import Icon from "../Icon";
import { type StatusVariant } from "./StatusBadge";

export interface MetricStripProps {
  label: string;
  value: string | number;
  icon?: IconName;
  trend?: {
    value: number;
    label?: string;
    period?: string;
  };
  tone?: StatusVariant;
  foot?: string;
  className?: string;
  compact?: boolean;
  "aria-label"?: string;
}

export function MetricStrip({
  label,
  value,
  icon,
  trend,
  tone,
  foot,
  className = "",
  compact = false,
  "aria-label": ariaLabel,
}: MetricStripProps) {
  const valueStr = String(value);

  return (
    <div
      className={`metric-strip ${compact ? "compact" : ""} ${className}`}
      role="status"
      aria-label={ariaLabel ?? `${label}: ${valueStr}${trend ? `, ${trend.value > 0 ? "up" : trend.value < 0 ? "down" : "unchanged"} ${trend.value}` : ""}`}
    >
      <div className="metric-strip-main">
        {icon && (
          <span className="metric-strip-icon">
            <Icon name={icon} size={compact ? 13 : 16} />
          </span>
        )}

        <div className="metric-strip-content">
          <span className="metric-strip-label">{label}</span>

          <div className="metric-strip-value-row">
            <strong
              className={`metric-strip-value ${tone ? `tone-${tone}` : ""}`}
            >
              {valueStr}
            </strong>

            {trend && (
              <span
                className={`metric-strip-trend tone-${
                  trend.value > 0 ? "danger" : trend.value < 0 ? "success" : "neutral"
                }`}
              >
                <span
                  style={{
                    display: "inline-flex",
                    transition: "transform 0.15s ease",
                    transform: trend.value < 0 ? "rotate(180deg)" : "none",
                  }}
                >
                  <Icon
                    name="chevron-right"
                    size={11}
                  />
                </span>
                <span>{Math.abs(trend.value)}</span>
                {trend.period && <span className="metric-strip-period">{trend.period}</span>}
              </span>
            )}
          </div>

          {foot && <span className="metric-strip-foot">{foot}</span>}
        </div>
      </div>
    </div>
  );
}

export interface StatCardProps {
  label: string;
  value: string | number;
  icon?: IconName;
  tone?: StatusVariant;
  foot?: string;
  badge?: React.ReactNode;
  className?: string;
  compact?: boolean;
  "aria-label"?: string;
}

export function StatCard({
  label,
  value,
  icon,
  tone,
  foot,
  badge,
  className = "",
  compact = false,
  "aria-label": ariaLabel,
}: StatCardProps) {
  const valueStr = String(value);

  return (
    <article
      className={`stat-card ${compact ? "compact" : ""} ${className}`}
      role="status"
      aria-label={ariaLabel ?? `${label}: ${valueStr}`}
    >
      <div className="stat-card-header">
        <span className="stat-card-label">
          {icon && <Icon name={icon} size={compact ? 12 : 14} />}
          {label}
        </span>
        {badge && <div className="stat-card-badge">{badge}</div>}
      </div>

      <strong className={`stat-card-value ${tone ? `tone-${tone}` : ""}`}>
        {valueStr}
      </strong>

      {foot && <span className="stat-card-foot">{foot}</span>}
    </article>
  );
}

export interface DeltaIndicatorProps {
  before: number;
  after: number;
  label?: string;
  max?: number;
  showValues?: boolean;
  className?: string;
  animate?: boolean;
  "aria-label"?: string;
}

export function DeltaIndicator({
  before,
  after,
  label,
  max = 100,
  showValues = true,
  className = "",
  animate = true,
  "aria-label": ariaLabel,
}: DeltaIndicatorProps) {
  const delta = after - before;
  const tone = delta > 0 ? "danger" : delta < 0 ? "success" : "neutral";
  const sign = delta > 0 ? `+${delta}` : delta < 0 ? `${delta}` : "±0";
  const beforePercent = max > 0 ? (before / max) * 100 : 0;
  const afterPercent = max > 0 ? (after / max) * 100 : 0;

  return (
    <div
      className={`delta-indicator ${className}`}
      role="img"
      aria-label={ariaLabel ?? `${label}: ${before} → ${after} (${sign})`}
    >
      {label && <span className="delta-label">{label}</span>}

      <div className="delta-bars">
        <div className="delta-bar-row">
          <span className="delta-bar-label">Before</span>
          <div className="delta-bar-track">
            <div
              className="delta-bar-fill"
              style={{
                width: `${beforePercent}%`,
                transition: animate
                  ? `width var(--dur-slow) var(--ease-out)`
                  : "none",
              } as CSSProperties}
            />
          </div>
          {showValues && <span className="delta-bar-value">{before}</span>}
        </div>

        <span className="delta-arrow" aria-hidden="true">→</span>

        <div className="delta-bar-row">
          <span className="delta-bar-label">After</span>
          <div className="delta-bar-track">
            <div
              className="delta-bar-fill"
              style={{
                width: `${afterPercent}%`,
                transition: animate
                  ? `width var(--dur-slow) var(--ease-out)`
                  : "none",
              } as CSSProperties}
            />
          </div>
          {showValues && <span className="delta-bar-value">{after}</span>}
        </div>
      </div>

      <span className={`delta-value tone-${tone}`}>{sign}</span>
    </div>
  );
}

export function MiniTrend({
  data,
  width = 80,
  height = 28,
  color = "var(--accent)",
  strokeWidth = 2,
  showPoints = false,
  className = "",
}: {
  data: number[];
  width?: number;
  height?: number;
  color?: string;
  strokeWidth?: number;
  showPoints?: boolean;
  className?: string;
}) {
  if (data.length < 2) {
    return <div className={`mini-trend ${className}`} style={{ width, height } as CSSProperties} />;
  }

  const min = Math.min(...data);
  const max = Math.max(...data);
  const range = max - min || 1;

  const points = data.map((value, index) => {
    const x = (index / (data.length - 1)) * width;
    const y = height - ((value - min) / range) * height;
    return `${x},${y}`;
  }).join(" ");

  const pathStyle: CSSProperties = {
    stroke: color,
    strokeWidth,
  };

  return (
    <svg
      className={`mini-trend ${className}`}
      width={width}
      height={height}
      viewBox={`0 0 ${width} ${height}`}
      aria-hidden="true"
    >
      <path
        d={`M${points}`}
        fill="none"
        style={pathStyle}
      />
      {showPoints &&
        data.map((value, index) => {
          const x = (index / (data.length - 1)) * width;
          const y = height - ((value - min) / range) * height;
          return (
            <circle
              key={index}
              cx={x}
              cy={y}
              r={3}
              fill={color}
            />
          );
        })}
    </svg>
  );
}