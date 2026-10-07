import { type CSSProperties } from "react";
import { type StatusVariant } from "./StatusBadge";

export interface RiskBarProps {
  score: number;
  max?: number;
  showValue?: boolean;
  showLabel?: boolean;
  label?: string;
  variant?: StatusVariant;
  height?: number;
  width?: string | number;
  className?: string;
  animate?: boolean;
  "aria-label"?: string;
}

function severityFromScore(score: number): StatusVariant {
  if (score >= 75) return "critical";
  if (score >= 50) return "high";
  if (score >= 25) return "medium";
  return "low";
}

export function RiskBar({
  score,
  max = 100,
  showValue = true,
  showLabel = false,
  label = "Risk",
  variant: overrideVariant,
  height = 6,
  width = "100%",
  className = "",
  animate = true,
  "aria-label": ariaLabel,
}: RiskBarProps) {
  const clamped = Math.max(0, Math.min(max, score));
  const percent = max > 0 ? (clamped / max) * 100 : 0;
  const band = overrideVariant ?? severityFromScore(clamped);

  const barStyle: CSSProperties = {
    width: `${percent}%`,
    height,
    transition: animate
      ? `width var(--dur-slow) var(--ease-out), background-color var(--dur-base) var(--ease-out)`
      : "none",
  };

  return (
    <div
      className={`riskbar-with-value ${className}`}
      style={{ width, minWidth: 72 } as CSSProperties}
      role="img"
      aria-label={ariaLabel ?? `${label}: ${Math.round(clamped)} out of ${max}`}
    >
      {showLabel && (
        <div className="riskbar-label-row">
          <span className="riskbar-label">{label}</span>
          {showValue && (
            <span className="riskbar-value">{Math.round(clamped)}</span>
          )}
        </div>
      )}

      <div className="riskbar" style={{ height } as CSSProperties}>
        <div
          className={`riskbar-fill sev-${band}`}
          style={barStyle}
        />
      </div>

      {!showLabel && showValue && (
        <span className="riskbar-value">{Math.round(clamped)}</span>
      )}
    </div>
  );
}

export function RiskBarWithDelta({
  before,
  after,
  max = 100,
  showValues = true,
  label = "Risk",
  className = "",
  animate = true,
}: {
  before: number;
  after: number;
  max?: number;
  showValues?: boolean;
  label?: string;
  className?: string;
  animate?: boolean;
}) {
  const delta = after - before;
  const tone = delta > 0 ? "danger" : delta < 0 ? "success" : "neutral";
  const sign = delta > 0 ? `+${delta}` : delta < 0 ? `${delta}` : "±0";

  return (
    <div className={`riskbar-delta ${className}`}>
      {label && <span className="riskbar-delta-label">{label}</span>}

      <div className="riskbar-delta-bars">
        <RiskBar
          score={before}
          max={max}
          showValue={showValues}
          showLabel={false}
          height={6}
          width="100%"
          animate={animate}
        />

        <span className="riskbar-delta-arrow" aria-hidden="true">→</span>

        <RiskBar
          score={after}
          max={max}
          showValue={showValues}
          showLabel={false}
          height={6}
          width="100%"
          animate={animate}
        />
      </div>

      <span className={`riskbar-delta-value tone-${tone}`}>
        {sign}
      </span>
    </div>
  );
}

export function SegmentedRiskBar({
  segments,
  height = 8,
  width = "100%",
  className = "",
  animate = true,
  "aria-label": ariaLabel,
}: {
  segments: Array<{ value: number; max: number; variant: StatusVariant; label?: string }>;
  height?: number;
  width?: string | number;
  className?: string;
  animate?: boolean;
  "aria-label"?: string;
}) {
  const total = segments.reduce((sum, s) => sum + s.max, 0);

  return (
    <div
      className={`segmented-riskbar ${className}`}
      style={{ width, height } as CSSProperties}
      role="img"
      aria-label={ariaLabel}
    >
      <div className="segmented-riskbar-track" style={{ height } as CSSProperties}>
        {segments.map((segment, index) => {
          const percent = total > 0 ? (segment.value / total) * 100 : 0;
          const segmentStyle: CSSProperties = {
            width: `${percent}%`,
            height: "100%",
            background: `var(--sev-${segment.variant})`,
            transition: animate
              ? `width var(--dur-slow) var(--ease-out)`
              : "none",
            borderRadius:
              index === 0
                ? `${height}px 0 0 ${height}px`
                : index === segments.length - 1
                ? `0 ${height}px ${height}px 0`
                : 0,
          };
          return (
            <div
              key={index}
              className="segmented-riskbar-segment"
              style={segmentStyle}
              title={segment.label ?? `${segment.variant}: ${segment.value}/${segment.max}`}
            />
          );
        })}
      </div>
    </div>
  );
}