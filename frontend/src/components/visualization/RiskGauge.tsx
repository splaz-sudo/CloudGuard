import { type CSSProperties } from "react";
import { StatusBadge, type StatusVariant } from "./StatusBadge";

export interface RiskGaugeProps {
  score: number;
  size?: number;
  strokeWidth?: number;
  showValue?: boolean;
  showLabel?: boolean;
  label?: string;
  delta?: {
    value: number;
    label?: string;
  };
  variant?: StatusVariant;
  className?: string;
  animate?: boolean;
  "aria-label"?: string;
}

const RING_RADIUS = 52;
const RING_CIRCUMFERENCE = 2 * Math.PI * RING_RADIUS;

function riskBand(score: number): StatusVariant {
  if (score >= 75) return "critical";
  if (score >= 50) return "high";
  if (score >= 25) return "medium";
  return "low";
}

export function RiskGauge({
  score,
  size = 148,
  strokeWidth = 9,
  showValue = true,
  showLabel = false,
  label = "Risk Score",
  delta,
  variant: overrideVariant,
  className = "",
  animate = true,
  "aria-label": ariaLabel,
}: RiskGaugeProps) {
  const clamped = Math.max(0, Math.min(100, Math.round(score)));
  const band = overrideVariant ?? riskBand(clamped);
  const offset = RING_CIRCUMFERENCE * (1 - clamped / 100);

  const ringStyle = {
    "--ring-circumference": String(RING_CIRCUMFERENCE),
    "--ring-offset": String(offset),
  } as React.CSSProperties;

  return (
    <div
      className={`risk-gauge ${className}`}
      style={{ width: size, height: size } as CSSProperties}
      role="img"
      aria-label={ariaLabel ?? `Risk score ${clamped} out of 100, ${band} risk`}
    >
      {showLabel && (
        <div className="risk-gauge-label">
          <span className="eyebrow">{label}</span>
        </div>
      )}

      <svg
        className="risk-ring"
        viewBox="0 0 120 120"
        style={ringStyle}
      >
        <circle
          className="risk-ring-track"
          cx={60}
          cy={60}
          r={RING_RADIUS}
          strokeWidth={strokeWidth}
        />
        <circle
          className={`risk-ring-fill band-${band}`}
          cx={60}
          cy={60}
          r={RING_RADIUS}
          strokeWidth={strokeWidth}
          strokeDasharray={RING_CIRCUMFERENCE}
          strokeDashoffset={animate ? offset : RING_CIRCUMFERENCE}
          style={{
            transition: animate
              ? `stroke-dashoffset var(--dur-slow) var(--ease-out), stroke var(--dur-base) var(--ease-out)`
              : "none",
          }}
        />
      </svg>

      {showValue && (
        <div className="risk-gauge-center">
          <strong className="risk-gauge-value">{clamped}</strong>
          <span className="risk-gauge-max">/ 100</span>
        </div>
      )}

      <StatusBadge variant={band} size="md" showDot={false}>
        {band.charAt(0).toUpperCase() + band.slice(1)} risk
      </StatusBadge>

      {delta && (
        <div
          className={`risk-gauge-delta tone-${delta.value > 0 ? "danger" : delta.value < 0 ? "success" : "neutral"}`}
        >
          {delta.value > 0 ? `+${delta.value}` : delta.value < 0 ? `${delta.value}` : "±0"}
          {delta.label && ` ${delta.label}`}
        </div>
      )}
    </div>
  );
}

export function InlineRiskGauge({
  score,
  size = 48,
  strokeWidth = 4,
  className = "",
  "aria-label": ariaLabel,
}: {
  score: number;
  size?: number;
  strokeWidth?: number;
  className?: string;
  "aria-label"?: string;
}) {
  const clamped = Math.max(0, Math.min(100, Math.round(score)));
  const band = riskBand(clamped);
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference * (1 - clamped / 100);

  return (
    <div
      className={`inline-risk-gauge ${className}`}
      style={{ width: size, height: size } as CSSProperties}
      role="img"
      aria-label={ariaLabel ?? `Risk score ${clamped} out of 100`}
    >
      <svg viewBox="0 0 48 48">
        <circle
          className="risk-ring-track"
          cx={24}
          cy={24}
          r={radius}
          strokeWidth={strokeWidth}
        />
        <circle
          className={`risk-ring-fill band-${band}`}
          cx={24}
          cy={24}
          r={radius}
          strokeWidth={strokeWidth}
          strokeDasharray={circumference}
          strokeDashoffset={offset}
        />
      </svg>
      <span className="inline-risk-value">{clamped}</span>
    </div>
  );
}