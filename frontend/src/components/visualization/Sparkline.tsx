import { type CSSProperties } from "react";

export interface SparklineProps {
  data: number[];
  width?: number;
  height?: number;
  color?: string;
  strokeWidth?: number;
  fill?: boolean;
  fillOpacity?: number;
  showPoints?: boolean;
  pointIndices?: number[];
  className?: string;
  "aria-label"?: string;
  animate?: boolean;
}

export function Sparkline({
  data,
  width = 120,
  height = 32,
  color = "var(--accent)",
  strokeWidth = 2,
  fill = false,
  fillOpacity = 0.15,
  showPoints = false,
  pointIndices = [],
  className = "",
  "aria-label": ariaLabel,
  animate = true,
}: SparklineProps) {
  if (data.length < 2) {
    return (
      <svg
        className={`sparkline ${className}`}
        width={width}
        height={height}
        viewBox={`0 0 ${width} ${height}`}
        aria-hidden="true"
      />
    );
  }

  const min = Math.min(...data);
  const max = Math.max(...data);
  const range = max - min || 1;

  const points = data.map((value, index) => {
    const x = (index / (data.length - 1)) * width;
    const y = height - ((value - min) / range) * height;
    return { x, y, value };
  });

  const pathD = points.map((p, i) => `${i === 0 ? "M" : "L"}${p.x.toFixed(2)} ${p.y.toFixed(2)}`).join(" ");

  const fillD = fill
    ? `${pathD} L${width} ${height} L0 ${height} Z`
    : undefined;

  const lineStyle: CSSProperties = {
    stroke: color,
    strokeWidth,
    fill: "none",
    transition: animate ? "stroke-dashoffset var(--dur-slow) var(--ease-out)" : "none",
  };

  const fillStyle: CSSProperties = {
    fill: color,
    fillOpacity,
    transition: animate ? "opacity var(--dur-slow) var(--ease-out)" : "none",
  };

  return (
    <svg
      className={`sparkline ${className}`}
      width={width}
      height={height}
      viewBox={`0 0 ${width} ${height}`}
      role="img"
      aria-label={ariaLabel ?? `Trend: ${data.join(", ")}`}
    >
      {fillD && <path d={fillD} style={fillStyle} />}
      <path d={pathD} style={lineStyle} />

      {showPoints && points.map((p, i) => (
        <circle
          key={i}
          cx={p.x}
          cy={p.y}
          r={pointIndices.includes(i) ? 4 : 3}
          fill={color}
          opacity={pointIndices.includes(i) ? 1 : 0.7}
        />
      ))}
    </svg>
  );
}

export interface MultiSparklineProps {
  series: Array<{
    data: number[];
    color: string;
    label: string;
  }>;
  width?: number;
  height?: number;
  strokeWidth?: number;
  className?: string;
  "aria-label"?: string;
}

export function MultiSparkline({
  series,
  width = 120,
  height = 32,
  strokeWidth = 2,
  className = "",
  "aria-label": ariaLabel,
}: MultiSparklineProps) {
  if (series.length === 0 || series[0].data.length < 2) {
    return <svg className={`sparkline ${className}`} width={width} height={height} aria-hidden="true" />;
  }

  const allData = series.flatMap(s => s.data);
  const min = Math.min(...allData);
  const max = Math.max(...allData);
  const range = max - min || 1;

  return (
    <svg
      className={`sparkline multi ${className}`}
      width={width}
      height={height}
      viewBox={`0 0 ${width} ${height}`}
      role="img"
      aria-label={ariaLabel}
    >
      {series.map((s, seriesIndex) => {
        const points = s.data.map((value, index) => {
          const x = (index / (s.data.length - 1)) * width;
          const y = height - ((value - min) / range) * height;
          return { x, y };
        });

        const pathD = points.map((p, i) => `${i === 0 ? "M" : "L"}${p.x.toFixed(2)} ${p.y.toFixed(2)}`).join(" ");

        return (
          <path
            key={seriesIndex}
            d={pathD}
            stroke={s.color}
            strokeWidth={strokeWidth}
            fill="none"
            style={{ transition: "stroke-dashoffset var(--dur-slow) var(--ease-out)" } as CSSProperties}
          />
        );
      })}
    </svg>
  );
}

export interface SparklineWithAxisProps extends SparklineProps {
  showMinMax?: boolean;
  showCurrent?: boolean;
  unit?: string;
}

export function SparklineWithAxis({
  data,
  width = 160,
  height = 40,
  color = "var(--accent)",
  strokeWidth = 2,
  showMinMax = true,
  showCurrent = true,
  unit = "",
  className = "",
  "aria-label": ariaLabel,
}: SparklineWithAxisProps) {
  if (data.length < 2) {
    return <div className={`sparkline-with-axis ${className}`} style={{ width, height } as CSSProperties} />;
  }

  const min = Math.min(...data);
  const max = Math.max(...data);
  const current = data[data.length - 1];
  const range = max - min || 1;

  const points = data.map((value, index) => {
    const x = (index / (data.length - 1)) * width;
    const y = height - ((value - min) / range) * height;
    return { x, y, value };
  });

  const pathD = points.map((p, i) => `${i === 0 ? "M" : "L"}${p.x.toFixed(2)} ${p.y.toFixed(2)}`).join(" ");

  return (
    <div className={`sparkline-with-axis ${className}`} style={{ width: width + 40, height: height + 20 } as CSSProperties}>
      <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} role="img" aria-label={ariaLabel}>
        <defs>
          <linearGradient id="sparkline-gradient" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={color} stopOpacity={0.3} />
            <stop offset="100%" stopColor={color} stopOpacity={0} />
          </linearGradient>
        </defs>

        <path
          d={`${pathD} L${width} ${height} L0 ${height} Z`}
          fill="url(#sparkline-gradient)"
          style={{ transition: "opacity var(--dur-slow) var(--ease-out)" } as CSSProperties}
        />
        <path d={pathD} stroke={color} strokeWidth={strokeWidth} fill="none" style={{ transition: "stroke-dashoffset var(--dur-slow) var(--ease-out)" } as CSSProperties} />

        {showCurrent && (
          <circle
            cx={points[points.length - 1].x}
            cy={points[points.length - 1].y}
            r={4}
            fill={color}
            stroke="var(--bg-app)"
            strokeWidth={2}
          />
        )}
      </svg>

      <div className="sparkline-axis">
        {showMinMax && (
          <>
            <span className="sparkline-max">{max}{unit}</span>
            <span className="sparkline-min">{min}{unit}</span>
          </>
        )}
        {showCurrent && (
          <span className="sparkline-current">{current}{unit}</span>
        )}
      </div>
    </div>
  );
}