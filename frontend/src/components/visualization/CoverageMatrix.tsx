import { type CSSProperties } from "react";
import { type IconName } from "../Icon";
import Icon from "../Icon";
import { StatusBadge } from "./StatusBadge";
import { MetricStrip } from "./MetricStrip";

export type CollectorStatus = "success" | "partial" | "failed";

export interface CollectorResult {
  collector: string;
  service: string;
  region: string | null;
  status: CollectorStatus;
  resourcesDiscovered: number;
  durationMs: number;
  errorCategory: string | null;
  errorMessage: string | null;
  coverageLimitation: string | null;
}

export interface CoverageMatrixProps {
  results: CollectorResult[];
  className?: string;
  showLegend?: boolean;
  compact?: boolean;
}

const STATUS_META: Record<CollectorStatus, { label: string; icon: IconName; variant: "success" | "warning" | "danger" }> = {
  success: { label: "SUCCESS", icon: "check", variant: "success" },
  partial: { label: "PARTIAL", icon: "warning", variant: "warning" },
  failed: { label: "FAILED", icon: "alert", variant: "danger" },
};

export function CoverageMatrix({
  results,
  className = "",
  showLegend = true,
  compact = false,
}: CoverageMatrixProps) {
  const attempted = results.length;
  const successful = results.filter((r) => r.status === "success").length;
  const partial = results.filter((r) => r.status === "partial").length;
  const failed = results.filter((r) => r.status === "failed").length;
  const totalResources = results.reduce((sum, r) => sum + r.resourcesDiscovered, 0);

  const percent = (part: number, whole: number) => whole === 0 ? "0%" : `${Math.round((part / whole) * 100)}%`;

  return (
    <section className={`coverage-matrix ${compact ? "compact" : ""} ${className}`}>
      <div className="coverage-matrix-header">
        <h3 className="coverage-matrix-title">Collection Coverage</h3>
        <div className="coverage-matrix-summary">
          <MetricStrip label="Attempted" value={attempted} icon="coverage" />
          <MetricStrip label="Resources" value={totalResources} icon="inventory" />
        </div>
      </div>

      <div className="coverage-health-bar" role="img" aria-label={`Collector outcomes: ${successful} successful, ${partial} partial, ${failed} failed out of ${attempted} attempted`}>
        <div
          className="coverage-health-segments"
          style={{ display: "flex", height: 10, borderRadius: "var(--r-pill)", overflow: "hidden", background: "var(--bg-inset)" } as CSSProperties}
        >
          {successful > 0 && (
            <div
              className="coverage-health-seg success"
              style={{
                width: `${(successful / attempted) * 100}%`,
                height: "100%",
                background: "var(--success)",
                transition: "width var(--dur-slow) var(--ease-out)",
              } as CSSProperties}
              title={`Successful: ${successful}`}
            />
          )}
          {partial > 0 && (
            <div
              className="coverage-health-seg partial"
              style={{
                width: `${(partial / attempted) * 100}%`,
                height: "100%",
                background: "var(--warning)",
                transition: "width var(--dur-slow) var(--ease-out)",
              } as CSSProperties}
              title={`Partial: ${partial}`}
            />
          )}
          {failed > 0 && (
            <div
              className="coverage-health-seg failed"
              style={{
                width: `${(failed / attempted) * 100}%`,
                height: "100%",
                background: "var(--danger)",
                transition: "width var(--dur-slow) var(--ease-out)",
              } as CSSProperties}
              title={`Failed: ${failed}`}
            />
          )}
        </div>

        {showLegend && (
          <div className="coverage-health-legend">
            <span className="coverage-legend-item">
              <span className="coverage-legend-swatch success" aria-hidden="true" />
              Successful — {successful} of {attempted} ({percent(successful, attempted)})
            </span>
            <span className="coverage-legend-item">
              <span className="coverage-legend-swatch partial" aria-hidden="true" />
              Partial — {partial} of {attempted} ({percent(partial, attempted)})
            </span>
            <span className="coverage-legend-item">
              <span className="coverage-legend-swatch failed" aria-hidden="true" />
              Failed — {failed} of {attempted} ({percent(failed, attempted)})
            </span>
          </div>
        )}
      </div>

      <div className="coverage-table-wrap">
        <table className="coverage-table data-table">
          <thead>
            <tr>
              <th scope="col">Service</th>
              <th scope="col">Region</th>
              <th scope="col">Status</th>
              <th scope="col" className="num">Resources</th>
              <th scope="col" className="num">Duration</th>
              <th scope="col">Error / Limitation</th>
            </tr>
          </thead>
          <tbody>
            {results.map((result) => {
              const meta = STATUS_META[result.status];
              return (
                <tr key={`${result.collector}-${result.service}-${result.region ?? "global"}`}>
                  <td className="cell-strong">
                    {result.service}
                    <span className="coverage-collector mono">{result.collector}</span>
                  </td>
                  <td>
                    {result.region ?? <span className="muted">Global</span>}
                  </td>
                  <td>
                    <StatusBadge
                      variant={meta.variant}
                      size="sm"
                      icon={meta.icon}
                      showDot={false}
                    >
                      {meta.label}
                    </StatusBadge>
                  </td>
                  <td className="cell-num">{result.resourcesDiscovered}</td>
                  <td className="cell-num">{result.durationMs.toFixed(0)} ms</td>
                  <td className="coverage-detail-cell">
                    {result.errorMessage ? (
                      <span className="coverage-cell-error truncate" title={result.errorMessage}>
                        {result.errorMessage}
                      </span>
                    ) : result.coverageLimitation ? (
                      <span className="coverage-cell-warn truncate" title={result.coverageLimitation}>
                        {result.coverageLimitation}
                      </span>
                    ) : (
                      <span className="muted">—</span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}

export function CoverageLimitations({
  className = "",
}: {
  className?: string;
}) {
  const limitations = [
    { title: "Cross-account resources", detail: "are not scanned unless cross-account roles are configured." },
    { title: "Regional services", detail: "are only scanned in configured regions; global services (IAM, CloudFront) are scanned once." },
    { title: "AccessDenied errors", detail: "indicate missing permissions; the affected resources were not scanned." },
    { title: "Service quotas", detail: "may limit results for large accounts (e.g. EC2 DescribeInstances)." },
    { title: "Unsupported services", detail: "are not yet implemented in CloudGuard collectors." },
  ];

  return (
    <section className={`coverage-limitations ${className}`}>
      <h3 className="coverage-limitations-title">
        <Icon name="info" size={14} />
        What was not assessed
      </h3>
      <ul className="coverage-limitations-list">
        {limitations.map((limitation, index) => (
          <li key={index}>
            <strong>{limitation.title}</strong> {limitation.detail}
          </li>
        ))}
      </ul>
    </section>
  );
}

export function CollectorStatusBadge({
  status,
  size = "md",
}: {
  status: CollectorStatus;
  size?: "sm" | "md" | "lg";
}) {
  const meta = STATUS_META[status];
  return (
    <StatusBadge variant={meta.variant} size={size} icon={meta.icon} showDot={false}>
      {meta.label}
    </StatusBadge>
  );
}