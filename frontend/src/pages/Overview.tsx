import {
  Fragment,
  type CSSProperties,
  type ReactNode,
} from "react";

import { useNavigate } from "react-router-dom";

import Icon, { type IconName } from "../components/Icon";

import {
  EmptyState,
  ErrorState,
  SkeletonCard,
} from "../components/StateBlock";

import {
  useScanContext,
} from "../context/ScanContext";

import {
  useApiQuery,
} from "../hooks/useApiQuery";

import {
  compareScans,
  getScanAttackPaths,
  getScanFindings,
  getScanOverview,
  getScanPrioritizedRemediations,
} from "../services/api";

import type {
  AttackPath,
  ComparisonResult,
  Finding,
  Overview as ScanOverview,
  Remediation,
  ScanRecord,
  SeverityCounts,
} from "../types/cloudguard";

import "../styles/overview.css";


/* ------------------------------------------
   Helpers
   ------------------------------------------ */

type RiskBand = "low" | "medium" | "high" | "critical";

const BAND_LABEL: Record<RiskBand, string> = {
  low: "Low",
  medium: "Medium",
  high: "High",
  critical: "Critical",
};

const BAND_BADGE: Record<RiskBand, string> = {
  low: "badge-success",
  medium: "badge-medium",
  high: "badge-high",
  critical: "badge-critical",
};

function riskBand(score: number): RiskBand {
  if (score >= 75) return "critical";
  if (score >= 50) return "high";
  if (score >= 25) return "medium";
  return "low";
}

function severityKey(severity: string): string {
  const key = severity.toLowerCase();
  if (
    key === "critical"
    || key === "high"
    || key === "medium"
    || key === "low"
    || key === "info"
  ) {
    return key;
  }
  return "info";
}

function formatTimestamp(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });
}

function relativeTime(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "";
  const diffMs = Date.now() - date.getTime();
  if (diffMs < 0) return "just now";
  const minutes = Math.floor(diffMs / 60_000);
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;
  const months = Math.floor(days / 30);
  return `${months}mo ago`;
}

function formatDuration(ms: number | null): string | null {
  if (ms === null) return null;
  if (ms < 1000) return `${ms} ms`;
  return `${(ms / 1000).toFixed(1)} s`;
}

function share(part: number, total: number): string {
  if (total <= 0) return "0%";
  return `${Math.round((part / total) * 100)}%`;
}

function shortId(id: string): string {
  return id.length > 17 ? `${id.slice(0, 17)}…` : id;
}

function topByRisk<T extends { risk_score: number }>(
  items: T[],
): T | null {
  if (items.length === 0) return null;
  return items.reduce(
    (top, item) => (item.risk_score > top.risk_score ? item : top),
  );
}

function findPreviousScan(
  scans: ScanRecord[],
  selectedScan: ScanRecord | null,
): ScanRecord | null {
  if (!selectedScan) {
    return null;
  }

  const candidates = scans.filter(
    (record) =>
      record.scan_id !== selectedScan.scan_id
      && record.source === selectedScan.source
      && record.environment === selectedScan.environment
      && record.created_at < selectedScan.created_at
      && (
        record.status === "completed"
        || record.status === "partial"
      ),
  );

  return candidates[0] ?? null;
}

function nodeKind(node: string): string {
  const separator = node.indexOf(":");
  const type = separator === -1 ? node : node.slice(0, separator);
  switch (type) {
    case "internet":
      return "Internet";
    case "ec2":
    case "lambda":
      return "Workload";
    case "iam_user":
    case "iam_role":
      return "Identity";
    case "s3_bucket":
    case "rds":
    case "secret":
      return "Data store";
    case "security_group":
    case "vpc":
      return "Network";
    default:
      return "Asset";
  }
}

function nodeLabel(node: string): string {
  const separator = node.indexOf(":");
  return separator === -1 ? node : node.slice(separator + 1);
}

function actionLabel(actionType: string): string {
  return actionType.replace(/_/g, " ").toUpperCase();
}

type DeltaInfo = {
  loading: boolean;
  failed: boolean;
  result: ComparisonResult | null;
  retry: () => void;
};

function riskDeltaText(
  delta: DeltaInfo,
  hasPrevious: boolean,
): { text: string; tone: "success" | "danger" | "neutral" } {
  if (!hasPrevious) {
    return {
      text: "First scan for this environment — no baseline yet.",
      tone: "neutral",
    };
  }
  if (delta.loading) {
    return {
      text: "Comparing with the previous scan…",
      tone: "neutral",
    };
  }
  if (delta.failed) {
    return {
      text: "Comparison with the previous scan is unavailable.",
      tone: "neutral",
    };
  }
  const value = delta.result?.risk_delta;
  if (value === null || value === undefined) {
    return {
      text: "No comparison data for this scan.",
      tone: "neutral",
    };
  }
  if (value === 0) {
    return {
      text: "Unchanged since the previous scan.",
      tone: "neutral",
    };
  }
  if (value < 0) {
    return {
      text: `Down ${-value} since the previous scan.`,
      tone: "success",
    };
  }
  return {
    text: `Up ${value} since the previous scan.`,
    tone: "danger",
  };
}


/* ------------------------------------------
   Page
   ------------------------------------------ */

function Overview() {
  const {
    scans,
    selectedScan,
    getSourceLabel,
    getStatusLabel,
    getDataFreshness,
  } = useScanContext();

  const navigate = useNavigate();

  const scanId = selectedScan?.scan_id ?? null;

  const dashboard = useApiQuery(
    async () => {
      if (!scanId) {
        throw new Error("No scan selected.");
      }

      const [
        overview,
        findings,
        attackPaths,
        remediations,
      ] = await Promise.all([
        getScanOverview(scanId),
        getScanFindings(scanId),
        getScanAttackPaths(scanId),
        getScanPrioritizedRemediations(scanId),
      ]);

      return {
        overview,
        findings,
        attackPaths,
        remediations,
      };
    },
    [scanId],
  );

  const previousScan = findPreviousScan(scans, selectedScan);

  const delta = useApiQuery(
    async () => {
      if (!scanId || !previousScan) {
        return null;
      }
      return compareScans(previousScan.scan_id, scanId);
    },
    [scanId, previousScan?.scan_id],
  );


  if (!selectedScan) {
    return (
      <div className="page">
        <EmptyState
          icon="scans"
          title="No scan selected"
          body="CloudGuard has no scan to analyze yet. Open the scan history to run or select a scan."
          action={
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => navigate("/scans")}
            >
              <Icon name="scans" size={14} />
              Open scan history
            </button>
          }
        />
      </div>
    );
  }


  if (dashboard.loading) {
    return <OverviewSkeleton />;
  }


  if (dashboard.error) {
    return (
      <div className="page">
        <header className="topbar">
          <div>
            <p className="eyebrow">SECURITY OVERVIEW</p>
            <h2>Cloud Security Posture</h2>
            <p className="page-subtitle">
              Dashboard data for the selected scan could
              not be loaded.
            </p>
          </div>
        </header>

        <ErrorState
          error={dashboard.error}
          resourceLabel="dashboard data"
          onRetry={dashboard.retry}
        />
      </div>
    );
  }


  if (!dashboard.data) {
    return <OverviewSkeleton />;
  }


  const {
    overview,
    findings,
    attackPaths,
    remediations,
  } = dashboard.data;

  const topPath = topByRisk(attackPaths);
  const topFinding = topByRisk(findings);
  const fixFirst = remediations[0] ?? null;
  const statusMeta = getStatusLabel(overview.status);

  const deltaInfo: DeltaInfo = {
    loading: delta.loading,
    failed: delta.error !== null,
    result: delta.data,
    retry: delta.retry,
  };

  const scannedAgo = relativeTime(overview.created_at);


  return (
    <div className="page">
      <header className="topbar">
        <div>
          <p className="eyebrow">SECURITY OVERVIEW</p>
          <h2>Cloud Security Posture</h2>
          <p className="page-subtitle">
            {overview.environment}
            {" · scanned "}
            {formatTimestamp(overview.created_at)}
            {scannedAgo ? ` (${scannedAgo})` : ""}
            {" · scan "}
            <code className="mono" title={overview.scan_id}>
              {shortId(overview.scan_id)}
            </code>
          </p>
        </div>

        <div className="topbar-badges">
          <span className={`scan-source-badge ${overview.source}`}>
            {getSourceLabel(overview.source)}
          </span>
          <span
            className={
              `badge badge-${
                statusMeta.variant === "error"
                  ? "danger"
                  : statusMeta.variant
              }`
            }
          >
            {statusMeta.label}
          </span>
          <span className="badge badge-neutral no-dot">
            {getDataFreshness(selectedScan)}
          </span>
        </div>
      </header>

      <section
        className="overview-hero"
        style={{ "--i": 1 } as CSSProperties}
      >
        <RiskGaugeCard
          score={overview.highest_risk_score}
          delta={deltaInfo}
          hasPrevious={previousScan !== null}
        />

        <div className="stat-grid">
          <StatCard
            icon="inventory"
            label="Assets"
            value={overview.assets}
            foot={`${overview.relationships} relationships mapped`}
          />
          <StatCard
            icon="lock"
            label="Sensitive assets"
            value={overview.sensitive_assets}
            foot={`${share(overview.sensitive_assets, overview.assets)} of all assets`}
          />
          <StatCard
            icon="paths"
            label="Attack paths"
            value={overview.attack_paths}
            foot="Routes to sensitive resources"
          />
          <StatCard
            icon="findings"
            label="Findings"
            value={overview.findings}
            foot={`${overview.severity.critical} critical · ${overview.severity.high} high`}
          />
          <StatCard
            icon="globe"
            label="Internet exposure"
            value={overview.internet_exposed_assets}
            foot={`${share(overview.internet_exposed_assets, overview.assets)} of assets reachable`}
          />
        </div>
      </section>

      <section
        className="overview-grid"
        style={{ "--i": 2 } as CSSProperties}
      >
        <SeverityPanel
          severity={overview.severity}
          total={overview.findings}
        />

        <AttackPathPanel
          path={topPath}
          total={attackPaths.length}
          onExplore={() => navigate("/attack-paths")}
        />

        <ExposurePanel
          overview={overview}
          freshness={getDataFreshness(selectedScan)}
        />
      </section>

      <section
        className="overview-grid"
        style={{ "--i": 3 } as CSSProperties}
      >
        <FixFirstCard
          remediation={fixFirst}
          total={remediations.length}
          onSimulate={(remediationId) => {
            // Hand the selected fix to the Remediations page,
            // which runs the read-only simulation for this scan.
            navigate("/remediations", {
              state: { remediationId },
            });
          }}
          onOpenPlan={() => navigate("/remediations")}
        />

        <TopIssueCard
          finding={topFinding}
          onReview={() => navigate("/findings")}
        />

        <ScanStatusCard
          scan={selectedScan}
          previous={previousScan}
          delta={deltaInfo}
          sourceLabel={getSourceLabel(selectedScan.source)}
        />
      </section>
    </div>
  );
}


/* ------------------------------------------
   Hero: risk gauge + stat cards
   ------------------------------------------ */

const RING_RADIUS = 52;
const RING_CIRCUMFERENCE = 2 * Math.PI * RING_RADIUS;

function RiskGaugeCard({
  score,
  delta,
  hasPrevious,
}: {
  score: number;
  delta: DeltaInfo;
  hasPrevious: boolean;
}) {
  const clamped = Math.max(0, Math.min(100, Math.round(score)));
  const band = riskBand(clamped);
  const offset = RING_CIRCUMFERENCE * (1 - clamped / 100);
  const deltaText = riskDeltaText(delta, hasPrevious);

  return (
    <article className="card risk-gauge-card">
      <div className="risk-gauge-head">
        <p className="eyebrow">RISK SCORE</p>
        <h3 className="card-title">Highest risk in this scan</h3>
      </div>

      <div className="risk-gauge">
        <svg
          className="risk-ring"
          viewBox="0 0 120 120"
          role="img"
          aria-label={
            `Highest risk score ${clamped} out of 100, `
            + `${BAND_LABEL[band]} risk`
          }
        >
          <circle
            className="risk-ring-track"
            cx={60}
            cy={60}
            r={RING_RADIUS}
          />
          <circle
            className={`risk-ring-fill band-${band}`}
            cx={60}
            cy={60}
            r={RING_RADIUS}
            strokeDasharray={RING_CIRCUMFERENCE}
            strokeDashoffset={offset}
            transform="rotate(-90 60 60)"
          />
        </svg>

        <div className="risk-gauge-center">
          <strong className="risk-gauge-value">{clamped}</strong>
          <span className="risk-gauge-max">/ 100</span>
        </div>
      </div>

      <span className={`badge badge-lg ${BAND_BADGE[band]}`}>
        {BAND_LABEL[band]} risk
      </span>

      <p className={`risk-gauge-delta tone-${deltaText.tone}`}>
        {deltaText.text}
      </p>
    </article>
  );
}


function StatCard({
  icon,
  label,
  value,
  foot,
}: {
  icon: IconName;
  label: string;
  value: number;
  foot: string;
}) {
  return (
    <article className="stat">
      <span className="stat-label">
        <Icon name={icon} size={13} />
        {label}
      </span>
      <strong className="stat-value">{value}</strong>
      <span className="stat-foot">{foot}</span>
    </article>
  );
}


/* ------------------------------------------
   Row: severity / attack path / exposure
   ------------------------------------------ */

const SEVERITY_ROWS = [
  { key: "critical", label: "Critical" },
  { key: "high", label: "High" },
  { key: "medium", label: "Medium" },
  { key: "low", label: "Low" },
  { key: "info", label: "Info" },
] as const;

function SeverityPanel({
  severity,
  total,
}: {
  severity: SeverityCounts;
  total: number;
}) {
  const max = Math.max(
    severity.critical,
    severity.high,
    severity.medium,
    severity.low,
    severity.info,
    1,
  );

  return (
    <article className="panel g-severity">
      <div className="panel-header">
        <div>
          <p className="eyebrow">RISK DISTRIBUTION</p>
          <h3 className="panel-title">Findings by severity</h3>
        </div>
        <span className="badge badge-neutral no-dot">
          {total} total
        </span>
      </div>

      <div className="panel-body">
        {total === 0 ? (
          <p className="card-note">
            <Icon name="check" size={15} />
            No findings were raised for this scan.
          </p>
        ) : (
          <div className="sev-rows">
            {SEVERITY_ROWS.map((row) => {
              const value = severity[row.key];
              const width = value === 0
                ? 0
                : Math.max((value / max) * 100, 4);

              return (
                <div className="sev-row" key={row.key}>
                  <span className="sev-row-name">{row.label}</span>
                  <span className="sev-row-track">
                    <span
                      className={`sev-row-fill ${row.key}`}
                      style={{ width: `${width}%` }}
                    />
                  </span>
                  <span className="sev-row-count">{value}</span>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </article>
  );
}


function AttackPathPanel({
  path,
  total,
  onExplore,
}: {
  path: AttackPath | null;
  total: number;
  onExplore: () => void;
}) {
  return (
    <article className="panel g-attack">
      <div className="panel-header">
        <div>
          <p className="eyebrow">MOST DANGEROUS PATH</p>
          <h3 className="panel-title">Top attack path</h3>
        </div>
        {path && (
          <span className={`badge badge-${severityKey(path.severity)}`}>
            {path.severity.toUpperCase()}
          </span>
        )}
      </div>

      <div className="panel-body">
        {!path ? (
          <p className="card-note">
            <Icon name="check" size={15} />
            No attack paths to sensitive resources were
            discovered in this scan.
          </p>
        ) : (
          <>
            <div className="chain">
              {path.nodes.map((node, index) => {
                const isLast = index === path.nodes.length - 1;
                const isSensitiveTarget =
                  isLast && path.sensitive_target;
                const hop = path.hops[index - 1];

                return (
                  <Fragment key={`${node}-${index}`}>
                    {index > 0 && (
                      <span className="chain-edge">
                        <span className="chain-edge-label">
                          {hop
                            ? hop.relationship_type.replace(/_/g, " ")
                            : ""}
                        </span>
                        <Icon name="chevron-right" size={12} />
                      </span>
                    )}

                    <span
                      className={
                        `chain-node${
                          isSensitiveTarget ? " sensitive" : ""
                        }`
                      }
                      title={node}
                    >
                      <span className="chain-node-kind">
                        {isSensitiveTarget
                          ? "Sensitive target"
                          : nodeKind(node)}
                      </span>
                      <span className="chain-node-id mono">
                        {nodeLabel(node)}
                      </span>
                    </span>
                  </Fragment>
                );
              })}
            </div>

            <p className="chain-explanation">{path.explanation}</p>

            <div className="chain-meta">
              <span>
                Risk <strong>{path.risk_score}</strong> / 100
              </span>
              <span>{path.hop_count} hops</span>
              <span>
                {total} path{total === 1 ? "" : "s"} in this scan
              </span>
            </div>

            <div className="panel-actions">
              <button
                type="button"
                className="btn btn-ghost btn-sm"
                onClick={onExplore}
              >
                Explore attack paths
                <Icon name="chevron-right" size={13} />
              </button>
            </div>
          </>
        )}
      </div>
    </article>
  );
}


function ExposurePanel({
  overview,
  freshness,
}: {
  overview: ScanOverview;
  freshness: string;
}) {
  return (
    <article className="panel g-exposure">
      <div className="panel-header">
        <div>
          <p className="eyebrow">ATTACK SURFACE</p>
          <h3 className="panel-title">Exposure summary</h3>
        </div>
      </div>

      <div className="panel-body exposure-body">
        <div className="exposure-row">
          <span className="exposure-label">
            <Icon name="globe" size={13} />
            Internet-exposed
          </span>
          <span className="exposure-value">
            {overview.internet_exposed_assets}
            <span className="exposure-dim">
              {" "}/ {overview.assets}
            </span>
          </span>
        </div>

        <div className="exposure-row">
          <span className="exposure-label">
            <Icon name="lock" size={13} />
            Sensitive assets
          </span>
          <span className="exposure-value">
            {overview.sensitive_assets}
          </span>
        </div>

        <div className="exposure-row">
          <span className="exposure-label">
            <Icon name="network" size={13} />
            Relationships
          </span>
          <span className="exposure-value">
            {overview.relationships}
          </span>
        </div>

        <div className="exposure-row">
          <span className="exposure-label">
            <Icon name="coverage" size={13} />
            Regions
          </span>
          {overview.regions.length > 0 ? (
            <span className="chip-row exposure-chips">
              {overview.regions.map((region) => (
                <span className="chip" key={region}>{region}</span>
              ))}
            </span>
          ) : (
            <span className="exposure-value muted">—</span>
          )}
        </div>

        <div className="exposure-row">
          <span className="exposure-label">
            <Icon name="identity" size={13} />
            Account
          </span>
          <span
            className="mono exposure-account"
            title={overview.account_identifier ?? undefined}
          >
            {overview.account_identifier ?? "local lab"}
          </span>
        </div>

        <div className="exposure-row">
          <span className="exposure-label">
            <Icon name="info" size={13} />
            Data basis
          </span>
          <span className="badge badge-info no-dot">
            {freshness}
          </span>
        </div>
      </div>
    </article>
  );
}


/* ------------------------------------------
   Row: fix first / top issue / scan status
   ------------------------------------------ */

function FixFirstCard({
  remediation,
  total,
  onSimulate,
  onOpenPlan,
}: {
  remediation: Remediation | null;
  total: number;
  onSimulate: (remediationId: string) => void;
  onOpenPlan: () => void;
}) {
  return (
    <article className="panel g-fix">
      <div className="panel-header">
        <div>
          <p className="eyebrow">WHAT SHOULD I FIX FIRST?</p>
          <h3 className="panel-title">Recommended first fix</h3>
        </div>
        {remediation && (
          <span className="badge badge-neutral no-dot">
            Priority #{remediation.priority ?? 1}
          </span>
        )}
      </div>

      <div className="panel-body">
        {!remediation ? (
          <p className="card-note">
            <Icon name="check" size={15} />
            No remediations are recommended for this scan —
            nothing pressing to fix.
          </p>
        ) : (
          <>
            <div className="fix-head">
              <h4 className="fix-title">{remediation.title}</h4>
              <span className="badge badge-info no-dot">
                {actionLabel(remediation.action_type)}
              </span>
            </div>

            <p className="fix-desc">{remediation.description}</p>

            <div className="fix-metrics">
              <FixMetric
                label="Paths affected"
                value={String(remediation.paths_affected)}
              />
              <FixMetric
                label="Paths removed"
                value={
                  remediation.paths_removed !== null
                    ? String(remediation.paths_removed)
                    : "—"
                }
              />
              <FixMetric
                label="Risk change"
                value={
                  remediation.risk_before !== null
                  && remediation.risk_after !== null
                    ? `${remediation.risk_before} → ${remediation.risk_after}`
                    : "—"
                }
              />
              <FixMetric
                label="Risk reduction"
                value={
                  remediation.risk_reduction !== null
                    ? `${remediation.risk_reduction} (${remediation.risk_reduction_percent ?? 0}%)`
                    : "—"
                }
              />
            </div>

            {remediation.affected_resources.length > 0 && (
              <div className="chip-row fix-resources">
                {remediation.affected_resources.slice(0, 3).map(
                  (resource) => (
                    <span
                      className="chip"
                      key={resource}
                      title={resource}
                    >
                      <span className="mono wrap-anywhere">
                        {resource}
                      </span>
                    </span>
                  ),
                )}
                {remediation.affected_resources.length > 3 && (
                  <span className="chip">
                    +{remediation.affected_resources.length - 3} more
                  </span>
                )}
              </div>
            )}

            <div className="fix-actions">
              <button
                type="button"
                className="btn btn-primary"
                onClick={() => onSimulate(remediation.remediation_id)}
              >
                <Icon name="remediate" size={14} />
                Simulate fix
              </button>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={onOpenPlan}
              >
                Open remediation plan ({total})
              </button>
            </div>
          </>
        )}
      </div>
    </article>
  );
}


function FixMetric({
  label,
  value,
}: {
  label: string;
  value: string;
}) {
  return (
    <div className="fix-metric">
      <span className="fix-metric-label">{label}</span>
      <span className="fix-metric-value">{value}</span>
    </div>
  );
}


function TopIssueCard({
  finding,
  onReview,
}: {
  finding: Finding | null;
  onReview: () => void;
}) {
  const risk = finding
    ? Math.max(0, Math.min(100, finding.risk_score))
    : 0;

  return (
    <article className="panel g-issue">
      <div className="panel-header">
        <div>
          <p className="eyebrow">HIGHEST-PRIORITY ISSUE</p>
          <h3 className="panel-title">Top finding</h3>
        </div>
        {finding && (
          <span
            className={
              `badge badge-${severityKey(finding.severity)}`
            }
          >
            {finding.severity.toUpperCase()}
          </span>
        )}
      </div>

      <div className="panel-body">
        {!finding ? (
          <p className="card-note">
            <Icon name="check" size={15} />
            No findings were raised for this scan.
          </p>
        ) : (
          <>
            <h4 className="issue-title">{finding.title}</h4>

            <div className="issue-risk riskbar-with-value">
              <div className="riskbar">
                <div
                  className={
                    `riskbar-fill sev-${severityKey(finding.severity)}`
                  }
                  style={{ width: `${risk}%` }}
                />
              </div>
              <span className="riskbar-value">{finding.risk_score}</span>
            </div>

            <p className="issue-desc">{finding.description}</p>

            {finding.affected_assets.length > 0 && (
              <div className="chip-row">
                {finding.affected_assets.slice(0, 3).map((asset) => (
                  <span className="chip" key={asset} title={asset}>
                    <span className="mono wrap-anywhere">{asset}</span>
                  </span>
                ))}
                {finding.affected_assets.length > 3 && (
                  <span className="chip">
                    +{finding.affected_assets.length - 3} more
                  </span>
                )}
              </div>
            )}

            <div className="panel-actions">
              <button
                type="button"
                className="btn btn-ghost btn-sm"
                onClick={onReview}
              >
                Review all findings
                <Icon name="chevron-right" size={13} />
              </button>
            </div>
          </>
        )}
      </div>
    </article>
  );
}


function ScanStatusCard({
  scan,
  previous,
  delta,
  sourceLabel,
}: {
  scan: ScanRecord;
  previous: ScanRecord | null;
  delta: DeltaInfo;
  sourceLabel: string;
}) {
  const duration = formatDuration(scan.duration_ms);
  const ago = relativeTime(scan.created_at);
  const result = delta.result;

  return (
    <article className="panel g-scan">
      <div className="panel-header">
        <div>
          <p className="eyebrow">SCAN STATUS</p>
          <h3 className="panel-title">Selected scan</h3>
        </div>
        <span className={`scan-source-badge ${scan.source}`}>
          {sourceLabel}
        </span>
      </div>

      <div className="panel-body">
        <div className="scan-meta">
          <MetaRow label="Environment" value={scan.environment} />

          <div className="scan-meta-row">
            <span className="scan-meta-label">Scanned</span>
            <span className="scan-meta-value">
              {formatTimestamp(scan.created_at)}
              {ago && <span className="muted"> · {ago}</span>}
            </span>
          </div>

          <div className="scan-meta-row">
            <span className="scan-meta-label">Scan ID</span>
            <span
              className="scan-meta-value mono scan-id truncate"
              title={scan.scan_id}
            >
              {scan.scan_id}
            </span>
          </div>

          <MetaRow
            label="Scanner"
            value={
              `v${scan.scanner_version}`
              + (duration ? ` · ${duration}` : "")
            }
          />
        </div>

        <div className="delta-block">
          <p className="delta-title">Vs previous scan</p>

          {!previous ? (
            <p className="delta-empty">
              First scan for this environment — the next scan
              will be compared against it.
            </p>
          ) : delta.loading ? (
            <p className="delta-empty">
              Comparing with the previous scan…
            </p>
          ) : delta.failed ? (
            <p className="delta-empty">
              Comparison unavailable.{" "}
              <button
                type="button"
                className="btn btn-ghost btn-sm"
                onClick={delta.retry}
              >
                <Icon name="refresh" size={13} />
                Retry
              </button>
            </p>
          ) : result ? (
            <div className="delta-rows">
              <div className="delta-row">
                <span>Risk</span>
                <DeltaValue
                  before={result.risk_before}
                  after={result.risk_after}
                  delta={result.risk_delta}
                />
              </div>

              <div className="delta-row">
                <span>Findings</span>
                <span className="delta-value">
                  {result.findings_before} → {result.findings_after}{" "}
                  <span className="muted">
                    (+{result.new_findings.length} new ·{" "}
                    {result.resolved_findings.length} resolved)
                  </span>
                </span>
              </div>

              <div className="delta-row">
                <span>Attack paths</span>
                <span className="delta-value">
                  {result.paths_before} → {result.paths_after}{" "}
                  <span className="muted">
                    (+{result.new_paths.length} new ·{" "}
                    {result.resolved_paths.length} resolved)
                  </span>
                </span>
              </div>

              <p className="delta-basis">
                Compared to {formatTimestamp(previous.created_at)}
                {" · "}
                <span className="mono" title={previous.scan_id}>
                  {shortId(previous.scan_id)}
                </span>
              </p>
            </div>
          ) : (
            <p className="delta-empty">
              No comparison data for this scan.
            </p>
          )}
        </div>
      </div>
    </article>
  );
}


function MetaRow({
  label,
  value,
}: {
  label: string;
  value: ReactNode;
}) {
  return (
    <div className="scan-meta-row">
      <span className="scan-meta-label">{label}</span>
      <span className="scan-meta-value">{value}</span>
    </div>
  );
}


function DeltaValue({
  before,
  after,
  delta,
}: {
  before: number;
  after: number;
  delta: number;
}) {
  const tone = delta > 0 ? "danger" : delta < 0 ? "success" : "neutral";
  const sign = delta > 0 ? `+${delta}` : delta < 0 ? `−${-delta}` : "±0";

  return (
    <span className="delta-value">
      {before} → {after}{" "}
      <span className={`delta-tone-${tone}`}>({sign})</span>
    </span>
  );
}


/* ------------------------------------------
   Loading skeleton
   ------------------------------------------ */

function OverviewSkeleton() {
  return (
    <div className="page">
      <header className="topbar">
        <div>
          <p className="eyebrow">SECURITY OVERVIEW</p>
          <h2>Cloud Security Posture</h2>
          <p className="page-subtitle">
            Analyzing the selected scan…
          </p>
        </div>
      </header>

      <div
        className="overview-hero"
        style={{ "--i": 1 } as CSSProperties}
      >
        <SkeletonCard lines={4} />
        <div className="stat-grid">
          {Array.from({ length: 5 }, (_, i) => (
            <SkeletonCard key={i} lines={2} />
          ))}
        </div>
      </div>

      <div
        className="overview-grid"
        style={{ "--i": 2 } as CSSProperties}
      >
        <SkeletonCard lines={6} />
        <SkeletonCard lines={6} />
        <SkeletonCard lines={6} />
      </div>
    </div>
  );
}


export default Overview;
