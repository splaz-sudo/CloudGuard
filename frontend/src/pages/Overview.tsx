import { useNavigate } from "react-router-dom";

import {
  compareScans,
  getScanAttackPaths,
  getScanFindings,
  getScanOverview,
  getScanPrioritizedRemediations,
} from "../services/api";

import {
  useScanContext,
} from "../context/ScanContext";

import {
  useApiQuery,
} from "../hooks/useApiQuery";

import type {
  ScanRecord,
} from "../types/cloudguard";


function Overview() {
  const { scans, selectedScan } =
    useScanContext();

  const navigate = useNavigate();

  const scanId =
    selectedScan?.scan_id ?? null;

  const dashboard = useApiQuery(
    async () => {
      if (!scanId) {
        throw new Error(
          "No scan selected.",
        );
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

  const previousScan = findPreviousScan(
    scans,
    selectedScan,
  );

  const delta = useApiQuery(
    async () => {
      if (
        !scanId
        || !previousScan
      ) {
        return null;
      }

      return compareScans(
        previousScan.scan_id,
        scanId,
      );
    },
    [scanId, previousScan?.scan_id],
  );


  if (!scanId || dashboard.loading) {
    return (
      <section className="page-state">
        Analyzing cloud environment...
      </section>
    );
  }


  if (dashboard.error || !dashboard.data) {
    return (
      <section className="page-state error-message">
        <div>
          <h2>
            CloudGuard API unavailable
          </h2>

          <p>
            The dashboard cannot connect to the
            CloudGuard backend. Make sure the
            API service is running, then try
            again.
          </p>

          {dashboard.error?.status && (
            <p>
              HTTP status:{" "}
              {dashboard.error.status}
            </p>
          )}

          {dashboard.error?.requestId && (
            <p>
              Request ID:{" "}
              <code>
                {
                  dashboard.error
                    .requestId
                }
              </code>
            </p>
          )}

          <button
            type="button"
            onClick={dashboard.retry}
          >
            Retry
          </button>
        </div>
      </section>
    );
  }


  const {
    overview,
    findings,
    attackPaths,
    remediations,
  } = dashboard.data;


  return (
    <>
      <header className="topbar">
        <div>
          <p className="eyebrow">
            SECURITY OVERVIEW
          </p>

          <h2>Cloud Security Posture</h2>

          <p className="subtitle">
            {overview.environment}
            {" · "}
            {overview.created_at
              .replace("T", " ")
              .slice(0, 16)}
            {" · "}
            <code>{overview.scan_id}</code>
          </p>
        </div>

        <div className="environment-badge">
          {environmentLabel(overview.mode)}
        </div>
      </header>

      <section className="metric-grid">
        <MetricCard
          label="Highest Risk"
          value={
            overview.highest_risk_score
          }
          detail={riskDeltaDetail(
            delta.data?.risk_delta,
            delta.loading,
            previousScan !== null,
          )}
          risk
        />

        <MetricCard
          label="Cloud Assets"
          value={overview.assets}
          detail={
            `${overview.sensitive_assets} sensitive`
          }
        />

        <MetricCard
          label="Attack Paths"
          value={overview.attack_paths}
          detail="To sensitive resources"
        />

        <MetricCard
          label="Findings"
          value={overview.findings}
          detail={
            `Across ${overview.relationships} relationships`
          }
        />
      </section>

      <section className="content-grid">
        <article className="panel">
          <div className="panel-header">
            <div>
              <p className="eyebrow">
                RISK DISTRIBUTION
              </p>

              <h3>Security Posture</h3>
            </div>

            <span className="live-label">
              {dataLabel(overview.mode)}
            </span>
          </div>

          <div className="severity-list">
            <SeverityRow
              name="Critical"
              value={
                overview.severity.critical
              }
              severity="critical"
            />

            <SeverityRow
              name="High"
              value={overview.severity.high}
              severity="high"
            />

            <SeverityRow
              name="Medium"
              value={overview.severity.medium}
              severity="medium"
            />

            <SeverityRow
              name="Low"
              value={overview.severity.low}
              severity="low"
            />
          </div>

          <div className="exposure-summary">
            <span>
              Internet-exposed assets
            </span>

            <strong>
              {
                overview
                  .internet_exposed_assets
              }
            </strong>
          </div>
        </article>

        <article className="panel">
          <div className="panel-header">
            <div>
              <p className="eyebrow">
                ATTACK SURFACE
              </p>

              <h3>Exposure Summary</h3>
            </div>
          </div>

          {attackPaths.length === 0 ? (
            <p className="attack-description">
              No attack paths to sensitive
              resources were discovered in
              this scan.
            </p>
          ) : (
            <>
              <div className="attack-summary">
                {attackPaths[0].nodes.map(
                  (node, nodeIndex) => (
                    <span
                      key={`${node}-${nodeIndex}`}
                      className="attack-chain-item"
                    >
                      {nodeIndex > 0 && (
                        <span className="arrow">
                          →
                        </span>
                      )}

                      <div
                        className={
                          nodeIndex ===
                            attackPaths[0]
                              .nodes
                              .length -
                              1 &&
                          attackPaths[0]
                            .sensitive_target
                            ? "attack-node sensitive"
                            : "attack-node"
                        }
                        title={node}
                      >
                        {shortNodeLabel(node)}
                      </div>
                    </span>
                  ),
                )}
              </div>

              <p className="attack-description">
                {attackPaths[0].explanation}
              </p>
            </>
          )}
        </article>
      </section>

      <section className="panel findings-panel">
        <div className="panel-header">
          <div>
            <p className="eyebrow">
              PRIORITIZED RISKS
            </p>

            <h3>Security Findings</h3>
          </div>

          <span className="finding-count">
            {findings.length} findings
          </span>
        </div>

        <div className="findings-list">
          {findings.map((finding) => (
            <article
              className="finding"
              key={finding.id}
            >
              <div className="finding-main">
                <span
                  className={
                    `severity-badge ${
                      finding.severity
                        .toLowerCase()
                    }`
                  }
                >
                  {finding.severity}
                </span>

                <div>
                  <h4>
                    {finding.title}
                  </h4>

                  <p>
                    {finding.description}
                  </p>

                  <div className="finding-assets">
                    {
                      finding
                        .affected_assets
                        .map((asset) => (
                          <span key={asset}>
                            {asset}
                          </span>
                        ))
                    }
                  </div>
                </div>
              </div>

              <div className="finding-risk">
                <span>Risk</span>

                <strong>
                  {finding.risk_score}
                </strong>
              </div>
            </article>
          ))}

          {findings.length === 0 && (
            <p className="attack-description">
              No findings were raised for this
              scan.
            </p>
          )}
        </div>
      </section>

      {remediations && remediations.length > 0 && (
        <section className="panel remediation-panel">
          <div className="panel-header">
            <div>
              <p className="eyebrow">
                WHAT SHOULD I FIX FIRST?
              </p>

              <h3>Recommended Remediations</h3>
            </div>

            <span className="finding-count">
              {remediations.length} remediation{remediations.length > 1 ? 's' : ''}
            </span>
          </div>

          <div className="remediation-list">
            {remediations.map((remediation) => (
              <article
                className="remediation-card"
                key={remediation.remediation_id}
              >
                <div className="remediation-header">
                  <span className="remediation-rank">
                    #{remediation.priority ?? '—'}
                  </span>

                  <div className="remediation-heading">
                    <h3>{remediation.title}</h3>

                    <span className="remediation-action">
                      {remediation.action_type
                        .replace(/_/g, ' ')
                        .toUpperCase()}
                    </span>
                  </div>
                </div>

                <p className="details-text">
                  {remediation.description}
                </p>

                <div className="finding-assets">
                  {remediation.affected_resources.map(
                    (resource) => (
                      <span key={resource}>
                        {resource}
                      </span>
                    ),
                  )}
                </div>

                <div className="remediation-metrics">
                  <div className="remediation-metric">
                    <span>Attack paths affected</span>
                    <strong>{remediation.paths_affected}</strong>
                  </div>

                  <div className="remediation-metric">
                    <span>Paths removed</span>
                    <strong>{remediation.paths_removed ?? '—'}</strong>
                  </div>

                  <div className="remediation-metric">
                    <span>Risk before</span>
                    <strong>{remediation.risk_before ?? '—'}</strong>
                  </div>

                  <div className="remediation-metric">
                    <span>Risk after</span>
                    <strong>{remediation.risk_after ?? '—'}</strong>
                  </div>

                  <div className="remediation-metric">
                    <span>Risk reduction</span>
                    <strong>
                      {remediation.risk_reduction ?? '—'}
                      ({remediation.risk_reduction_percent ?? 0}%)
                    </strong>
                  </div>
                </div>

                <div className="details-divider" />

                <p className="details-section-title">
                  Evidence
                </p>

                <ul className="remediation-evidence">
                  {remediation.evidence.map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ul>

                <p className="details-section-title">
                  Expected effect
                </p>

                <p className="details-text">
                  {remediation.expected_effect}
                </p>

                <button
                  type="button"
                  className="simulate-button"
                  onClick={() => {
                    // Hand the selected fix to the Remediations page,
                    // which runs the read-only simulation for this scan.
                    navigate("/remediations", {
                      state: {
                        remediationId:
                          remediation.remediation_id,
                      },
                    });
                  }}
                >
                  SIMULATE FIX
                </button>
              </article>
            ))}
          </div>
        </section>
      )}
    </>
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
      record.scan_id
        !== selectedScan.scan_id
      && record.source
        === selectedScan.source
      && record.environment
        === selectedScan.environment
      && record.created_at
        < selectedScan.created_at
      && (
        record.status === "completed"
        || record.status === "partial"
      ),
  );

  return candidates[0] ?? null;
}


function riskDeltaDetail(
  riskDelta: number | null | undefined,
  loading: boolean,
  hasPrevious: boolean,
): string {
  if (!hasPrevious) {
    return "/ 100";
  }

  if (loading) {
    return "/ 100 · comparing...";
  }

  if (
    riskDelta === null
    || riskDelta === undefined
  ) {
    return "/ 100";
  }

  if (riskDelta === 0) {
    return "/ 100 · unchanged";
  }

  if (riskDelta < 0) {
    return (
      `/ 100 · ↓ ${-riskDelta}`
      + " since previous scan"
    );
  }

  return (
    `/ 100 · ↑ ${riskDelta}`
    + " since previous scan"
  );
}


function environmentLabel(
  mode: string,
) {
  return mode === "local"
    ? "LOCAL LAB"
    : "AWS SCAN";
}


function dataLabel(mode: string) {
  return mode === "local"
    ? "SIMULATED DATA"
    : "SCAN RESULT";
}


function shortNodeLabel(node: string) {
  const separatorIndex =
    node.indexOf(":");

  if (separatorIndex === -1) {
    return node;
  }

  return node.slice(separatorIndex + 1);
}


type MetricCardProps = {
  label: string;
  value: number;
  detail: string;
  risk?: boolean;
};


function MetricCard({
  label,
  value,
  detail,
  risk = false,
}: MetricCardProps) {
  return (
    <article
      className={
        risk
          ? "metric-card risk-card"
          : "metric-card"
      }
    >
      <span className="metric-label">
        {label}
      </span>

      <strong
        className={
          risk
            ? "risk-score"
            : undefined
        }
      >
        {value}
      </strong>

      <span className="metric-detail">
        {detail}
      </span>
    </article>
  );
}


type SeverityRowProps = {
  name: string;
  value: number;
  severity: string;
};


function SeverityRow({
  name,
  value,
  severity,
}: SeverityRowProps) {
  const width =
    value === 0
      ? "0%"
      : `${Math.min(
          value * 35,
          100,
        )}%`;

  return (
    <div className="severity-row">
      <div className="severity-meta">
        <span>{name}</span>

        <strong>
          {value}
        </strong>
      </div>

      <div className="severity-track">
        <div
          className={
            `severity-fill ${severity}`
          }
          style={{ width }}
        />
      </div>
    </div>
  );
}


export default Overview;
