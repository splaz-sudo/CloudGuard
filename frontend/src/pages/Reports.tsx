import {
  type CSSProperties,
  type ReactNode,
} from "react";

import Icon from "../components/Icon";
import {
  EmptyState,
  ErrorState,
  LoadingState,
  PartialNotice,
} from "../components/StateBlock";

import {
  useScanContext,
} from "../context/ScanContext";

import { useApiQuery } from "../hooks/useApiQuery";
import { getSecurityReport } from "../services/api";

import type {
  ReportFinding,
  SecurityReport,
} from "../types/cloudguard";

import "../styles/reports.css";


const TOP_FINDINGS_COUNT = 5;


function severityBadgeClass(
  severity: string,
): string {
  switch (severity.toLowerCase()) {
    case "critical":
      return "badge-critical";
    case "high":
      return "badge-high";
    case "medium":
      return "badge-medium";
    case "low":
      return "badge-low";
    case "info":
      return "badge-info";
    default:
      return "badge-neutral";
  }
}


function formatScanTimestamp(
  createdAt: string,
): string {
  return createdAt
    .replace("T", " ")
    .slice(0, 16);
}


/**
 * JSON export of the report payload already
 * loaded for the selected scan — no extra API
 * call, no contract change.
 */
function downloadJson(report: SecurityReport) {
  const blob = new Blob(
    [JSON.stringify(report, null, 2)],
    { type: "application/json" },
  );

  const url = URL.createObjectURL(blob);

  const anchor =
    document.createElement("a");

  anchor.href = url;
  anchor.download =
    "CloudGuard-Security-Assessment.json";

  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();

  URL.revokeObjectURL(url);
}


/** Existing PDF export mechanism — unchanged. */
function downloadPdf() {
  window.location.href =
    "/api/report/pdf";
}


function Reports() {
  const {
    selectedScan,
    getSourceLabel,
  } = useScanContext();

  const scanId =
    selectedScan?.scan_id ?? null;

  // The report always reflects the globally
  // selected scan: changing the selection in
  // the sidebar re-fetches the assessment.
  const reportQuery = useApiQuery(
    () => getSecurityReport(),
    [scanId],
  );

  const report = reportQuery.data;


  const exportActions = (
    <div className="report-actions">
      <button
        type="button"
        className="btn btn-secondary"
        disabled={!report}
        onClick={() => {
          if (report) {
            downloadJson(report);
          }
        }}
      >
        <Icon name="download" size={14} />
        Download JSON
      </button>

      <button
        type="button"
        className="btn btn-primary"
        onClick={downloadPdf}
      >
        <Icon name="download" size={14} />
        Download PDF
      </button>
    </div>
  );


  let body: ReactNode;

  if (reportQuery.loading) {
    body = (
      <LoadingState label="Building CloudGuard security assessment…" />
    );
  } else if (reportQuery.error) {
    body = (
      <ErrorState
        error={reportQuery.error}
        resourceLabel="the report"
        onRetry={reportQuery.retry}
      />
    );
  } else if (!report) {
    body = (
      <EmptyState
        icon="reports"
        title="No report data"
        body="The API returned no report for the selected scan. Run a scan, then retry."
      />
    );
  } else {
    body = (
      <ReportView
        report={report}
        scanMeta={
          selectedScan
            ? {
                environment:
                  selectedScan.environment,
                timestamp:
                  formatScanTimestamp(
                    selectedScan.created_at,
                  ),
                sourceLabel: getSourceLabel(
                  selectedScan.source,
                ),
                scanId: selectedScan.scan_id,
              }
            : null
        }
      />
    );
  }


  return (
    <div className="page">
      <header className="topbar">
        <div>
          <p className="eyebrow">
            SECURITY ASSESSMENT
          </p>

          <h2>
            {report?.report_name ?? "Reports"}
          </h2>

          <p className="page-subtitle">
            Consolidated security posture,
            attack-path, identity, network,
            findings and compliance evidence.
          </p>
        </div>

        {exportActions}
      </header>

      {body}
    </div>
  );
}


function ReportView({
  report,
  scanMeta,
}: {
  report: SecurityReport;
  scanMeta: {
    environment: string;
    timestamp: string;
    sourceLabel: string;
    scanId: string;
  } | null;
}) {
  const { summary, compliance } = report;

  const severityTotal =
    summary.critical_findings
    + summary.high_findings
    + summary.medium_findings
    + summary.low_findings
    + summary.info_findings;

  const severitySegments = [
    {
      key: "critical",
      label: "Critical",
      count: summary.critical_findings,
    },
    {
      key: "high",
      label: "High",
      count: summary.high_findings,
    },
    {
      key: "medium",
      label: "Medium",
      count: summary.medium_findings,
    },
    {
      key: "low",
      label: "Low",
      count: summary.low_findings,
    },
    {
      key: "info",
      label: "Info",
      count: summary.info_findings,
    },
  ];

  const topFindings = [...report.findings]
    .sort(
      (a, b) => b.risk_score - a.risk_score,
    )
    .slice(0, TOP_FINDINGS_COUNT);

  const remediableFindings =
    report.findings.filter(
      (finding) => finding.remediation,
    );

  const remediationHighlights =
    [...remediableFindings]
      .sort(
        (a, b) => b.risk_score - a.risk_score,
      )
      .slice(0, 3);

  const primaryAttackPath =
    report.attack_paths.length > 0
      ? report.attack_paths[0]
      : null;

  const isPartial =
    report.assessment_mode
      .toLowerCase()
      .includes("partial")
    || summary.mode
      .toLowerCase()
      .includes("partial");


  return (
    <>
      {isPartial && (
        <PartialNotice>
          This assessment is based on a partial
          scan — one or more collectors failed,
          so some resources were not assessed.
        </PartialNotice>
      )}

      <section
        className="card report-exec"
        style={{ "--i": 1 } as CSSProperties}
      >
        <div className="card-header">
          <div>
            <p className="card-title">
              Executive summary
            </p>

            <p className="card-subtitle">
              Scan metadata and assessment scope
            </p>
          </div>

          <span className="badge badge-info no-dot">
            {report.assessment_mode
              .toUpperCase()}
          </span>
        </div>

        <dl className="report-exec-grid">
          <div className="report-exec-item">
            <dt>Environment</dt>

            <dd>
              {scanMeta?.environment
                ?? "Latest completed scan"}
            </dd>
          </div>

          <div className="report-exec-item">
            <dt>Scan timestamp</dt>

            <dd>
              {scanMeta?.timestamp ?? "—"}
            </dd>
          </div>

          <div className="report-exec-item">
            <dt>Source</dt>

            <dd>
              {scanMeta?.sourceLabel ?? "—"}
            </dd>
          </div>

          <div className="report-exec-item">
            <dt>Scan ID</dt>

            <dd>
              {scanMeta ? (
                <code className="mono wrap-anywhere">
                  {scanMeta.scanId}
                </code>
              ) : (
                "—"
              )}
            </dd>
          </div>

          <div className="report-exec-item">
            <dt>Report version</dt>

            <dd>v{report.report_version}</dd>
          </div>
        </dl>

        <p className="report-scope-note secondary">
          {report.scope_note}
        </p>
      </section>

      <section
        className="stat-grid"
        style={{ "--i": 2 } as CSSProperties}
      >
        <div className="stat">
          <span className="stat-label">
            Highest risk
          </span>

          <p className="stat-value">
            {summary.highest_risk_score}
          </p>

          <p className="stat-foot">
            Maximum correlated risk score
          </p>
        </div>

        <div className="stat">
          <span className="stat-label">
            Critical
          </span>

          <p className="stat-value">
            {summary.critical_findings}
          </p>

          <p className="stat-foot">
            Critical security findings
          </p>
        </div>

        <div className="stat">
          <span className="stat-label">
            High
          </span>

          <p className="stat-value">
            {summary.high_findings}
          </p>

          <p className="stat-foot">
            High severity findings
          </p>
        </div>

        <div className="stat">
          <span className="stat-label">
            Attack paths
          </span>

          <p className="stat-value">
            {summary.attack_paths}
          </p>

          <p className="stat-foot">
            Paths to sensitive assets
          </p>
        </div>

        <div className="stat">
          <span className="stat-label">
            Exposed assets
          </span>

          <p className="stat-value">
            {summary.internet_exposed_assets}
          </p>

          <p className="stat-foot">
            Internet-exposed resources
          </p>
        </div>

        <div className="stat">
          <span className="stat-label">
            Assets
          </span>

          <p className="stat-value">
            {summary.total_assets}
          </p>

          <p className="stat-foot">
            Assets represented in graph
          </p>
        </div>
      </section>

      <section
        className="card"
        style={{ "--i": 3 } as CSSProperties}
      >
        <div className="card-header">
          <div>
            <p className="card-title">
              Severity distribution
            </p>

            <p className="card-subtitle">
              {severityTotal}
              {" findings by severity"}
            </p>
          </div>
        </div>

        {severityTotal === 0 ? (
          <p className="muted">
            No findings were recorded in this
            assessment.
          </p>
        ) : (
          <>
            <div
              className="report-sevbar"
              role="img"
              aria-label={
                "Findings by severity: "
                + severitySegments
                  .map(
                    (segment) =>
                      `${segment.label} `
                      + `${segment.count}`,
                  )
                  .join(", ")
              }
            >
              {severitySegments.map(
                (segment) =>
                  segment.count > 0 && (
                    <span
                      key={segment.key}
                      className={
                        `report-sevseg ${
                          segment.key
                        }`
                      }
                      style={{
                        width: `${
                          (segment.count
                            / severityTotal)
                          * 100
                        }%`,
                      }}
                      title={
                        `${segment.label}: `
                        + `${segment.count}`
                      }
                    />
                  ),
              )}
            </div>

            <div className="report-sev-legend">
              {severitySegments.map(
                (segment) => (
                  <span
                    key={segment.key}
                    className="report-sev-legend-item"
                  >
                    <span
                      className={
                        `badge badge-sm ${
                          severityBadgeClass(
                            segment.key,
                          )
                        }`
                      }
                    >
                      {segment.label
                        .toUpperCase()}
                    </span>

                    <span className="report-sev-count">
                      {segment.count}
                    </span>
                  </span>
                ),
              )}
            </div>
          </>
        )}
      </section>

      <div
        className="report-two-col"
        style={{ "--i": 4 } as CSSProperties}
      >
        <section className="panel">
          <div className="panel-header">
            <div>
              <p className="eyebrow">
                EXECUTIVE SUMMARY
              </p>

              <h3 className="panel-title">
                Security posture
              </h3>
            </div>
          </div>

          <dl className="report-kv">
            <div>
              <dt>Cloud assets</dt>
              <dd>{summary.total_assets}</dd>
            </div>

            <div>
              <dt>Security relationships</dt>
              <dd>
                {summary.total_relationships}
              </dd>
            </div>

            <div>
              <dt>Sensitive assets</dt>
              <dd>{summary.sensitive_assets}</dd>
            </div>

            <div>
              <dt>Findings</dt>
              <dd>{summary.findings}</dd>
            </div>

            <div>
              <dt>Identity risks</dt>
              <dd>
                {report.identity_risks.length}
              </dd>
            </div>

            <div>
              <dt>Network risks</dt>
              <dd>
                {report.network_risks.length}
              </dd>
            </div>
          </dl>
        </section>

        <section className="panel">
          <div className="panel-header">
            <div>
              <p className="eyebrow">
                COMPLIANCE
              </p>

              <h3 className="panel-title">
                Evidence mapping
              </h3>
            </div>
          </div>

          <dl className="report-kv">
            <div>
              <dt>Frameworks</dt>
              <dd>{compliance.frameworks}</dd>
            </div>

            <div>
              <dt>Mapped controls</dt>
              <dd>
                {compliance.mapped_controls}
              </dd>
            </div>

            <div>
              <dt>Non-compliant</dt>
              <dd>
                {
                  compliance
                    .non_compliant_controls
                }
              </dd>
            </div>

            <div>
              <dt>Not assessed</dt>
              <dd>
                {
                  compliance
                    .not_assessed_controls
                }
              </dd>
            </div>

            <div>
              <dt>Mapped findings</dt>
              <dd>
                {compliance.mapped_findings}
              </dd>
            </div>
          </dl>
        </section>
      </div>

      <section
        className="panel"
        style={{ "--i": 5 } as CSSProperties}
      >
        <div className="panel-header">
          <div>
            <p className="eyebrow">
              HIGHEST PRIORITY
            </p>

            <h3 className="panel-title">
              Top findings
            </h3>
          </div>

          <span className="badge badge-neutral no-dot">
            {"Top "}
            {topFindings.length}
            {" of "}
            {report.findings.length}
          </span>
        </div>

        {topFindings.length === 0 ? (
          <p className="report-panel-empty muted">
            No findings were recorded in this
            assessment.
          </p>
        ) : (
          <ol className="report-top-list">
            {topFindings.map((finding) => (
              <TopFindingRow
                key={finding.id}
                finding={finding}
              />
            ))}
          </ol>
        )}
      </section>

      <section
        className="panel"
        style={{ "--i": 6 } as CSSProperties}
      >
        <div className="panel-header">
          <div>
            <p className="eyebrow">
              ATTACK PATHS
            </p>

            <h3 className="panel-title">
              Internet to sensitive resource
            </h3>
          </div>

          <span className="badge badge-neutral no-dot">
            {summary.attack_paths}
            {" paths"}
          </span>
        </div>

        {primaryAttackPath ? (
          <div className="panel-body">
            <p className="secondary report-path-intro">
              Highest-priority path (
              {
                primaryAttackPath.hop_count
              }
              {" "}
              {
                primaryAttackPath.hop_count === 1
                  ? "hop"
                  : "hops"
              }
              ). The full set is explored on the
              Attack Paths page.
            </p>

            <div className="report-path">
              {primaryAttackPath.nodes.map(
                (node, index) => (
                  <div
                    className="report-path-segment"
                    key={`${node}-${index}`}
                  >
                    <div className="report-path-node">
                      <span
                        className="report-path-index"
                        aria-hidden="true"
                      >
                        {index + 1}
                      </span>

                      <code className="mono wrap-anywhere">
                        {node}
                      </code>
                    </div>

                    {index
                      < primaryAttackPath.nodes
                          .length
                          - 1 && (
                      <Icon
                        name="chevron-right"
                        size={14}
                        className="report-path-arrow"
                      />
                    )}
                  </div>
                ),
              )}
            </div>
          </div>
        ) : (
          <p className="report-panel-empty muted">
            No attack paths to sensitive assets
            were identified.
          </p>
        )}
      </section>

      <section
        className="panel"
        style={{ "--i": 7 } as CSSProperties}
      >
        <div className="panel-header">
          <div>
            <p className="eyebrow">
              REMEDIATION
            </p>

            <h3 className="panel-title">
              Remediation summary
            </h3>
          </div>

          <span className="badge badge-neutral no-dot">
            {remediableFindings.length}
            {" of "}
            {report.findings.length}
            {" findings have guidance"}
          </span>
        </div>

        {remediationHighlights.length === 0 ? (
          <p className="report-panel-empty muted">
            No remediation guidance is available
            for the recorded findings.
          </p>
        ) : (
          <ul className="report-remediation-list">
            {remediationHighlights.map(
              (finding) => (
                <li key={finding.id}>
                  <div className="report-remediation-head">
                    <span
                      className={
                        `badge badge-sm ${
                          severityBadgeClass(
                            finding.severity,
                          )
                        }`
                      }
                    >
                      {finding.severity
                        .toUpperCase()}
                    </span>

                    <strong>
                      {finding.title}
                    </strong>
                  </div>

                  <p className="secondary">
                    {finding.remediation}
                  </p>
                </li>
              ),
            )}
          </ul>
        )}
      </section>

      <section
        className="panel"
        style={{ "--i": 8 } as CSSProperties}
      >
        <div className="panel-header">
          <div>
            <p className="eyebrow">
              PRIORITIZED FINDINGS
            </p>

            <h3 className="panel-title">
              Security findings
            </h3>
          </div>

          <span className="badge badge-neutral no-dot">
            {report.findings.length}
          </span>
        </div>

        {report.findings.length === 0 ? (
          <p className="report-panel-empty muted">
            No findings were recorded in this
            assessment.
          </p>
        ) : (
          <ul className="report-findings-list">
            {report.findings.map((finding) => (
              <li
                className="report-finding-row"
                key={finding.id}
              >
                <div className="report-finding-main">
                  <div className="report-finding-title">
                    <span
                      className={
                        `badge badge-sm ${
                          severityBadgeClass(
                            finding.severity,
                          )
                        }`
                      }
                    >
                      {finding.severity
                        .toUpperCase()}
                    </span>

                    <strong>
                      {finding.title}
                    </strong>
                  </div>

                  <p className="secondary">
                    {finding.description}
                  </p>

                  <code className="mono wrap-anywhere report-finding-id">
                    {finding.id}
                  </code>
                </div>

                <div className="report-finding-score">
                  <strong>
                    {finding.risk_score}
                  </strong>

                  <span>RISK</span>
                </div>
              </li>
            ))}
          </ul>
        )}
      </section>

      <div
        className="report-two-col"
        style={{ "--i": 9 } as CSSProperties}
      >
        <section className="panel">
          <div className="panel-header">
            <div>
              <p className="eyebrow">
                IDENTITY RISK
              </p>

              <h3 className="panel-title">
                IAM exposure
              </h3>
            </div>
          </div>

          {report.identity_risks.length === 0 ? (
            <p className="report-panel-empty muted">
              No identity risks were identified.
            </p>
          ) : (
            <div className="report-risk-list">
              {report.identity_risks.map(
                (risk) => (
                  <article
                    className="report-risk-card"
                    key={risk.identity_id}
                  >
                    <div className="report-risk-head">
                      <div className="report-risk-name">
                        <strong>
                          {risk.identity_name}
                        </strong>

                        <span className="muted">
                          {risk.identity_type}
                        </span>
                      </div>

                      <div className="report-risk-score">
                        <strong>
                          {risk.risk_score}
                        </strong>

                        <span
                          className={
                            `badge badge-sm ${
                              severityBadgeClass(
                                risk.severity,
                              )
                            }`
                          }
                        >
                          {risk.severity
                            .toUpperCase()}
                        </span>
                      </div>
                    </div>

                    <ul>
                      {risk.risk_factors.map(
                        (factor) => (
                          <li key={factor}>
                            {factor}
                          </li>
                        ),
                      )}
                    </ul>
                  </article>
                ),
              )}
            </div>
          )}
        </section>

        <section className="panel">
          <div className="panel-header">
            <div>
              <p className="eyebrow">
                NETWORK RISK
              </p>

              <h3 className="panel-title">
                Public exposure
              </h3>
            </div>
          </div>

          {report.network_risks.length === 0 ? (
            <p className="report-panel-empty muted">
              No network exposure risks were
              identified.
            </p>
          ) : (
            <div className="report-risk-list">
              {report.network_risks.map(
                (risk) => (
                  <article
                    className="report-risk-card"
                    key={risk.asset_id}
                  >
                    <div className="report-risk-head">
                      <div className="report-risk-name">
                        <strong>
                          {risk.asset_name}
                        </strong>

                        <span className="mono muted wrap-anywhere">
                          {risk.public_ip
                            ?? "No public IP"}
                        </span>
                      </div>

                      <div className="report-risk-score">
                        <strong>
                          {risk.risk_score}
                        </strong>

                        <span
                          className={
                            `badge badge-sm ${
                              severityBadgeClass(
                                risk.severity,
                              )
                            }`
                          }
                        >
                          {risk.severity
                            .toUpperCase()}
                        </span>
                      </div>
                    </div>

                    <ul>
                      {risk.risk_factors.map(
                        (factor) => (
                          <li key={factor}>
                            {factor}
                          </li>
                        ),
                      )}
                    </ul>
                  </article>
                ),
              )}
            </div>
          )}
        </section>
      </div>

      <section
        className="panel"
        style={{ "--i": 10 } as CSSProperties}
      >
        <div className="panel-header">
          <div>
            <p className="eyebrow">
              ASSESSMENT LIMITATIONS
            </p>

            <h3 className="panel-title">
              Interpretation notes
            </h3>
          </div>
        </div>

        <div className="panel-body">
          <ul className="report-limitations">
            {report.limitations.map(
              (limitation) => (
                <li key={limitation}>
                  {limitation}
                </li>
              ),
            )}
          </ul>
        </div>
      </section>
    </>
  );
}


function TopFindingRow({
  finding,
}: {
  finding: ReportFinding;
}) {
  return (
    <li className="report-top-row">
      <div className="report-finding-main">
        <div className="report-finding-title">
          <span
            className={
              `badge badge-sm ${
                severityBadgeClass(
                  finding.severity,
                )
              }`
            }
          >
            {finding.severity.toUpperCase()}
          </span>

          <strong>{finding.title}</strong>
        </div>

        <p className="secondary">
          {finding.description}
        </p>

        <code className="mono wrap-anywhere report-finding-id">
          {finding.id}
        </code>
      </div>

      <div className="report-finding-score">
        <strong>{finding.risk_score}</strong>

        <span>RISK</span>
      </div>
    </li>
  );
}


export default Reports;
