import {
  useEffect,
  useState,
} from "react";

import {
  getSecurityReport,
} from "../services/api";

import type {
  SecurityReport,
} from "../types/cloudguard";


function Reports() {
  const [
    report,
    setReport,
  ] = useState<SecurityReport | null>(
    null,
  );

  const [
    loading,
    setLoading,
  ] = useState(true);

  const [
    error,
    setError,
  ] = useState<string | null>(null);


  useEffect(() => {
    async function loadReport() {
      try {
        setLoading(true);
        setError(null);

        const data =
          await getSecurityReport();

        setReport(data);
      } catch (err) {
        const message =
          err instanceof Error
            ? err.message
            : "Unable to load security report.";

        setError(message);
      } finally {
        setLoading(false);
      }
    }

    void loadReport();
  }, []);


  function downloadPdf() {
    window.location.href =
      "/api/report/pdf";
  }


  if (loading) {
    return (
      <section className="reports-page">
        <div className="page-header">
          <div>
            <span className="page-eyebrow">
              SECURITY ASSESSMENT
            </span>

            <h2>Reports</h2>

            <p>
              Building CloudGuard security
              assessment...
            </p>
          </div>
        </div>

        <div className="report-state-card">
          Loading security report...
        </div>
      </section>
    );
  }


  if (error || report === null) {
    return (
      <section className="reports-page">
        <div className="page-header">
          <div>
            <span className="page-eyebrow">
              SECURITY ASSESSMENT
            </span>

            <h2>Reports</h2>

            <p>
              Consolidated cloud security
              intelligence.
            </p>
          </div>
        </div>

        <div className="report-state-card">
          <strong>
            Report unavailable
          </strong>

          <p>
            {error ??
              "No report data was returned."}
          </p>
        </div>
      </section>
    );
  }


  const {
    summary,
    compliance,
  } = report;

  const topFinding =
    report.findings.length > 0
      ? report.findings[0]
      : null;

  const primaryAttackPath =
    report.attack_paths.length > 0
      ? report.attack_paths[0]
      : null;


  return (
    <section className="reports-page">
      <div className="page-header report-page-header">
        <div>
          <span className="page-eyebrow">
            SECURITY ASSESSMENT
          </span>

          <h2>
            {report.report_name}
          </h2>

          <p>
            Consolidated security posture,
            attack-path, identity, network,
            findings and compliance evidence.
          </p>
        </div>

        <div className="report-header-meta">
          <span className="report-mode-badge">
            {report.assessment_mode.toUpperCase()}
          </span>

          <span>
            Report v{report.report_version}
          </span>

          <button
            type="button"
            className="report-download-button"
            onClick={downloadPdf}
          >
            Download PDF
          </button>
        </div>
      </div>


      <div className="report-scope-banner">
        <div>
          <span className="report-section-label">
            ASSESSMENT SCOPE
          </span>

          <p>
            {report.scope_note}
          </p>
        </div>
      </div>


      <div className="report-metrics-grid">
        <article className="report-metric-card">
          <span>Highest Risk</span>

          <strong>
            {summary.highest_risk_score}
          </strong>

          <small>
            Maximum correlated risk score
          </small>
        </article>

        <article className="report-metric-card">
          <span>Critical</span>

          <strong>
            {summary.critical_findings}
          </strong>

          <small>
            Critical security findings
          </small>
        </article>

        <article className="report-metric-card">
          <span>High</span>

          <strong>
            {summary.high_findings}
          </strong>

          <small>
            High severity findings
          </small>
        </article>

        <article className="report-metric-card">
          <span>Attack Paths</span>

          <strong>
            {summary.attack_paths}
          </strong>

          <small>
            Paths to sensitive assets
          </small>
        </article>

        <article className="report-metric-card">
          <span>Exposed Assets</span>

          <strong>
            {summary.internet_exposed_assets}
          </strong>

          <small>
            Internet-exposed resources
          </small>
        </article>

        <article className="report-metric-card">
          <span>Assets</span>

          <strong>
            {summary.total_assets}
          </strong>

          <small>
            Assets represented in graph
          </small>
        </article>
      </div>


      <div className="report-content-grid">
        <article className="report-panel">
          <div className="report-panel-header">
            <div>
              <span className="report-section-label">
                EXECUTIVE SUMMARY
              </span>

              <h3>
                Security posture
              </h3>
            </div>
          </div>

          <div className="report-summary-list">
            <div>
              <span>
                Cloud assets
              </span>

              <strong>
                {summary.total_assets}
              </strong>
            </div>

            <div>
              <span>
                Security relationships
              </span>

              <strong>
                {summary.total_relationships}
              </strong>
            </div>

            <div>
              <span>
                Sensitive assets
              </span>

              <strong>
                {summary.sensitive_assets}
              </strong>
            </div>

            <div>
              <span>
                Findings
              </span>

              <strong>
                {summary.findings}
              </strong>
            </div>

            <div>
              <span>
                Identity risks
              </span>

              <strong>
                {report.identity_risks.length}
              </strong>
            </div>

            <div>
              <span>
                Network risks
              </span>

              <strong>
                {report.network_risks.length}
              </strong>
            </div>
          </div>
        </article>


        <article className="report-panel">
          <div className="report-panel-header">
            <div>
              <span className="report-section-label">
                COMPLIANCE
              </span>

              <h3>
                Evidence mapping
              </h3>
            </div>
          </div>

          <div className="report-summary-list">
            <div>
              <span>
                Frameworks
              </span>

              <strong>
                {compliance.frameworks}
              </strong>
            </div>

            <div>
              <span>
                Mapped controls
              </span>

              <strong>
                {compliance.mapped_controls}
              </strong>
            </div>

            <div>
              <span>
                Non-compliant
              </span>

              <strong>
                {
                  compliance
                    .non_compliant_controls
                }
              </strong>
            </div>

            <div>
              <span>
                Not assessed
              </span>

              <strong>
                {
                  compliance
                    .not_assessed_controls
                }
              </strong>
            </div>

            <div>
              <span>
                Mapped findings
              </span>

              <strong>
                {compliance.mapped_findings}
              </strong>
            </div>
          </div>
        </article>
      </div>


      {topFinding && (
        <article className="report-panel report-priority-panel">
          <div className="report-panel-header">
            <div>
              <span className="report-section-label">
                TOP PRIORITY
              </span>

              <h3>
                {topFinding.title}
              </h3>
            </div>

            <div className="report-risk-group">
              <span
                className={`severity-badge ${topFinding.severity.toLowerCase()}`}
              >
                {topFinding.severity}
              </span>

              <strong>
                {topFinding.risk_score}/100
              </strong>
            </div>
          </div>

          <p className="report-description">
            {topFinding.description}
          </p>

          <div className="report-detail-columns">
            <div>
              <span className="report-section-label">
                AFFECTED ASSETS
              </span>

              <div className="report-chip-list">
                {topFinding.affected_assets.map(
                  (asset) => (
                    <span
                      className="report-chip"
                      key={asset}
                    >
                      {asset}
                    </span>
                  ),
                )}
              </div>
            </div>

            <div>
              <span className="report-section-label">
                REMEDIATION
              </span>

              <p>
                {topFinding.remediation ??
                  "No remediation guidance available."}
              </p>
            </div>
          </div>
        </article>
      )}


      {primaryAttackPath && (
        <article className="report-panel">
          <div className="report-panel-header">
            <div>
              <span className="report-section-label">
                ATTACK PATH
              </span>

              <h3>
                Internet to sensitive resource
              </h3>
            </div>

            <span className="report-hop-count">
              {primaryAttackPath.hop_count}
              {" "}
              hops
            </span>
          </div>

          <div className="report-attack-path">
            {primaryAttackPath.nodes.map(
              (node, index) => (
                <div
                  className="report-path-segment"
                  key={`${node}-${index}`}
                >
                  <div className="report-path-node">
                    <span>
                      {index + 1}
                    </span>

                    <strong>
                      {node}
                    </strong>
                  </div>

                  {index <
                    primaryAttackPath.nodes.length -
                      1 && (
                    <span className="report-path-arrow">
                      →
                    </span>
                  )}
                </div>
              ),
            )}
          </div>
        </article>
      )}


      <article className="report-panel">
        <div className="report-panel-header">
          <div>
            <span className="report-section-label">
              PRIORITIZED FINDINGS
            </span>

            <h3>
              Security findings
            </h3>
          </div>

          <span className="report-count-badge">
            {report.findings.length}
          </span>
        </div>

        <div className="report-findings-list">
          {report.findings.map(
            (finding) => (
              <div
                className="report-finding-row"
                key={finding.id}
              >
                <div className="report-finding-main">
                  <div className="report-finding-title">
                    <span
                      className={`severity-badge ${finding.severity.toLowerCase()}`}
                    >
                      {finding.severity}
                    </span>

                    <strong>
                      {finding.title}
                    </strong>
                  </div>

                  <p>
                    {finding.description}
                  </p>

                  <span className="report-finding-id">
                    {finding.id}
                  </span>
                </div>

                <div className="report-finding-score">
                  <strong>
                    {finding.risk_score}
                  </strong>

                  <span>
                    RISK
                  </span>
                </div>
              </div>
            ),
          )}
        </div>
      </article>


      <div className="report-content-grid">
        <article className="report-panel">
          <div className="report-panel-header">
            <div>
              <span className="report-section-label">
                IDENTITY RISK
              </span>

              <h3>
                IAM exposure
              </h3>
            </div>
          </div>

          {report.identity_risks.map(
            (risk) => (
              <div
                className="report-risk-card"
                key={risk.identity_id}
              >
                <div>
                  <strong>
                    {risk.identity_name}
                  </strong>

                  <span>
                    {risk.identity_type}
                  </span>
                </div>

                <div className="report-risk-score">
                  <strong>
                    {risk.risk_score}
                  </strong>

                  <span>
                    {risk.severity.toUpperCase()}
                  </span>
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
              </div>
            ),
          )}
        </article>


        <article className="report-panel">
          <div className="report-panel-header">
            <div>
              <span className="report-section-label">
                NETWORK RISK
              </span>

              <h3>
                Public exposure
              </h3>
            </div>
          </div>

          {report.network_risks.map(
            (risk) => (
              <div
                className="report-risk-card"
                key={risk.asset_id}
              >
                <div>
                  <strong>
                    {risk.asset_name}
                  </strong>

                  <span>
                    {risk.public_ip ??
                      "No public IP"}
                  </span>
                </div>

                <div className="report-risk-score">
                  <strong>
                    {risk.risk_score}
                  </strong>

                  <span>
                    {risk.severity.toUpperCase()}
                  </span>
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
              </div>
            ),
          )}
        </article>
      </div>


      <article className="report-panel">
        <div className="report-panel-header">
          <div>
            <span className="report-section-label">
              ASSESSMENT LIMITATIONS
            </span>

            <h3>
              Interpretation notes
            </h3>
          </div>
        </div>

        <ul className="report-limitations">
          {report.limitations.map(
            (limitation) => (
              <li key={limitation}>
                {limitation}
              </li>
            ),
          )}
        </ul>
      </article>
    </section>
  );
}


export default Reports;