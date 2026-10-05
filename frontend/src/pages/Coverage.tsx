import {
  useEffect,
  useState,
} from "react";

import {
  useScanContext,
} from "../context/ScanContext";

import { getScanCollectorResults } from "../services/api";

import type {
  CollectorResult,
} from "../types/cloudguard";


function Coverage() {
  const { selectedScan } =
    useScanContext();

  const scanId =
    selectedScan?.scan_id ?? null;

  const [collectorResults, setCollectorResults] =
    useState<CollectorResult[]>([]);

  const [loading, setLoading] =
    useState(true);

  const [error, setError] =
    useState<string | null>(null);


  useEffect(() => {
    if (!scanId) {
      return;
    }

    const currentScanId: string = scanId;

    async function loadCoverage() {
      setLoading(true);
      setError(null);

      try {
        const data = await getScanCollectorResults(
          currentScanId,
        );

        setCollectorResults(data);
      } catch (requestError) {
        const message =
          requestError instanceof Error
            ? requestError.message
            : "Unable to load coverage data.";

        setError(message);
      } finally {
        setLoading(false);
      }
    }

    loadCoverage();
  }, [scanId]);


  const servicesAttempted = collectorResults.length;
  const servicesSuccessful = collectorResults.filter(
    (r) => r.status === "success",
  ).length;
  const servicesFailed = collectorResults.filter(
    (r) => r.status === "failed",
  ).length;
  const servicesPartial = collectorResults.filter(
    (r) => r.status === "partial",
  ).length;

  const totalResources = collectorResults.reduce(
    (sum, r) => sum + r.resources_discovered,
    0,
  );

// Service status and per-service breakdowns available for future use


  if (loading) {
    return (
      <section className="page-state">
        Loading coverage data...
      </section>
    );
  }


  if (error) {
    return (
      <section className="page-state error-message">
        {error}
      </section>
    );
  }


  if (collectorResults.length === 0) {
    return (
      <section className="page-state">
        <p>No collector results available for this scan.</p>
        <p className="details-text">
          Run a scan to see coverage information.
        </p>
      </section>
    );
  }


  return (
    <>
      <header className="topbar">
        <div>
          <p className="eyebrow">
            COVERAGE
          </p>

          <h2>Collection Coverage</h2>

          <p className="subtitle">
            Services scanned, resources discovered,
            and collection status.
          </p>
        </div>

        <div className="environment-badge">
          {servicesAttempted} SERVICES ATTEMPTED
        </div>
      </header>

      <section className="metric-grid">
        <MetricCard
          label="Services Attempted"
          value={servicesAttempted}
        />
        <MetricCard
          label="Successful"
          value={servicesSuccessful}
          detail={`${servicesSuccessful}/${servicesAttempted}`}
        />
        <MetricCard
          label="Partial"
          value={servicesPartial}
          detail="Limited data"
        />
        <MetricCard
          label="Failed"
          value={servicesFailed}
          detail="Access denied or error"
        />
      </section>

      <section className="panel">
        <div className="panel-header">
          <div>
            <p className="eyebrow">
              SERVICE COVERAGE
            </p>

            <h3>Per-Service Status</h3>
          </div>
        </div>

        <div className="coverage-table-wrapper">
          <table className="coverage-table">
            <thead>
              <tr>
                <th>Service</th>
                <th>Status</th>
                <th>Resources</th>
                <th>Duration</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {collectorResults.map((result) => (
                <tr key={`${result.collector}-${result.service}-${result.region}`}>
                  <td>
                    <span className="service-name">
                      {result.service}
                      {result.region && (
                        <span className="region-badge">
                          {result.region}
                        </span>
                      )}
                    </span>
                  </td>
                  <td>
                    <span
                      className={`status-badge ${result.status}`}
                    >
                      {result.status.toUpperCase()}
                    </span>
                  </td>
                  <td>
                    {result.resources_discovered}
                  </td>
                  <td>
                    {result.duration_ms.toFixed(0)} ms
                  </td>
                  <td>
                    {result.error_message ? (
                      <span className="error-text">
                        {result.error_message}
                      </span>
                    ) : result.coverage_limitation ? (
                      <span className="warning-text">
                        {result.coverage_limitation}
                      </span>
                    ) : (
                      <span className="success-text">
                        Complete
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="panel">
        <div className="panel-header">
          <div>
            <p className="eyebrow">
              COVERAGE SUMMARY
            </p>

            <h3>Resource Discovery</h3>
          </div>
        </div>

        <div className="coverage-summary-grid">
          <CoverageSummaryCard
            label="Total Resources"
            value={totalResources}
            tone="primary"
          />
          <CoverageSummaryCard
            label="Services Successful"
            value={servicesSuccessful}
            detail={`${servicesSuccessful}/${servicesAttempted}`}
            tone="success"
          />
          <CoverageSummaryCard
            label="Services Partial"
            value={servicesPartial}
            detail="Limited data"
            tone="warning"
          />
          <CoverageSummaryCard
            label="Services Failed"
            value={servicesFailed}
            detail="Check permissions"
            tone="danger"
          />
        </div>

        <div className="coverage-chart">
          <div className="chart-bars">
            <div
              className="chart-bar success"
              style={{
                width: `${servicesAttempted > 0 ? (servicesSuccessful / servicesAttempted) * 100 : 0}%`,
              }}
              title={`${servicesSuccessful} Successful`}
            />
            <div
              className="chart-bar partial"
              style={{
                width: `${servicesAttempted > 0 ? (servicesPartial / servicesAttempted) * 100 : 0}%`,
              }}
              title={`${servicesPartial} Partial`}
            />
            <div
              className="chart-bar failed"
              style={{
                width: `${servicesAttempted > 0 ? (servicesFailed / servicesAttempted) * 100 : 0}%`,
              }}
              title={`${servicesFailed} Failed`}
            />
          </div>
          <div className="chart-legend">
            <span className="legend-item success">
              <span className="legend-color success" />
              Successful
            </span>
            <span className="legend-item partial">
              <span className="legend-color partial" />
              Partial
            </span>
            <span className="legend-item failed">
              <span className="legend-color failed" />
              Failed
            </span>
          </div>
        </div>
      </section>

      <section className="panel">
        <div className="panel-header">
          <div>
            <p className="eyebrow">
              LIMITATIONS
            </p>

            <h3>Known Coverage Gaps</h3>
          </div>
        </div>

        <ul className="limitations-list">
          <li>
            <strong>Cross-account resources</strong> not scanned unless
            cross-account roles are configured.
          </li>
          <li>
            <strong>Regional services</strong> only scanned in configured
            regions; global services (IAM, CloudFront) scanned once.
          </li>
          <li>
            <strong>AccessDenied errors</strong> indicate missing
            permissions; resources not scanned.
          </li>
          <li>
            <strong>Service quotas</strong> may limit results for
            large accounts (e.g., EC2 DescribeInstances).
          </li>
          <li>
            <strong>Unsupported services</strong> not yet implemented
            in CloudGuard collectors.
          </li>
        </ul>
      </section>
    </>
  );
}


function CoverageSummaryCard({
  label,
  value,
  detail,
  tone = "primary",
}: {
  label: string;
  value: number;
  detail?: string;
  tone?: "primary" | "success" | "warning" | "danger";
}) {
  return (
    <article
      className={`coverage-summary-card ${tone}`}
    >
      <span className="summary-label">
        {label}
      </span>

      <strong>{value}</strong>

      {detail && (
        <span className="summary-detail">
          {detail}
        </span>
      )}
    </article>
  );
}

function MetricCard({
  label,
  value,
  detail,
}: {
  label: string;
  value: number | string;
  detail?: string;
}) {
  return (
    <article className="metric-card">
      <span className="metric-label">
        {label}
      </span>

      <strong>{value}</strong>

      {detail && (
        <span className="metric-detail">
          {detail}
        </span>
      )}
    </article>
  );
}

export default Coverage;