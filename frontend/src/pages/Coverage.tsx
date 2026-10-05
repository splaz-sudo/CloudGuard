import {
  type CSSProperties,
  type ReactNode,
} from "react";

import {
  EmptyState,
  ErrorState,
  LoadingState,
} from "../components/StateBlock";

import {
  useScanContext,
} from "../context/ScanContext";

import { useScanQuery } from "../hooks/useApiQuery";
import { getScanCollectorResults } from "../services/api";

import type {
  CollectorResult,
} from "../types/cloudguard";

import "../styles/coverage.css";


const STATUS_BADGE: Record<
  CollectorResult["status"],
  string
> = {
  success: "badge-success",
  partial: "badge-warning",
  failed: "badge-danger",
};


function percent(
  part: number,
  whole: number,
): string {
  if (whole === 0) {
    return "0%";
  }

  return `${Math.round((part / whole) * 100)}%`;
}


function Coverage() {
  const {
    selectedScan,
    loading: scansLoading,
  } = useScanContext();

  const scanId =
    selectedScan?.scan_id ?? null;

  // Follows the globally selected scan and
  // re-fetches collector results whenever the
  // selection changes.
  const coverage = useScanQuery(
    getScanCollectorResults,
    scanId,
    { enabled: scanId !== null },
  );

  const results = coverage.data ?? [];

  const attempted = results.length;

  const successful = results.filter(
    (r) => r.status === "success",
  ).length;

  const partial = results.filter(
    (r) => r.status === "partial",
  ).length;

  const failed = results.filter(
    (r) => r.status === "failed",
  ).length;

  const totalResources = results.reduce(
    (sum, r) => sum + r.resources_discovered,
    0,
  );


  let body: ReactNode;

  if (scansLoading) {
    body = (
      <LoadingState label="Loading scans…" />
    );
  } else if (!scanId) {
    body = (
      <EmptyState
        icon="scans"
        title="No scan selected"
        body="Select a scan from the sidebar to view its collection coverage."
      />
    );
  } else if (coverage.loading) {
    body = (
      <LoadingState label="Loading coverage data…" />
    );
  } else if (coverage.error) {
    body = (
      <ErrorState
        error={coverage.error}
        resourceLabel="coverage data"
        onRetry={coverage.retry}
      />
    );
  } else if (results.length === 0) {
    body = (
      <EmptyState
        icon="coverage"
        title="No collector results"
        body="This scan recorded no collector results. Run a new scan to see which services were assessed."
      />
    );
  } else {
    body = (
      <>
        <section
          className="stat-grid coverage-stats"
          style={{ "--i": 1 } as CSSProperties}
        >
          <div className="stat">
            <span className="stat-label">
              Services attempted
            </span>

            <p className="stat-value">
              {attempted}
            </p>

            <p className="stat-foot">
              Collectors run in this scan
            </p>
          </div>

          <div className="stat">
            <span className="stat-label">
              Successful
            </span>

            <p className="stat-value tone-success">
              {successful}
            </p>

            <p className="stat-foot">
              {percent(successful, attempted)}
              {" of attempted"}
            </p>
          </div>

          <div className="stat">
            <span className="stat-label">
              Partial
            </span>

            <p className="stat-value tone-warning">
              {partial}
            </p>

            <p className="stat-foot">
              Limited data collected
            </p>
          </div>

          <div className="stat">
            <span className="stat-label">
              Failed
            </span>

            <p className="stat-value tone-danger">
              {failed}
            </p>

            <p className="stat-foot">
              Access denied or error
            </p>
          </div>

          <div className="stat">
            <span className="stat-label">
              Resources discovered
            </span>

            <p className="stat-value">
              {totalResources}
            </p>

            <p className="stat-foot">
              Across all collectors
            </p>
          </div>
        </section>

        <section
          className="card coverage-health"
          style={{ "--i": 2 } as CSSProperties}
        >
          <div className="card-header">
            <div>
              <p className="card-title">
                Collection health
              </p>

              <p className="card-subtitle">
                Share of attempted collectors by
                outcome
              </p>
            </div>
          </div>

          <div
            className="coverage-segbar"
            role="img"
            aria-label={
              `Collector outcomes: ${successful}`
              + ` successful, ${partial} partial,`
              + ` ${failed} failed out of`
              + ` ${attempted} attempted.`
            }
          >
            {successful > 0 && (
              <span
                className="coverage-seg success"
                style={{
                  width: `${
                    (successful / attempted) * 100
                  }%`,
                }}
                title={
                  `Successful: ${successful}`
                }
              />
            )}

            {partial > 0 && (
              <span
                className="coverage-seg partial"
                style={{
                  width: `${
                    (partial / attempted) * 100
                  }%`,
                }}
                title={`Partial: ${partial}`}
              />
            )}

            {failed > 0 && (
              <span
                className="coverage-seg failed"
                style={{
                  width: `${
                    (failed / attempted) * 100
                  }%`,
                }}
                title={`Failed: ${failed}`}
              />
            )}
          </div>

          <div className="coverage-legend">
            <span className="coverage-legend-item">
              <span
                className="coverage-swatch success"
                aria-hidden="true"
              />
              Successful — {successful}
              {" of "}
              {attempted}
              {" ("}
              {percent(successful, attempted)}
              {")"}
            </span>

            <span className="coverage-legend-item">
              <span
                className="coverage-swatch partial"
                aria-hidden="true"
              />
              Partial — {partial}
              {" of "}
              {attempted}
              {" ("}
              {percent(partial, attempted)}
              {")"}
            </span>

            <span className="coverage-legend-item">
              <span
                className="coverage-swatch failed"
                aria-hidden="true"
              />
              Failed — {failed}
              {" of "}
              {attempted}
              {" ("}
              {percent(failed, attempted)}
              {")"}
            </span>
          </div>
        </section>

        <section
          style={{ "--i": 3 } as CSSProperties}
        >
          <h3 className="section-title">
            Per-service collector results
          </h3>

          <div className="table-wrap coverage-table">
            <div className="table-scroll">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Service</th>
                    <th>Region</th>
                    <th>Status</th>
                    <th className="num">
                      Resources
                    </th>
                    <th className="num">
                      Duration
                    </th>
                    <th>Error / limitation</th>
                  </tr>
                </thead>

                <tbody>
                  {results.map((result) => (
                    <tr
                      key={
                        `${result.collector}-`
                        + `${result.service}-`
                        + `${result.region ?? "global"}`
                      }
                    >
                      <td className="cell-strong">
                        {result.service}

                        <span className="coverage-collector mono">
                          {result.collector}
                        </span>
                      </td>

                      <td>
                        {result.region ?? (
                          <span className="muted">
                            Global
                          </span>
                        )}
                      </td>

                      <td>
                        <span
                          className={
                            `badge ${
                              STATUS_BADGE[
                                result.status
                              ]
                            }`
                          }
                        >
                          {result.status
                            .toUpperCase()}
                        </span>
                      </td>

                      <td className="cell-num">
                        {
                          result
                            .resources_discovered
                        }
                      </td>

                      <td className="cell-num">
                        {result.duration_ms
                          .toFixed(0)}
                        {" ms"}
                      </td>

                      <td className="coverage-detail-cell">
                        {result.error_message ? (
                          <span
                            className="coverage-cell-error truncate"
                            title={
                              result.error_message
                            }
                          >
                            {
                              result.error_message
                            }
                          </span>
                        ) : result.coverage_limitation ? (
                          <span
                            className="coverage-cell-warn truncate"
                            title={
                              result.coverage_limitation
                            }
                          >
                            {
                              result.coverage_limitation
                            }
                          </span>
                        ) : (
                          <span className="muted">
                            —
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </section>

        <section
          className="panel"
          style={{ "--i": 4 } as CSSProperties}
        >
          <div className="panel-header">
            <div>
              <p className="eyebrow">
                LIMITATIONS
              </p>

              <h3 className="panel-title">
                What was not assessed
              </h3>
            </div>
          </div>

          <div className="panel-body">
            <ul className="coverage-limitations">
              <li>
                <strong>
                  Cross-account resources
                </strong>
                {" are not scanned unless "}
                cross-account roles are
                configured.
              </li>

              <li>
                <strong>
                  Regional services
                </strong>
                {" are only scanned in configured"}
                regions; global services (IAM,
                CloudFront) are scanned once.
              </li>

              <li>
                <strong>
                  AccessDenied errors
                </strong>
                {" indicate missing permissions;"}
                the affected resources were not
                scanned.
              </li>

              <li>
                <strong>
                  Service quotas
                </strong>
                {" may limit results for large"}
                accounts (e.g. EC2
                DescribeInstances).
              </li>

              <li>
                <strong>
                  Unsupported services
                </strong>
                {" are not yet implemented in"}
                CloudGuard collectors.
              </li>
            </ul>
          </div>
        </section>
      </>
    );
  }


  return (
    <div className="page">
      <header className="topbar">
        <div>
          <p className="eyebrow">
            COVERAGE
          </p>

          <h2>Collection Coverage</h2>

          <p className="page-subtitle">
            Services scanned, resources
            discovered, and collection status
            for the selected scan.
          </p>
        </div>

        {attempted > 0 && (
          <span className="badge badge-info badge-lg no-dot">
            {attempted}
            {" services attempted"}
          </span>
        )}
      </header>

      {body}
    </div>
  );
}


export default Coverage;
