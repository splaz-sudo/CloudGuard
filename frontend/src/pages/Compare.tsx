import {
  useEffect,
  useState,
} from "react";

import { useScanContext } from "../context/ScanContext";
import { useApiQuery } from "../hooks/useApiQuery";
import { compareScans } from "../services/api";

import type {
  AttackPathChange,
  FindingChange,
} from "../types/cloudguard";


function Compare() {
  const { scans, loading } =
    useScanContext();

  const completed = scans.filter(
    (record) =>
      record.status === "completed"
      || record.status === "partial",
  );

  const [scanA, setScanA] =
    useState<string>("");

  const [scanB, setScanB] =
    useState<string>("");


  useEffect(() => {
    if (completed.length === 0) {
      return;
    }

    setScanA((current) =>
      current
      || completed[
        Math.min(
          1,
          completed.length - 1,
        )
      ].scan_id,
    );

    setScanB((current) =>
      current
      || completed[0].scan_id,
    );
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [completed.length]);


  const canCompare =
    scanA !== ""
    && scanB !== ""
    && scanA !== scanB;

  const comparison = useApiQuery(
    () => compareScans(scanA, scanB),
    [scanA, scanB],
  );


  if (loading) {
    return (
      <section className="page-state">
        Loading scans...
      </section>
    );
  }


  return (
    <>
      <header className="topbar">
        <div>
          <p className="eyebrow">
            POSTURE CHANGE
          </p>

          <h2>Compare Scans</h2>

          <p className="subtitle">
            Observation-based comparison of two
            scans. CloudGuard reports what
            changed; it does not claim it
            caused the change.
          </p>
        </div>
      </header>

      <section className="panel">
        <div className="compare-selectors">
          <ScanPicker
            label="SCAN A (before)"
            scans={completed}
            value={scanA}
            onChange={setScanA}
          />

          <span className="arrow">→</span>

          <ScanPicker
            label="SCAN B (after)"
            scans={completed}
            value={scanB}
            onChange={setScanB}
          />
        </div>

        {!canCompare && (
          <p className="details-text">
            Select two different completed
            scans to compare. Run additional
            scans from the Scans page if
            needed.
          </p>
        )}
      </section>

      {canCompare
        && comparison.loading && (
        <section className="page-state">
          Comparing scans...
        </section>
      )}

      {/* Error and results are mutually exclusive: the query hook clears
          stale data whenever a new request starts, so a failure can never
          render alongside a payload that belongs to a different request. */}
      {canCompare
        && comparison.error
        && !comparison.data && (
        <section className="page-state error-message">
          <div>
            <h2>Comparison failed</h2>

            <p>
              {comparison.error.message}
            </p>

            <button
              type="button"
              onClick={
                comparison.retry
              }
            >
              Retry
            </button>
          </div>
        </section>
      )}

      {canCompare
        && !comparison.loading
        && !comparison.error
        && comparison.data && (
        <ComparisonView
          comparison={
            comparison.data
          }
        />
      )}
    </>
  );
}


function ScanPicker({
  label,
  scans,
  value,
  onChange,
}: {
  label: string;
  scans: {
    scan_id: string;
    environment: string;
    created_at: string;
  }[];
  value: string;
  onChange: (value: string) => void;
}) {
  return (
    <div className="compare-picker">
      <label>{label}</label>

      <select
        value={value}
        onChange={(event) => {
          onChange(event.target.value);
        }}
      >
        {scans.map((record) => (
          <option
            key={record.scan_id}
            value={record.scan_id}
          >
            {record.environment}
            {" · "}
            {record.created_at
              .replace("T", " ")
              .slice(5, 16)}
            {" · "}
            {record.scan_id.slice(0, 13)}
          </option>
        ))}
      </select>
    </div>
  );
}


function ComparisonView({
  comparison,
}: {
  comparison: import(
    "../types/cloudguard"
  ).ComparisonResult;
}) {
  const improved =
    comparison.risk_delta < 0;

  const regressed =
    comparison.risk_delta > 0;

  return (
    <>
      <section className="metric-grid">
        <article className="metric-card risk-card">
          <span className="metric-label">
            Highest Risk
          </span>

          <strong className="risk-score">
            {comparison.risk_before}
            {" → "}
            {comparison.risk_after}
          </strong>

          <span
            className={
              "metric-detail "
              + (improved
                ? "delta-good"
                : regressed
                  ? "delta-bad"
                  : "")
            }
          >
            {comparison.risk_delta === 0
              ? "no change"
              : comparison.risk_delta < 0
                ? `↓ ${-comparison.risk_delta} improved`
                : `↑ ${comparison.risk_delta} regressed`}
          </span>
        </article>

        <article className="metric-card">
          <span className="metric-label">
            Attack Paths
          </span>

          <strong>
            {comparison.paths_before}
            {" → "}
            {comparison.paths_after}
          </strong>

          <span className="metric-detail">
            {comparison.resolved_paths.length}
            {" resolved · "}
            {comparison.new_paths.length}
            {" new"}
          </span>
        </article>

        <article className="metric-card">
          <span className="metric-label">
            Findings
          </span>

          <strong>
            {comparison.findings_before}
            {" → "}
            {comparison.findings_after}
          </strong>

          <span className="metric-detail">
            {
              comparison
                .resolved_findings
                .length
            }
            {" resolved · "}
            {
              comparison.new_findings.length
            }
            {" new"}
          </span>
        </article>
      </section>

      <section className="compare-grid">
        <ChangePanel
          title="RESOLVED"
          tone="good"
          findings={
            comparison.resolved_findings
          }
          paths={
            comparison.resolved_paths
          }
          empty="Nothing was resolved."
        />

        <ChangePanel
          title="UNCHANGED"
          tone="neutral"
          findings={
            comparison.unchanged_findings
          }
          paths={
            comparison.unchanged_paths
          }
          empty="Nothing remained unchanged."
        />

        <ChangePanel
          title="NEW"
          tone="bad"
          findings={
            comparison.new_findings
          }
          paths={comparison.new_paths}
          empty="No new issues appeared."
        />
      </section>

      <p className="comparison-note">
        {comparison.note}
      </p>
    </>
  );
}


function ChangePanel({
  title,
  tone,
  findings,
  paths,
  empty,
}: {
  title: string;
  tone: "good" | "neutral" | "bad";
  findings: FindingChange[];
  paths: AttackPathChange[];
  empty: string;
}) {
  const marker =
    tone === "good"
      ? "✓"
      : tone === "bad"
        ? "!"
        : "●";

  return (
    <article
      className={
        `panel change-panel ${tone}`
      }
    >
      <p className="eyebrow">{title}</p>

      {findings.length === 0
      && paths.length === 0 ? (
        <p className="details-text">
          {empty}
        </p>
      ) : (
        <ul className="change-list">
          {findings.map((finding) => (
            <li key={finding.fingerprint}>
              <span
                className={
                  `change-marker ${tone}`
                }
              >
                {marker}
              </span>

              <div>
                <strong>
                  {finding.title}
                </strong>

                <span>
                  {finding.finding_id}
                  {" · risk "}
                  {finding.risk_score}
                </span>
              </div>
            </li>
          ))}

          {paths.map((path) => (
            <li key={path.path_id}>
              <span
                className={
                  `change-marker ${tone}`
                }
              >
                {marker}
              </span>

              <div>
                <strong>
                  {path.nodes.join(" → ")}
                </strong>

                <span>
                  {path.path_id}
                  {" · risk "}
                  {path.risk_score}
                </span>
              </div>
            </li>
          ))}
        </ul>
      )}
    </article>
  );
}


export default Compare;
