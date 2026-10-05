import {
  useEffect,
  useState,
  type CSSProperties,
} from "react";

import Icon from "../components/Icon";
import { Select } from "../components/FormControls";
import {
  EmptyState,
  ErrorState,
  LoadingState,
} from "../components/StateBlock";

import { useScanContext } from "../context/ScanContext";
import { useApiQuery } from "../hooks/useApiQuery";
import { compareScans } from "../services/api";

import type {
  AttackPathChange,
  ComparisonResult,
  FindingChange,
  ScanRecord,
} from "../types/cloudguard";

import "../styles/compare.css";


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


function scanOptionLabel(
  record: ScanRecord,
): string {
  return (
    record.environment
    + " · "
    + record.created_at
      .replace("T", " ")
      .slice(5, 16)
    + " · "
    + record.scan_id.slice(0, 13)
  );
}


function formatSigned(delta: number): string {
  if (delta === 0) {
    return "±0";
  }

  return delta > 0
    ? `+${delta}`
    : `−${-delta}`;
}


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


  // Preselect sensible defaults once the scan
  // list is known: latest completed scan as
  // Current (B), the one before it as Baseline (A).
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


  const recordA =
    completed.find(
      (record) => record.scan_id === scanA,
    ) ?? null;

  const recordB =
    completed.find(
      (record) => record.scan_id === scanB,
    ) ?? null;

  const canCompare =
    scanA !== ""
    && scanB !== ""
    && scanA !== scanB
    && recordA !== null
    && recordB !== null;

  // Explain why the compare action is disabled so
  // the user can fix the selection instead of
  // guessing. Only one reason shows at a time.
  let disabledHint: string | null = null;

  if (!loading) {
    if (completed.length < 2) {
      disabledHint =
        "At least two completed or partial "
        + "scans are needed to compare. Run "
        + "another scan from the Scans page.";
    } else if (scanA === "" || scanB === "") {
      disabledHint =
        "Select both a Baseline (A) and a "
        + "Current (B) scan to compare.";
    } else if (scanA === scanB) {
      disabledHint =
        "Baseline (A) and Current (B) must be "
        + "two different scans.";
    } else if (!recordA || !recordB) {
      disabledHint =
        "Both scans must be completed or "
        + "partial to be compared.";
    }
  }

  // The request is gated on a valid selection, so
  // empty or identical scan IDs never reach the
  // API (prevents 400/404 calls). Valid picker
  // changes still auto-compare, as before.
  const comparison = useApiQuery(
    () => compareScans(scanA, scanB),
    [scanA, scanB],
    { immediate: canCompare },
  );


  return (
    <div className="page">
      <header className="topbar">
        <div>
          <p className="eyebrow">
            POSTURE CHANGE
          </p>

          <h2>Compare Scans</h2>

          <p className="page-subtitle">
            Observation-based comparison of two
            scans. CloudGuard reports what
            changed; it does not claim it caused
            the change.
          </p>
        </div>
      </header>

      <section
        className="panel"
        style={{ "--i": 1 } as CSSProperties}
      >
        <div className="panel-body">
          {loading ? (
            <LoadingState
              label="Loading scans…"
              compact
            />
          ) : completed.length === 0 ? (
            <EmptyState
              icon="scans"
              title="No completed scans yet"
              body="Run at least two scans from the Scans page, then return here to compare them."
            />
          ) : (
            <>
              <div className="compare-controls">
                <Select
                  label="Baseline (A) — before"
                  options={completed.map(
                    (record) => ({
                      value: record.scan_id,
                      label:
                        scanOptionLabel(record),
                    }),
                  )}
                  value={scanA}
                  onChange={setScanA}
                  fullWidth
                />

                <span
                  className="compare-controls-arrow"
                  aria-hidden="true"
                >
                  <Icon
                    name="chevron-right"
                    size={18}
                  />
                </span>

                <Select
                  label="Current (B) — after"
                  options={completed.map(
                    (record) => ({
                      value: record.scan_id,
                      label:
                        scanOptionLabel(record),
                    }),
                  )}
                  value={scanB}
                  onChange={setScanB}
                  fullWidth
                />

                <button
                  type="button"
                  className="btn btn-primary compare-button"
                  disabled={
                    !canCompare
                    || comparison.loading
                  }
                  onClick={() =>
                    comparison.refetch()
                  }
                >
                  <Icon name="swap" size={15} />
                  Compare scans
                </button>
              </div>

              {disabledHint ? (
                <p className="field-hint compare-hint">
                  <Icon name="info" size={13} />
                  <span>{disabledHint}</span>
                </p>
              ) : (
                <p className="field-hint compare-hint">
                  <span>
                    Comparing
                    {" "}
                    <code className="mono">
                      {scanA.slice(0, 13)}
                    </code>
                    {" → "}
                    <code className="mono">
                      {scanB.slice(0, 13)}
                    </code>
                    . Change either picker to
                    compare a different pair.
                  </span>
                </p>
              )}
            </>
          )}
        </div>
      </section>

      {canCompare
        && comparison.loading && (
        <LoadingState label="Comparing scans…" />
      )}

      {/* Error and results are mutually exclusive: the query hook clears
          stale data whenever a new request starts, so a failure can never
          render alongside a payload that belongs to a different request. */}
      {canCompare
        && comparison.error
        && !comparison.data && (
        <ErrorState
          error={comparison.error}
          resourceLabel="scan comparison"
          onRetry={comparison.retry}
        />
      )}

      {canCompare
        && !comparison.loading
        && !comparison.error
        && comparison.data && (
        <ComparisonView
          comparison={comparison.data}
        />
      )}
    </div>
  );
}


function DeltaStat({
  label,
  before,
  after,
  chipClass,
  chipLabel,
  foot,
  index,
}: {
  label: string;
  before: number;
  after: number;
  chipClass: string;
  chipLabel: string;
  foot?: string;
  index: number;
}) {
  return (
    <div
      className="compare-delta-item"
      style={{ "--i": index } as CSSProperties}
    >
      <span className="stat-label">
        {label}
      </span>

      <div className="compare-delta-values">
        <span className="compare-delta-num">
          {before}
        </span>

        <Icon
          name="chevron-right"
          size={20}
          className="compare-delta-arrow"
        />

        <span className="compare-delta-num">
          {after}
        </span>

        <span
          className={`badge no-dot ${chipClass}`}
        >
          {chipLabel}
        </span>
      </div>

      {foot ? (
        <span className="stat-foot">
          {foot}
        </span>
      ) : null}
    </div>
  );
}


function ComparisonView({
  comparison,
}: {
  comparison: ComparisonResult;
}) {
  const improved =
    comparison.risk_delta < 0;

  const regressed =
    comparison.risk_delta > 0;

  const riskChipClass = improved
    ? "badge-success"
    : regressed
      ? "badge-danger"
      : "badge-neutral";

  const riskChipLabel =
    comparison.risk_delta === 0
      ? "No change"
      : improved
        ? `−${-comparison.risk_delta} improved`
        : `+${comparison.risk_delta} regressed`;

  const findingsDelta =
    comparison.findings_after
    - comparison.findings_before;

  const pathsDelta =
    comparison.paths_after
    - comparison.paths_before;

  const nothingChanged =
    comparison.resolved_findings.length === 0
    && comparison.new_findings.length === 0
    && comparison.unchanged_findings.length
      === 0
    && comparison.resolved_paths.length === 0
    && comparison.new_paths.length === 0
    && comparison.unchanged_paths.length === 0;


  return (
    <>
      <section
        className="compare-delta"
        style={{ "--i": 2 } as CSSProperties}
        aria-label="Comparison summary"
      >
        <DeltaStat
          label="Highest risk"
          before={comparison.risk_before}
          after={comparison.risk_after}
          chipClass={riskChipClass}
          chipLabel={riskChipLabel}
          foot="Maximum correlated risk score"
          index={0}
        />

        <DeltaStat
          label="Findings"
          before={comparison.findings_before}
          after={comparison.findings_after}
          chipClass="badge-neutral"
          chipLabel={formatSigned(findingsDelta)}
          foot={
            `${comparison.resolved_findings.length}`
            + " resolved · "
            + `${comparison.new_findings.length}`
            + " new"
          }
          index={1}
        />

        <DeltaStat
          label="Attack paths"
          before={comparison.paths_before}
          after={comparison.paths_after}
          chipClass="badge-neutral"
          chipLabel={formatSigned(pathsDelta)}
          foot={
            `${comparison.resolved_paths.length}`
            + " resolved · "
            + `${comparison.new_paths.length}`
            + " new"
          }
          index={2}
        />
      </section>

      {nothingChanged ? (
        <section
          className="panel"
          style={{ "--i": 3 } as CSSProperties}
        >
          <EmptyState
            icon="check"
            title="Nothing changed between these scans"
            body="Neither scan recorded findings or attack paths that differ, so there is nothing to review."
          />
        </section>
      ) : (
        <section
          className="compare-groups"
          style={{ "--i": 3 } as CSSProperties}
        >
          <ChangeGroup
            tone="resolved"
            icon="check"
            title="Resolved"
            subtitle="Observed in Baseline (A), no longer present in Current (B)."
            findings={
              comparison.resolved_findings
            }
            paths={comparison.resolved_paths}
            empty="Nothing was resolved."
          />

          <ChangeGroup
            tone="new"
            icon="alert"
            title="New"
            subtitle="First observed in Current (B)."
            findings={comparison.new_findings}
            paths={comparison.new_paths}
            empty="No new issues appeared."
          />

          <ChangeGroup
            tone="unchanged"
            icon="info"
            title="Unchanged"
            subtitle="Observed in both scans."
            findings={
              comparison.unchanged_findings
            }
            paths={comparison.unchanged_paths}
            empty="Nothing remained unchanged."
          />
        </section>
      )}

      <section
        className="panel"
        style={{ "--i": 4 } as CSSProperties}
      >
        <div className="panel-body compare-note">
          <p className="eyebrow">
            INTERPRETATION
          </p>

          <p className="secondary">
            {comparison.note}
          </p>
        </div>
      </section>
    </>
  );
}


function ChangeGroup({
  tone,
  icon,
  title,
  subtitle,
  findings,
  paths,
  empty,
}: {
  tone: "resolved" | "new" | "unchanged";
  icon: "check" | "alert" | "info";
  title: string;
  subtitle: string;
  findings: FindingChange[];
  paths: AttackPathChange[];
  empty: string;
}) {
  const count =
    findings.length + paths.length;

  const countBadge =
    tone === "resolved"
      ? "badge-success"
      : tone === "new"
        ? "badge-danger"
        : "badge-neutral";

  return (
    <article
      className={
        `panel change-group change-group-${tone}`
      }
    >
      <div className="panel-header">
        <div className="change-group-heading">
          <span
            className={`change-group-icon ${tone}`}
            aria-hidden="true"
          >
            <Icon name={icon} size={15} />
          </span>

          <div>
            <h3 className="panel-title">
              {title}
            </h3>

            <p className="card-subtitle">
              {subtitle}
            </p>
          </div>
        </div>

        <span
          className={`badge no-dot ${countBadge}`}
        >
          {count}
          {" "}
          {count === 1 ? "item" : "items"}
        </span>
      </div>

      {count === 0 ? (
        <p className="change-empty muted">
          {empty}
        </p>
      ) : (
        <ul className="change-list">
          {findings.map((finding) => (
            <li
              className="change-item"
              key={`f-${finding.fingerprint}`}
            >
              <div className="change-item-top">
                <span
                  className={
                    "badge badge-sm "
                    + severityBadgeClass(
                      finding.severity,
                    )
                  }
                >
                  {finding.severity
                    .toUpperCase()}
                </span>

                <span className="change-risk">
                  Risk {finding.risk_score}
                </span>
              </div>

              <p className="change-item-title">
                {finding.title}
              </p>

              <code className="mono wrap-anywhere change-item-id">
                {finding.finding_id}
              </code>
            </li>
          ))}

          {paths.map((path) => (
            <li
              className="change-item"
              key={`p-${path.path_id}`}
            >
              <div className="change-item-top">
                <span className="badge badge-sm badge-neutral no-dot">
                  ATTACK PATH
                </span>

                <span className="change-risk">
                  Risk {path.risk_score}
                </span>
              </div>

              <p className="change-item-title mono wrap-anywhere">
                {path.nodes.join(" → ")}
              </p>

              <code className="mono wrap-anywhere change-item-id">
                {path.path_id}
              </code>
            </li>
          ))}
        </ul>
      )}
    </article>
  );
}


export default Compare;
