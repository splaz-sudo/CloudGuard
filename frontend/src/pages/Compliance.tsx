import "../styles/compliance.css";

import {
  useCallback,
  useEffect,
  useMemo,
  useState,
} from "react";

import Icon from "../components/Icon";

import {
  EmptyState,
  ErrorState,
  SkeletonCard,
} from "../components/StateBlock";

import {
  Select,
} from "../components/FormControls";

import {
  CloudGuardAPIError,
  getScanCompliance,
} from "../services/api";

import {
  useScanContext,
} from "../context/ScanContext";

import type {
  ComplianceControl,
  ComplianceReport,
} from "../types/cloudguard";


const STATUS_FILTERS = [
  { value: "ALL", label: "All statuses" },
  { value: "COMPLIANT", label: "Compliant" },
  {
    value: "NON_COMPLIANT",
    label: "Non-Compliant",
  },
  {
    value: "NOT_ASSESSED",
    label: "Not Assessed",
  },
];


function Compliance() {
  const { selectedScan } =
    useScanContext();

  const scanId =
    selectedScan?.scan_id ?? null;

  const [report, setReport] =
    useState<ComplianceReport | null>(null);

  const [loading, setLoading] =
    useState(true);

  const [error, setError] =
    useState<CloudGuardAPIError | null>(null);

  const [frameworkFilter, setFrameworkFilter] =
    useState("ALL");

  const [statusFilter, setStatusFilter] =
    useState("ALL");


  const loadCompliance =
    useCallback(async () => {
      if (!scanId) {
        return;
      }

      setLoading(true);
      setError(null);

      try {
        const data =
          await getScanCompliance(scanId);

        setReport(data);
      } catch (requestError) {
        if (
          requestError
          instanceof CloudGuardAPIError
        ) {
          setError(requestError);
        } else {
          setError(
            new CloudGuardAPIError(
              "Unable to load compliance data.",
            ),
          );
        }
      } finally {
        setLoading(false);
      }
    }, [scanId]);


  useEffect(() => {
    void loadCompliance();
  }, [loadCompliance]);


  const frameworkOptions = useMemo(() => {
    if (!report) {
      return [
        {
          value: "ALL",
          label: "All frameworks",
        },
      ];
    }

    return [
      {
        value: "ALL",
        label: "All frameworks",
      },
      ...report.frameworks.map(
        (framework) => ({
          value: framework.framework,
          label: framework.framework,
        }),
      ),
    ];
  }, [report]);


  const statusCounts = useMemo(() => {
    const counts = {
      COMPLIANT: 0,
      NON_COMPLIANT: 0,
      NOT_ASSESSED: 0,
      UNKNOWN: 0,
    };

    if (!report) {
      return counts;
    }

    for (const control of report.controls) {
      // Widen to string: the API type only
      // lists two statuses, but a compliant
      // or unrecognized status must still
      // be counted, not misclassified.
      const status: string = control.status;

      if (
        status === "COMPLIANT"
        || status === "NON_COMPLIANT"
        || status === "NOT_ASSESSED"
      ) {
        counts[status] += 1;
      } else {
        counts.UNKNOWN += 1;
      }
    }

    return counts;
  }, [report]);


  const controls = useMemo(() => {
    if (!report) {
      return [];
    }

    return report.controls.filter(
      (control) => {
        if (
          frameworkFilter !== "ALL"
          && control.framework
            !== frameworkFilter
        ) {
          return false;
        }

        if (
          statusFilter !== "ALL"
          && control.status !== statusFilter
        ) {
          return false;
        }

        return true;
      },
    );
  }, [report, frameworkFilter, statusFilter]);


  const pageHeader = (
    <header className="topbar">
      <div>
        <p className="eyebrow">
          Compliance Mapping
        </p>

        <h2>
          Compliance &amp; Controls
        </h2>

        <p className="page-subtitle">
          Evidence-based mappings between
          CloudGuard security findings and
          relevant security framework
          controls.
        </p>
      </div>

      <span className="badge badge-info badge-lg no-dot">
        Local assessment
      </span>
    </header>
  );


  if (loading) {
    return (
      <div className="page">
        {pageHeader}

        <div
          className="comp-loading"
          aria-busy="true"
          aria-label="Loading compliance data"
        >
          <SkeletonCard lines={3} />
          <SkeletonCard lines={2} />
          <SkeletonCard lines={2} />
        </div>
      </div>
    );
  }


  if (error || !report) {
    return (
      <div className="page">
        {pageHeader}

        <ErrorState
          error={
            error
            ?? new CloudGuardAPIError(
              "Compliance report unavailable.",
            )
          }
          resourceLabel="compliance data"
          onRetry={() => {
            void loadCompliance();
          }}
        />
      </div>
    );
  }


  return (
    <div className="page">
      {pageHeader}

      <section
        className="stat-grid"
        aria-label="Control status summary"
      >
        <StatusStat
          label="Compliant"
          value={statusCounts.COMPLIANT}
          tone="success"
        />

        <StatusStat
          label="Non-Compliant"
          value={statusCounts.NON_COMPLIANT}
          tone="danger"
        />

        <StatusStat
          label="Not Assessed"
          value={statusCounts.NOT_ASSESSED}
          tone="neutral"
        />

        <StatusStat
          label="Unknown"
          value={statusCounts.UNKNOWN}
          tone="info"
        />

        <StatusStat
          label="Frameworks"
          value={report.frameworks.length}
        />

        <StatusStat
          label="Mapped Findings"
          value={report.mapped_findings}
        />
      </section>

      {report.frameworks.length > 0 && (
        <div
          className="chip-row"
          aria-label="Framework summaries"
        >
          {report.frameworks.map(
            (framework) => (
              <span
                className="chip"
                key={framework.framework}
              >
                <strong className="strong">
                  {framework.framework}
                </strong>
                {framework.total_controls}{" "}
                controls &middot;{" "}
                {framework.non_compliant}{" "}
                flagged &middot;{" "}
                {framework.not_assessed} not
                assessed
              </span>
            ),
          )}
        </div>
      )}

      <div className="toolbar">
        <Select
          label="Framework"
          value={frameworkFilter}
          onChange={setFrameworkFilter}
          options={frameworkOptions}
        />

        <Select
          label="Status"
          value={statusFilter}
          onChange={setStatusFilter}
          options={STATUS_FILTERS}
        />

        <span className="toolbar-spacer" />

        <p className="comp-count">
          Showing {controls.length} of{" "}
          {report.controls.length} controls
        </p>
      </div>

      {report.controls.length === 0 ? (
        <EmptyState
          icon="shield"
          title="No compliance mappings"
          body="No framework controls were mapped to the findings in this scan."
        />
      ) : controls.length === 0 ? (
        <EmptyState
          icon="search"
          title="No controls match these filters"
          body="Try widening the framework or status filter to see more controls."
        />
      ) : (
        <section
          className="comp-list"
          aria-label="Control assessment"
        >
          {controls.map((control, index) => (
            <ControlRow
              key={`${control.framework}-${control.control_id}`}
              control={control}
              defaultOpen={index === 0}
            />
          ))}
        </section>
      )}

      <div
        className="comp-disclaimer"
        role="note"
      >
        <Icon name="info" size={15} />

        <p>
          CloudGuard reports evidence-based
          mappings for the controls
          represented by its current
          security analysis. This view is
          not a complete compliance audit,
          certification, or attestation.
          Controls without sufficient
          evidence are not assumed to be
          compliant.
        </p>
      </div>
    </div>
  );
}


function StatusStat({
  label,
  value,
  tone,
}: {
  label: string;
  value: number;
  tone?:
    | "success"
    | "danger"
    | "neutral"
    | "info";
}) {
  return (
    <div
      className={
        tone
          ? `stat comp-stat-${tone}`
          : "stat"
      }
    >
      <span className="stat-label">
        {label}
      </span>

      <p className="stat-value">{value}</p>
    </div>
  );
}


/**
 * Four visually distinct status treatments,
 * always paired with a text label so status
 * is never conveyed by color alone.
 */
function StatusBadge({
  status,
}: {
  status: string;
}) {
  const meta = STATUS_BADGES[status] ?? {
    badgeClass: "badge-info",
    label: "Unknown",
    raw: status,
  };

  return (
    <span
      className={`badge ${meta.badgeClass}`}
      title={
        meta.label === "Unknown"
          ? `Unrecognized status: ${meta.raw}`
          : undefined
      }
    >
      {meta.label}
    </span>
  );
}


const STATUS_BADGES: Record<
  string,
  {
    badgeClass: string;
    label: string;
    raw?: string;
  }
> = {
  COMPLIANT: {
    badgeClass: "badge-success",
    label: "Compliant",
  },
  NON_COMPLIANT: {
    badgeClass: "badge-danger",
    label: "Non-Compliant",
  },
  NOT_ASSESSED: {
    badgeClass: "badge-neutral",
    label: "Not Assessed",
  },
};


function ControlRow({
  control,
  defaultOpen,
}: {
  control: ComplianceControl;
  defaultOpen: boolean;
}) {
  return (
    <details
      className="comp-row"
      open={defaultOpen}
    >
      <summary className="comp-row-summary">
        <Icon
          name="chevron-right"
          size={15}
          className="comp-chev"
        />

        <span className="comp-row-main">
          <span className="mono comp-id">
            {control.control_id}
          </span>

          <span className="comp-title">
            {control.title}
          </span>
        </span>

        <span className="chip comp-framework">
          {control.framework}
        </span>

        <StatusBadge
          status={control.status}
        />
      </summary>

      <div className="comp-row-body">
        <section className="comp-section">
          <p className="comp-label">
            Control objective
          </p>

          <p className="comp-text">
            {control.description}
          </p>
        </section>

        <div className="comp-columns">
          <section className="comp-section">
            <p className="comp-label">
              Related findings (
              {control.related_findings.length}
              )
            </p>

            {control.related_findings.length
            > 0 ? (
              <div className="chip-row">
                {control.related_findings.map(
                  (finding) => (
                    <span
                      className="chip"
                      key={finding}
                    >
                      <span className="mono">
                        {finding}
                      </span>
                    </span>
                  ),
                )}
              </div>
            ) : (
              <p className="comp-text muted">
                No related findings were
                observed.
              </p>
            )}
          </section>

          <section className="comp-section">
            <p className="comp-label">
              Affected assets (
              {control.affected_assets.length})
            </p>

            {control.affected_assets.length
            > 0 ? (
              <div className="chip-row">
                {control.affected_assets.map(
                  (asset) => (
                    <span
                      className="chip"
                      key={asset}
                    >
                      <span className="mono">
                        {asset}
                      </span>
                    </span>
                  ),
                )}
              </div>
            ) : (
              <p className="comp-text muted">
                No affected assets
                identified.
              </p>
            )}
          </section>
        </div>

        <section className="comp-section">
          <p className="comp-label">
            Evidence (
            {control.evidence.length})
          </p>

          {control.evidence.length > 0 ? (
            <ul className="comp-evidence">
              {control.evidence.map(
                (evidence, index) => (
                  <li
                    key={`${control.control_id}-evidence-${index}`}
                  >
                    <span
                      className="comp-evidence-index"
                      aria-hidden="true"
                    >
                      {index + 1}
                    </span>

                    <p>{evidence}</p>
                  </li>
                ),
              )}
            </ul>
          ) : (
            <p className="comp-text muted">
              This control has not been
              assessed with sufficient
              evidence.
            </p>
          )}
        </section>

        <section className="comp-section">
          <p className="comp-label">
            Recommended remediation
          </p>

          {control.remediation.length > 0 ? (
            <ul className="comp-guidance">
              {control.remediation.map(
                (item, index) => (
                  <li
                    key={`${control.control_id}-remediation-${index}`}
                  >
                    <Icon
                      name="check"
                      size={14}
                    />

                    <p>{item}</p>
                  </li>
                ),
              )}
            </ul>
          ) : (
            <p className="comp-text muted">
              No remediation guidance is
              currently available.
            </p>
          )}
        </section>
      </div>
    </details>
  );
}


export default Compliance;
