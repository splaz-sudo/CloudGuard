import {
  useEffect,
  useMemo,
  useState,
} from "react";

import {
  getCompliance,
} from "../services/api";

import type {
  ComplianceControl,
  ComplianceReport,
} from "../types/cloudguard";


function Compliance() {
  const [report, setReport] =
    useState<ComplianceReport | null>(null);

  const [
    selectedControl,
    setSelectedControl,
  ] = useState<ComplianceControl | null>(
    null,
  );

  const [
    selectedFramework,
    setSelectedFramework,
  ] = useState("ALL");

  const [loading, setLoading] =
    useState(true);

  const [error, setError] =
    useState<string | null>(null);


  useEffect(() => {
    async function loadCompliance() {
      try {
        const data =
          await getCompliance();

        setReport(data);

        if (data.controls.length > 0) {
          setSelectedControl(
            data.controls[0],
          );
        }
      } catch (requestError) {
        setError(
          requestError instanceof Error
            ? requestError.message
            : (
              "Unable to load " +
              "compliance data."
            ),
        );
      } finally {
        setLoading(false);
      }
    }

    loadCompliance();
  }, []);


  const controls = useMemo(() => {
    if (!report) {
      return [];
    }

    if (selectedFramework === "ALL") {
      return report.controls;
    }

    return report.controls.filter(
      (control) =>
        control.framework ===
        selectedFramework,
    );
  }, [
    report,
    selectedFramework,
  ]);


  const metrics = useMemo(() => {
    if (!report) {
      return {
        frameworks: 0,
        controls: 0,
        nonCompliant: 0,
        mappedFindings: 0,
      };
    }

    return {
      frameworks:
        report.frameworks.length,

      controls:
        report.controls.length,

      nonCompliant:
        report.controls.filter(
          (control) =>
            control.status ===
            "NON_COMPLIANT",
        ).length,

      mappedFindings:
        report.mapped_findings,
    };
  }, [report]);


  if (loading) {
    return (
      <section className="page-state">
        Loading compliance mappings...
      </section>
    );
  }


  if (error || !report) {
    return (
      <section
        className="page-state error-message"
      >
        {error ??
          "Compliance report unavailable."}
      </section>
    );
  }


  return (
    <>
      <header className="topbar">
        <div>
          <p className="eyebrow">
            COMPLIANCE MAPPING
          </p>

          <h2>
            Compliance & Controls
          </h2>

          <p className="subtitle">
            Evidence-based mappings between
            CloudGuard security findings and
            relevant security framework
            controls.
          </p>
        </div>

        <div className="environment-badge">
          LOCAL ASSESSMENT
        </div>
      </header>


      <section className="compliance-metrics">
        <Metric
          label="Frameworks"
          value={metrics.frameworks}
        />

        <Metric
          label="Mapped Controls"
          value={metrics.controls}
        />

        <Metric
          label="Non-Compliant"
          value={metrics.nonCompliant}
          tone="danger"
        />

        <Metric
          label="Mapped Findings"
          value={metrics.mappedFindings}
        />
      </section>


      <section className="compliance-frameworks">
        {report.frameworks.map(
          (framework) => (
            <button
              type="button"
              key={framework.framework}
              className={
                selectedFramework ===
                framework.framework
                  ? (
                    "framework-card " +
                    "selected"
                  )
                  : "framework-card"
              }
              onClick={() => {
                setSelectedFramework(
                  framework.framework,
                );

                const first =
                  report.controls.find(
                    (control) =>
                      control.framework ===
                      framework.framework,
                  );

                if (first) {
                  setSelectedControl(first);
                }
              }}
            >
              <div>
                <span>
                  FRAMEWORK
                </span>

                <strong>
                  {framework.framework}
                </strong>
              </div>

              <div className="framework-stats">
                <span>
                  {
                    framework
                      .total_controls
                  }{" "}
                  controls
                </span>

                <span className="framework-danger">
                  {
                    framework
                      .non_compliant
                  }{" "}
                  flagged
                </span>
              </div>
            </button>
          ),
        )}
      </section>


      <div className="compliance-filter-row">
        <button
          type="button"
          className={
            selectedFramework === "ALL"
              ? "compliance-filter active"
              : "compliance-filter"
          }
          onClick={() => {
            setSelectedFramework("ALL");

            if (
              report.controls.length > 0
            ) {
              setSelectedControl(
                report.controls[0],
              );
            }
          }}
        >
          ALL CONTROLS
        </button>

        {report.frameworks.map(
          (framework) => (
            <button
              type="button"
              key={
                `filter-${framework.framework}`
              }
              className={
                selectedFramework ===
                framework.framework
                  ? (
                    "compliance-filter " +
                    "active"
                  )
                  : "compliance-filter"
              }
              onClick={() => {
                setSelectedFramework(
                  framework.framework,
                );

                const first =
                  report.controls.find(
                    (control) =>
                      control.framework ===
                      framework.framework,
                  );

                if (first) {
                  setSelectedControl(first);
                }
              }}
            >
              {framework.framework}
            </button>
          ),
        )}
      </div>


      <section className="compliance-layout">
        <div className="compliance-list-panel">
          <div className="compliance-list-header">
            <div>
              <p className="eyebrow">
                CONTROL ASSESSMENT
              </p>

              <h3>
                Mapped Controls
              </h3>
            </div>

            <span>
              {controls.length}
            </span>
          </div>


          <div className="compliance-list">
            {controls.map(
              (control) => (
                <button
                  type="button"
                  key={
                    `${control.framework}-${control.control_id}`
                  }
                  className={
                    selectedControl
                      ?.control_id ===
                      control.control_id &&
                    selectedControl
                      ?.framework ===
                      control.framework
                      ? (
                        "compliance-list-item " +
                        "selected"
                      )
                      : (
                        "compliance-list-item"
                      )
                  }
                  onClick={() =>
                    setSelectedControl(
                      control,
                    )
                  }
                >
                  <div>
                    <div className="control-list-meta">
                      <span className="control-id">
                        {control.control_id}
                      </span>

                      <StatusBadge
                        status={
                          control.status
                        }
                      />
                    </div>

                    <strong>
                      {control.title}
                    </strong>

                    <small>
                      {control.framework}
                    </small>
                  </div>
                </button>
              ),
            )}
          </div>
        </div>


        <div className="compliance-details-panel">
          {selectedControl ? (
            <ControlDetails
              control={selectedControl}
            />
          ) : (
            <div className="empty-state">
              Select a compliance control
              to inspect its evidence.
            </div>
          )}
        </div>
      </section>


      <div className="compliance-disclaimer">
        CloudGuard reports evidence-based
        mappings for the controls represented
        by its current security analysis.
        This view is not a complete compliance
        audit, certification, or attestation.
        Controls without sufficient evidence
        are not assumed to be compliant.
      </div>
    </>
  );
}


function Metric({
  label,
  value,
  tone = "",
}: {
  label: string;
  value: number;
  tone?: string;
}) {
  return (
    <article
      className={
        `compliance-metric ${tone}`
      }
    >
      <span>{label}</span>
      <strong>{value}</strong>
    </article>
  );
}


function StatusBadge({
  status,
}: {
  status: string;
}) {
  const statusClass =
    status
      .toLowerCase()
      .replaceAll("_", "-");

  return (
    <span
      className={
        `compliance-status ${statusClass}`
      }
    >
      {status.replaceAll("_", " ")}
    </span>
  );
}


function ControlDetails({
  control,
}: {
  control: ComplianceControl;
}) {
  return (
    <>
      <div className="compliance-detail-header">
        <div>
          <div className="control-heading-meta">
            <span className="control-id">
              {control.control_id}
            </span>

            <StatusBadge
              status={control.status}
            />
          </div>

          <h3>
            {control.title}
          </h3>

          <p>
            {control.framework}
          </p>
        </div>
      </div>


      <section className="compliance-section">
        <p className="details-section-title">
          Control Objective
        </p>

        <p className="details-text">
          {control.description}
        </p>
      </section>


      <section className="compliance-section">
        <p className="details-section-title">
          Related Findings
        </p>

        <div className="compliance-chip-list">
          {control.related_findings.length >
          0 ? (
            control.related_findings.map(
              (finding) => (
                <span
                  className="compliance-chip finding-chip"
                  key={finding}
                >
                  {finding}
                </span>
              ),
            )
          ) : (
            <p className="details-text">
              No related findings were
              observed.
            </p>
          )}
        </div>
      </section>


      <section className="compliance-section">
        <p className="details-section-title">
          Affected Assets
        </p>

        <div className="compliance-chip-list">
          {control.affected_assets.length >
          0 ? (
            control.affected_assets.map(
              (asset) => (
                <span
                  className="compliance-chip"
                  key={asset}
                >
                  {asset}
                </span>
              ),
            )
          ) : (
            <p className="details-text">
              No affected assets identified.
            </p>
          )}
        </div>
      </section>


      <section className="compliance-section">
        <p className="details-section-title">
          Evidence
        </p>

        <div className="compliance-evidence-list">
          {control.evidence.length > 0 ? (
            control.evidence.map(
              (evidence, index) => (
                <div
                  className="compliance-evidence"
                  key={
                    `${control.control_id}-evidence-${index}`
                  }
                >
                  <span>
                    {index + 1}
                  </span>

                  <p>
                    {evidence}
                  </p>
                </div>
              ),
            )
          ) : (
            <p className="details-text">
              This control has not been
              assessed with sufficient
              evidence.
            </p>
          )}
        </div>
      </section>


      <section className="compliance-section">
        <p className="details-section-title">
          Recommended Remediation
        </p>

        <div className="compliance-remediation-list">
          {control.remediation.length >
          0 ? (
            control.remediation.map(
              (item, index) => (
                <div
                  className="compliance-remediation"
                  key={
                    `${control.control_id}-remediation-${index}`
                  }
                >
                  <span>✓</span>

                  <p>
                    {item}
                  </p>
                </div>
              ),
            )
          ) : (
            <p className="details-text">
              No remediation guidance is
              currently available.
            </p>
          )}
        </div>
      </section>
    </>
  );
}


export default Compliance;