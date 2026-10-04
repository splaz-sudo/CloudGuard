import {
  useEffect,
  useMemo,
  useState,
} from "react";

import {
  getScanFindings,
} from "../services/api";

import {
  useScanContext,
} from "../context/ScanContext";

import type {
  Finding,
} from "../types/cloudguard";


type SeverityFilter =
  | "all"
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "info";


function Findings() {
  const { selectedScan } =
    useScanContext();

  const scanId =
    selectedScan?.scan_id ?? null;

  const [findings, setFindings] =
    useState<Finding[]>([]);

  const [
    selectedFinding,
    setSelectedFinding,
  ] = useState<Finding | null>(null);

  const [severityFilter, setSeverityFilter] =
    useState<SeverityFilter>("all");

  const [search, setSearch] =
    useState("");

  const [loading, setLoading] =
    useState(true);

  const [error, setError] =
    useState<string | null>(null);


  useEffect(() => {
    if (!scanId) {
      return;
    }

    const currentScanId: string = scanId;

    async function loadFindings() {
      setLoading(true);
      setError(null);

      try {
        const data = await getScanFindings(
          currentScanId,
        );

        const sorted = [...data].sort(
          (left, right) =>
            right.risk_score -
            left.risk_score,
        );

        setFindings(sorted);

        if (sorted.length > 0) {
          setSelectedFinding(
            sorted[0],
          );
        } else {
          setSelectedFinding(null);
        }
      } catch (requestError) {
        setError(
          requestError instanceof Error
            ? requestError.message
            : "Unable to load findings.",
        );
      } finally {
        setLoading(false);
      }
    }

    loadFindings();
  }, [scanId]);


  const metrics = useMemo(() => {
    const countSeverity = (
      severity: string,
    ) =>
      findings.filter(
        (finding) =>
          finding.severity
            .toLowerCase() === severity,
      ).length;

    return {
      total: findings.length,
      critical:
        countSeverity("critical"),
      high:
        countSeverity("high"),
      medium:
        countSeverity("medium"),
    };
  }, [findings]);


  const filteredFindings = useMemo(() => {
    const query =
      search.trim().toLowerCase();

    return findings.filter(
      (finding) => {
        const severityMatches =
          severityFilter === "all" ||
          finding.severity
            .toLowerCase() ===
            severityFilter;

        const searchMatches =
          !query ||
          finding.title
            .toLowerCase()
            .includes(query) ||
          finding.id
            .toLowerCase()
            .includes(query) ||
          finding.category
            .toLowerCase()
            .includes(query) ||
          finding.affected_assets.some(
            (asset) =>
              asset
                .toLowerCase()
                .includes(query),
          );

        return (
          severityMatches &&
          searchMatches
        );
      },
    );
  }, [
    findings,
    search,
    severityFilter,
  ]);


  if (loading) {
    return (
      <section className="page-state">
        Loading security findings...
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


  return (
    <>
      <header className="topbar">
        <div>
          <p className="eyebrow">
            SECURITY FINDINGS
          </p>

          <h2>
            Findings & Remediation
          </h2>

          <p className="subtitle">
            Prioritized security findings
            generated from CloudGuard's
            security graph and contextual
            analysis.
          </p>
        </div>

        <div className="environment-badge">
          {findings.length} FINDINGS
        </div>
      </header>


      <section className="findings-metrics">
        <FindingMetric
          label="Critical"
          value={metrics.critical}
          tone="critical"
        />

        <FindingMetric
          label="High"
          value={metrics.high}
          tone="high"
        />

        <FindingMetric
          label="Medium"
          value={metrics.medium}
          tone="medium"
        />

        <FindingMetric
          label="Total"
          value={metrics.total}
        />
      </section>


      <section className="findings-toolbar">
        <input
          type="search"
          className="findings-search"
          placeholder="Search findings..."
          value={search}
          onChange={(event) =>
            setSearch(
              event.target.value,
            )
          }
        />

        <div className="findings-filters">
          {(
            [
              "all",
              "critical",
              "high",
              "medium",
              "low",
              "info",
            ] as SeverityFilter[]
          ).map((severity) => (
            <button
              key={severity}
              type="button"
              className={
                severityFilter ===
                severity
                  ? (
                    "finding-filter " +
                    "active"
                  )
                  : "finding-filter"
              }
              onClick={() =>
                setSeverityFilter(
                  severity,
                )
              }
            >
              {severity.toUpperCase()}
            </button>
          ))}
        </div>
      </section>


      <section className="findings-layout">
        <div className="findings-list-panel">
          <div className="findings-list-header">
            <div>
              <p className="eyebrow">
                PRIORITIZED FINDINGS
              </p>

              <h3>
                Security Issues
              </h3>
            </div>

            <span>
              {filteredFindings.length}
            </span>
          </div>


          <div className="findings-list">
            {filteredFindings.map(
              (finding) => (
                <button
                  key={finding.id}
                  type="button"
                  className={
                    selectedFinding?.id ===
                    finding.id
                      ? (
                        "finding-list-item " +
                        "selected"
                      )
                      : "finding-list-item"
                  }
                  onClick={() =>
                    setSelectedFinding(
                      finding,
                    )
                  }
                >
                  <div className="finding-list-copy">
                    <div>
                      <span
                        className={
                          `finding-severity ${
                            finding.severity
                              .toLowerCase()
                          }`
                        }
                      >
                        {finding.severity}
                      </span>

                      <span className="finding-category">
                        {formatCategory(
                          finding.category,
                        )}
                      </span>
                    </div>

                    <strong>
                      {finding.title}
                    </strong>

                    <small>
                      {finding.id}
                    </small>
                  </div>

                  <div className="finding-list-score">
                    <span>
                      RISK
                    </span>

                    <strong>
                      {finding.risk_score}
                    </strong>
                  </div>
                </button>
              ),
            )}

            {filteredFindings.length ===
              0 && (
              <div className="empty-state">
                No findings match the
                current filters.
              </div>
            )}
          </div>
        </div>


        <div className="finding-details-panel">
          {selectedFinding ? (
            <FindingDetails
              finding={
                selectedFinding
              }
            />
          ) : (
            <div className="empty-state">
              Select a finding to inspect
              its evidence and remediation.
            </div>
          )}
        </div>
      </section>
    </>
  );
}


function FindingMetric({
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
        `finding-metric ${tone}`
      }
    >
      <span>{label}</span>
      <strong>{value}</strong>
    </article>
  );
}


function FindingDetails({
  finding,
}: {
  finding: Finding;
}) {
  return (
    <>
      <div className="finding-detail-header">
        <div>
          <div className="finding-detail-badges">
            <span
              className={
                `finding-severity ${
                  finding.severity
                    .toLowerCase()
                }`
              }
            >
              {finding.severity}
            </span>

            <span className="finding-category">
              {formatCategory(
                finding.category,
              )}
            </span>
          </div>

          <h3>
            {finding.title}
          </h3>

          <p>
            {finding.id}
          </p>
        </div>

        <div className="finding-risk-score">
          <span>
            Risk Score
          </span>

          <strong>
            {finding.risk_score}
          </strong>
        </div>
      </div>


      <div className="finding-section">
        <p className="details-section-title">
          Description
        </p>

        <p className="finding-description">
          {finding.description}
        </p>
      </div>


      <div className="finding-section">
        <p className="details-section-title">
          Affected Assets
        </p>

        <div className="finding-assets">
          {finding.affected_assets.map(
            (asset) => (
              <div
                className="finding-asset"
                key={asset}
              >
                {asset}
              </div>
            ),
          )}
        </div>
      </div>


      <div className="finding-section">
        <p className="details-section-title">
          Evidence
        </p>

        <div className="finding-evidence-list">
          {finding.evidence.map(
            (evidence, index) => (
              <div
                className="finding-evidence"
                key={
                  `${finding.id}-${index}`
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
          )}
        </div>
      </div>


      <div className="finding-section">
        <p className="details-section-title">
          Recommended Remediation
        </p>

        {finding.remediation ? (
          <div className="finding-remediation">
            <span>✓</span>

            <p>
              {finding.remediation}
            </p>
          </div>
        ) : (
          <p className="details-text">
            No remediation guidance is
            currently available.
          </p>
        )}
      </div>


      <div className="finding-context">
        <div>
          <span>Category</span>

          <strong>
            {formatCategory(
              finding.category,
            )}
          </strong>
        </div>

        <div>
          <span>
            Affected Assets
          </span>

          <strong>
            {
              finding
                .affected_assets
                .length
            }
          </strong>
        </div>

        <div>
          <span>
            Evidence Items
          </span>

          <strong>
            {finding.evidence.length}
          </strong>
        </div>
      </div>
    </>
  );
}


function formatCategory(
  category: string,
) {
  return category
    .replaceAll("_", " ")
    .replace(
      /\b\w/g,
      (character) =>
        character.toUpperCase(),
    );
}


export default Findings;