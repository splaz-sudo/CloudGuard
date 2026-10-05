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

  const [categoryFilter, setCategoryFilter] =
    useState<string[]>([]);

  const [regionFilter, setRegionFilter] =
    useState<string[]>([]);

// Status filter removed - comparison feature not active

  const [search, setSearch] =
    useState("");

  const [loading, setLoading] =
    useState(true);

  const [error, setError] =
    useState<string | null>(null);

// Comparison state removed - feature not active


  useEffect(() => {
    if (!scanId) {
      return;
    }

    const currentScanId = scanId;

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

  // Get available categories from findings
  const availableCategories = useMemo(
    () => [
      ...new Set(findings.map((f) => f.category)),
    ].sort(),
    [findings],
  );

  // Get available regions from findings (via affected assets)
  const availableRegions = useMemo(
    () => [
      ...new Set(
        findings
          .flatMap((f) =>
            f.affected_assets
              .map((a) => a.split(":")[0])
          )
          .filter((r) => r)
      ),
    ].sort(),
    [findings],
  );

// Use findings directly since comparison feature is not active
  const findingsWithStatus = findings;


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

    return findingsWithStatus.filter(
      (finding) => {
        const severityMatches =
          severityFilter === "all" ||
          finding.severity
            .toLowerCase() ===
            severityFilter;

        const categoryMatches =
          categoryFilter.length === 0 ||
          categoryFilter.includes(
            finding.category,
          );

        const regionMatches =
          regionFilter.length === 0 ||
          finding.affected_assets.some(
            (asset) =>
              regionFilter.some((r) =>
                asset.toLowerCase().startsWith(r.toLowerCase()),
              ),
          );

        const statusMatches = true;

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
          categoryMatches &&
          regionMatches &&
          statusMatches &&
          searchMatches
        );
      },
    );
  }, [
    findingsWithStatus,
    search,
    severityFilter,
    categoryFilter,
    regionFilter,
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


// Comparison banner removed - comparison feature not active

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
          placeholder="Search findings by title, ID, category, evidence..."
          value={search}
          onChange={(event) =>
            setSearch(
              event.target.value,
            )
          }
        />

        <div className="findings-filters">
          <div className="filter-group">
            <label>Severity</label>
            <select
              value={severityFilter}
              onChange={(e) =>
                setSeverityFilter(
                  e.target.value as SeverityFilter,
                )
              }
            >
              <option value="all">All</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </select>
          </div>

          <div className="filter-group">
            <label>Category</label>
            <select
              className="filter-multi"
              multiple
              value={categoryFilter}
              onChange={(e) =>
                setCategoryFilter(
                  Array.from(
                    e.target.selectedOptions,
                    (o) => o.value,
                  ),
                )
              }
            >
              {availableCategories.map((cat) => (
                <option key={cat} value={cat}>
                  {cat}
                </option>
              ))}
            </select>
          </div>

          <div className="filter-group">
            <label>Region</label>
            <select
              className="filter-multi"
              multiple
              value={regionFilter}
              onChange={(e) =>
                setRegionFilter(
                  Array.from(
                    e.target.selectedOptions,
                    (o) => o.value,
                  ),
                )
              }
            >
              {availableRegions.map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </select>
          </div>

        </div>

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
              {filteredFindings.length} /{" "}
              {findings.length} findings
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

                      {finding.comparisonStatus && (
                        <span
                          className={
                            `finding-status ${
                              finding.comparisonStatus
                            }`
                          }
                        >
                          {finding.comparisonStatus
                            .toUpperCase()}
                        </span>
                      )}

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


type SeverityFilter =
  | "all"
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "info";


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
  // Determine status badge
  const statusBadge = finding.comparisonStatus
    ? (
        <span
          className={
            `finding-status ${
              finding.comparisonStatus
            }`
          }
        >
          {finding.comparisonStatus.toUpperCase()}
        </span>
      )
    : null;

  return (
    <div className="finding-details">
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

            {statusBadge}
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

        {finding.comparisonStatus && (
          <div>
            <span>Status</span>

            <strong>
              <span
                className={
                  `finding-status ${
                    finding.comparisonStatus
                  }`
                }
              >
                {finding.comparisonStatus.toUpperCase()}
              </span>
            </strong>
          </div>
        )}

// Comparison scan reference removed - comparison feature not active
      </div>
    </div>
    </div>
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