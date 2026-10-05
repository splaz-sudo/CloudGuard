import {
  useMemo,
  useRef,
  useState,
  type CSSProperties,
  type KeyboardEvent,
} from "react";

import { getScanFindings } from "../services/api";
import { useScanContext } from "../context/ScanContext";
import { useScanQuery } from "../hooks/useApiQuery";

import Icon from "../components/Icon";
import {
  MultiSelect,
  SearchInput,
  Select,
} from "../components/FormControls";
import {
  EmptyState,
  ErrorState,
  SkeletonLine,
} from "../components/StateBlock";

import type { Finding } from "../types/cloudguard";

import "../styles/findings.css";


type SeverityFilter =
  | "all"
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "info";

type SeverityTone =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "info"
  | "neutral";

const MAX_REGION_BADGES = 4;


function Findings() {
  const { selectedScan } = useScanContext();
  const scanId = selectedScan?.scan_id ?? null;

  const findingsQuery = useScanQuery(
    getScanFindings,
    scanId,
  );

  const [selectedId, setSelectedId] =
    useState<string | null>(null);

  const [severityFilter, setSeverityFilter] =
    useState<SeverityFilter>("all");

  const [categoryFilter, setCategoryFilter] =
    useState<string[]>([]);

  const [regionFilter, setRegionFilter] =
    useState<string[]>([]);

  const [search, setSearch] = useState("");

  const listRef = useRef<HTMLDivElement>(null);

  const findings = useMemo(
    () =>
      [...(findingsQuery.data ?? [])].sort(
        (left, right) =>
          right.risk_score - left.risk_score,
      ),
    [findingsQuery.data],
  );

  // Effective selection: the explicitly selected
  // finding, falling back to the highest-risk one
  // whenever the data set changes (new scan, etc.).
  const selectedFinding =
    findings.find(
      (finding) => finding.id === selectedId,
    ) ?? findings[0] ?? null;

  const availableCategories = useMemo(
    () =>
      [
        ...new Set(
          findings.map((finding) => finding.category),
        ),
      ].sort(),
    [findings],
  );

  const availableRegions = useMemo(
    () =>
      [
        ...new Set(
          findings.flatMap((finding) =>
            getFindingRegions(finding)
          ),
        ),
      ].sort(),
    [findings],
  );

  const filteredFindings = useMemo(() => {
    const queryText = search.trim().toLowerCase();

    return findings.filter((finding) => {
      const severityMatches =
        severityFilter === "all"
        || finding.severity.toLowerCase()
          === severityFilter;

      const categoryMatches =
        categoryFilter.length === 0
        || categoryFilter.includes(finding.category);

      const regionMatches =
        regionFilter.length === 0
        || finding.affected_assets.some((asset) =>
          regionFilter.some((region) =>
            asset
              .toLowerCase()
              .startsWith(region.toLowerCase())
          )
        );

      const searchMatches =
        !queryText
        || finding.title
          .toLowerCase()
          .includes(queryText)
        || finding.id
          .toLowerCase()
          .includes(queryText)
        || finding.category
          .toLowerCase()
          .includes(queryText)
        || finding.affected_assets.some((asset) =>
          asset.toLowerCase().includes(queryText)
        );

      return (
        severityMatches
        && categoryMatches
        && regionMatches
        && searchMatches
      );
    });
  }, [
    findings,
    search,
    severityFilter,
    categoryFilter,
    regionFilter,
  ]);

  const metrics = useMemo(() => {
    const countSeverity = (severity: string) =>
      findings.filter(
        (finding) =>
          finding.severity.toLowerCase() === severity,
      ).length;

    return {
      total: findings.length,
      critical: countSeverity("critical"),
      high: countSeverity("high"),
      medium: countSeverity("medium"),
    };
  }, [findings]);

  const clearFilters = () => {
    setSearch("");
    setSeverityFilter("all");
    setCategoryFilter([]);
    setRegionFilter([]);
  };

  // Arrow-key navigation for the findings listbox:
  // moves the selection (and focus) row by row.
  const handleListKeyDown = (
    event: KeyboardEvent<HTMLDivElement>,
  ) => {
    if (
      event.key !== "ArrowDown"
      && event.key !== "ArrowUp"
    ) {
      return;
    }

    event.preventDefault();

    if (filteredFindings.length === 0) {
      return;
    }

    const currentIndex = filteredFindings.findIndex(
      (finding) =>
        finding.id === selectedFinding?.id,
    );

    const nextIndex =
      event.key === "ArrowDown"
        ? Math.min(
            currentIndex + 1,
            filteredFindings.length - 1,
          )
        : Math.max(currentIndex - 1, 0);

    const next =
      filteredFindings[
        nextIndex < 0 ? 0 : nextIndex
      ];

    if (!next || next.id === selectedFinding?.id) {
      return;
    }

    setSelectedId(next.id);

    listRef.current
      ?.querySelector<HTMLButtonElement>(
        `[data-finding-id="${CSS.escape(next.id)}"]`,
      )
      ?.focus();
  };

  return (
    <div className="page">
      <header
        className="topbar"
        style={{ "--i": 0 } as CSSProperties}
      >
        <div>
          <p className="eyebrow">SECURITY FINDINGS</p>
          <h2>Findings &amp; Remediation</h2>
          <p className="page-subtitle">
            Prioritized security findings generated from
            CloudGuard's security graph and contextual
            analysis.
          </p>
        </div>

        {scanId
          && !findingsQuery.loading
          && !findingsQuery.error && (
          <span className="chip findings-count">
            <strong>{findings.length}</strong>
            findings in scan
          </span>
        )}
      </header>

      {!scanId ? (
        <EmptyState
          icon="scans"
          title="No scan selected"
          body="Select a scan from the sidebar to inspect its security findings."
        />
      ) : findingsQuery.error ? (
        <ErrorState
          error={findingsQuery.error}
          resourceLabel="findings"
          onRetry={findingsQuery.retry}
        />
      ) : findingsQuery.loading ? (
        <FindingsLoadingSkeleton />
      ) : findings.length === 0 ? (
        <div className="panel">
          <EmptyState
            icon="findings"
            title="No findings in this scan"
            body="CloudGuard did not detect any security findings in the selected scan."
          />
        </div>
      ) : (
        <>
          <div
            className="stat-grid"
            style={{ "--i": 1 } as CSSProperties}
          >
            <FindingStat
              label="Critical"
              value={metrics.critical}
              tone="critical"
            />
            <FindingStat
              label="High"
              value={metrics.high}
              tone="high"
            />
            <FindingStat
              label="Medium"
              value={metrics.medium}
              tone="medium"
            />
            <FindingStat
              label="Total"
              value={metrics.total}
            />
          </div>

          <div
            className="toolbar findings-toolbar"
            style={{ "--i": 2 } as CSSProperties}
          >
            <div className="filter-group findings-search-group">
              <label
                className="form-label"
                htmlFor="findings-search"
              >
                Search
              </label>
              <SearchInput
                id="findings-search"
                placeholder="Search by title, ID, category, or asset..."
                value={search}
                onChange={setSearch}
              />
            </div>

            <Select
              label="Severity"
              options={[
                { value: "all", label: "All severities" },
                { value: "critical", label: "Critical" },
                { value: "high", label: "High" },
                { value: "medium", label: "Medium" },
                { value: "low", label: "Low" },
                { value: "info", label: "Info" },
              ]}
              value={severityFilter}
              onChange={(value) =>
                setSeverityFilter(
                  value as SeverityFilter,
                )
              }
            />

            <MultiSelect
              label="Category"
              options={availableCategories.map(
                (category) => ({
                  value: category,
                  label: formatCategory(category),
                }),
              )}
              value={categoryFilter}
              onChange={setCategoryFilter}
              placeholder="All categories"
            />

            <MultiSelect
              label="Region"
              options={availableRegions.map(
                (region) => ({
                  value: region,
                  label: region,
                }),
              )}
              value={regionFilter}
              onChange={setRegionFilter}
              placeholder="All regions"
            />
          </div>

          <div
            className="findings-layout"
            style={{ "--i": 3 } as CSSProperties}
          >
            <aside
              className="panel findings-list-panel"
              aria-label="Findings list"
            >
              <div className="findings-list-head">
                <div>
                  <h3 className="panel-title">
                    Security Issues
                  </h3>
                  <p className="card-subtitle">
                    Highest risk first
                  </p>
                </div>

                <span className="chip findings-count">
                  <strong>
                    {filteredFindings.length}
                  </strong>
                  / {findings.length}
                </span>
              </div>

              {filteredFindings.length === 0 ? (
                <EmptyState
                  icon="search"
                  title="No findings match your filters"
                  body="Adjust the search text or clear the active filters to see matching findings."
                  action={
                    <button
                      type="button"
                      className="btn btn-secondary btn-sm"
                      onClick={clearFilters}
                    >
                      <Icon name="x" size={14} />
                      Clear filters
                    </button>
                  }
                />
              ) : (
                <div
                  className="findings-list-scroll"
                  role="listbox"
                  aria-label="Findings"
                  ref={listRef}
                  onKeyDown={handleListKeyDown}
                >
                  {filteredFindings.map((finding) => (
                    <FindingRow
                      key={finding.id}
                      finding={finding}
                      selected={
                        finding.id
                        === selectedFinding?.id
                      }
                      onSelect={() =>
                        setSelectedId(finding.id)
                      }
                    />
                  ))}
                </div>
              )}
            </aside>

            <section
              className="panel finding-detail-panel"
              aria-label="Finding details"
            >
              {selectedFinding ? (
                <FindingDetails
                  finding={selectedFinding}
                />
              ) : (
                <EmptyState
                  icon="eye"
                  title="Select a finding"
                  body="Choose a finding from the list to inspect its evidence and remediation guidance."
                />
              )}
            </section>
          </div>
        </>
      )}
    </div>
  );
}


function FindingStat({
  label,
  value,
  tone,
}: {
  label: string;
  value: number;
  tone?: SeverityTone;
}) {
  return (
    <div className="stat">
      <span className="stat-label">{label}</span>
      <span
        className={
          `stat-value${
            tone ? ` finding-tone-${tone}` : ""
          }`
        }
      >
        {value}
      </span>
    </div>
  );
}


function FindingRow({
  finding,
  selected,
  onSelect,
}: {
  finding: Finding;
  selected: boolean;
  onSelect: () => void;
}) {
  const tone = severityTone(finding.severity);
  const regions = getFindingRegions(finding);

  const metaText =
    formatCategory(finding.category)
    + (regions.length > 0
      ? ` · ${regions.join(", ")}`
      : "");

  return (
    <button
      type="button"
      role="option"
      aria-selected={selected}
      data-finding-id={finding.id}
      className={
        `finding-row${selected ? " selected" : ""}`
      }
      onClick={onSelect}
      title={finding.title}
    >
      <span className="finding-row-top">
        <span className="finding-row-badges">
          <span
            className={
              `badge badge-sm ${
                severityBadgeClass(finding.severity)
              }`
            }
          >
            {finding.severity.toUpperCase()}
          </span>

          {finding.comparisonStatus && (
            <span
              className={
                `badge badge-sm ${
                  statusBadgeClass(
                    finding.comparisonStatus,
                  )
                }`
              }
            >
              {finding.comparisonStatus.toUpperCase()}
            </span>
          )}
        </span>

        <span className="finding-row-score">
          <span className="finding-row-score-label">
            Risk
          </span>
          <span
            className={
              `finding-row-score-value finding-tone-${tone}`
            }
          >
            {finding.risk_score}
          </span>
        </span>
      </span>

      <span className="finding-row-title">
        {finding.title}
      </span>

      <span
        className="finding-row-meta"
        title={metaText}
      >
        {metaText}
      </span>
    </button>
  );
}


function FindingDetails({
  finding,
}: {
  finding: Finding;
}) {
  const tone = severityTone(finding.severity);
  const regions = getFindingRegions(finding);

  const riskPercent = Math.min(
    100,
    Math.max(0, finding.risk_score),
  );

  return (
    <article className="finding-detail">
      <div className="finding-detail-top">
        <div className="finding-detail-badges">
          <span
            className={
              `badge ${
                severityBadgeClass(finding.severity)
              }`
            }
          >
            {finding.severity.toUpperCase()}
          </span>

          <span className="badge badge-neutral no-dot">
            {formatCategory(finding.category)}
          </span>

          {regions
            .slice(0, MAX_REGION_BADGES)
            .map((region) => (
              <span
                key={region}
                className="badge badge-info no-dot"
              >
                <Icon name="globe" size={11} />
                {region}
              </span>
            ))}

          {regions.length > MAX_REGION_BADGES && (
            <span className="badge badge-neutral no-dot">
              +{regions.length - MAX_REGION_BADGES} more
            </span>
          )}

          {finding.comparisonStatus && (
            <span
              className={
                `badge ${
                  statusBadgeClass(
                    finding.comparisonStatus,
                  )
                }`
              }
            >
              {finding.comparisonStatus.toUpperCase()}
            </span>
          )}
        </div>

        <div className="finding-risk">
          <span className="finding-risk-label">
            Risk score
          </span>

          <strong
            className={
              `finding-risk-value finding-tone-${tone}`
            }
          >
            {finding.risk_score}
            <span className="finding-risk-max">
              /100
            </span>
          </strong>

          <span
            className="riskbar finding-risk-bar"
            aria-hidden="true"
          >
            <span
              className={
                `riskbar-fill${
                  tone === "neutral"
                    ? ""
                    : ` sev-${tone}`
                }`
              }
              style={{ width: `${riskPercent}%` }}
            />
          </span>
        </div>
      </div>

      <div className="finding-detail-heading">
        <h3 className="finding-detail-title">
          {finding.title}
        </h3>
        <p className="finding-detail-id mono wrap-anywhere">
          {finding.id}
        </p>
      </div>

      <section className="finding-section">
        <h4 className="finding-section-title">
          Description
        </h4>
        <p className="finding-description">
          {finding.description}
        </p>
      </section>

      <section className="finding-section">
        <h4 className="finding-section-title">
          Affected Assets
          <span className="finding-section-count">
            {finding.affected_assets.length}
          </span>
        </h4>

        {finding.affected_assets.length > 0 ? (
          <ul className="finding-assets">
            {finding.affected_assets.map((asset) => (
              <li
                className="finding-asset"
                key={asset}
              >
                {asset.includes(":") && (
                  <span className="finding-asset-type">
                    {asset.split(":")[0]}
                  </span>
                )}
                <span className="mono wrap-anywhere">
                  {asset}
                </span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="finding-section-empty">
            No specific assets are linked to this
            finding.
          </p>
        )}
      </section>

      <section className="finding-section">
        <h4 className="finding-section-title">
          Evidence
          <span className="finding-section-count">
            {finding.evidence.length}
          </span>
        </h4>

        {finding.evidence.length > 0 ? (
          <ol className="finding-evidence-list">
            {finding.evidence.map((item, index) => (
              <li
                className="finding-evidence-item"
                key={`${finding.id}-evidence-${index}`}
              >
                <span
                  className="finding-evidence-index"
                  aria-hidden="true"
                >
                  {index + 1}
                </span>
                <p className="wrap-anywhere">{item}</p>
              </li>
            ))}
          </ol>
        ) : (
          <p className="finding-section-empty">
            No evidence recorded for this finding.
          </p>
        )}
      </section>

      <section className="finding-section">
        <h4 className="finding-section-title">
          Recommended Remediation
        </h4>

        {finding.remediation ? (
          <div className="finding-remediation">
            <Icon name="remediate" size={16} />
            <p>{finding.remediation}</p>
          </div>
        ) : (
          <p className="finding-section-empty">
            No remediation guidance is currently
            available for this finding.
          </p>
        )}
      </section>

      <details className="finding-more">
        <summary>
          <Icon name="chevron-right" size={14} />
          Additional details
        </summary>

        <dl className="finding-more-grid">
          <div>
            <dt>Category</dt>
            <dd>{formatCategory(finding.category)}</dd>
          </div>

          <div>
            <dt>Severity</dt>
            <dd>{finding.severity.toUpperCase()}</dd>
          </div>

          <div>
            <dt>Affected assets</dt>
            <dd>{finding.affected_assets.length}</dd>
          </div>

          <div>
            <dt>Evidence items</dt>
            <dd>{finding.evidence.length}</dd>
          </div>

          {finding.comparisonStatus && (
            <div>
              <dt>Status vs. prior scan</dt>
              <dd>
                {finding.comparisonStatus.toUpperCase()}
              </dd>
            </div>
          )}

          <div className="finding-more-wide">
            <dt>Finding ID</dt>
            <dd className="mono wrap-anywhere">
              {finding.id}
            </dd>
          </div>
        </dl>
      </details>
    </article>
  );
}


function FindingsLoadingSkeleton() {
  return (
    <div
      className="findings-layout"
      role="status"
      aria-label="Loading findings"
    >
      <div
        className="panel findings-list-panel"
        aria-hidden="true"
      >
        <div className="findings-list-head">
          <SkeletonLine width="40%" />
        </div>

        <div className="findings-list-scroll">
          {Array.from({ length: 6 }, (_, index) => (
            <div
              className="finding-row-skeleton"
              key={index}
            >
              <SkeletonLine width="35%" />
              <SkeletonLine width="92%" />
              <SkeletonLine width="58%" />
            </div>
          ))}
        </div>
      </div>

      <div
        className="panel finding-detail-panel"
        aria-hidden="true"
      >
        <div className="finding-detail-skeleton">
          <SkeletonLine width="42%" />
          <SkeletonLine width="72%" height={20} />
          <SkeletonLine width="34%" />
          <SkeletonLine width="100%" />
          <SkeletonLine width="100%" />
          <SkeletonLine width="64%" />
        </div>
      </div>
    </div>
  );
}


/* ---------- helpers ---------- */

function severityTone(
  severity: string,
): SeverityTone {
  switch (severity.toLowerCase()) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "medium":
      return "medium";
    case "low":
      return "low";
    case "info":
      return "info";
    default:
      return "neutral";
  }
}


function severityBadgeClass(
  severity: string,
): string {
  const tone = severityTone(severity);
  return tone === "neutral"
    ? "badge-neutral"
    : `badge-${tone}`;
}


function statusBadgeClass(status: string): string {
  switch (status) {
    case "new":
      return "badge-info";
    case "resolved":
      return "badge-success";
    default:
      return "badge-neutral";
  }
}


function getFindingRegions(
  finding: Finding,
): string[] {
  return [
    ...new Set(
      finding.affected_assets
        .map((asset) => asset.split(":")[0])
        .filter((region) => region),
    ),
  ];
}


function formatCategory(category: string) {
  return category
    .replaceAll("_", " ")
    .replace(
      /\b\w/g,
      (character) => character.toUpperCase(),
    );
}


export default Findings;
