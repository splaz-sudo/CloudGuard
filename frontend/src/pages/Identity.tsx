import {
  Fragment,
  useMemo,
  useState,
  type CSSProperties,
} from "react";

import {
  getScanIdentityRisks,
} from "../services/api";

import {
  useScanContext,
} from "../context/ScanContext";

import {
  useScanQuery,
} from "../hooks/useApiQuery";

import Icon, { type IconName } from "../components/Icon";

import {
  EmptyState,
  ErrorState,
  LoadingState,
} from "../components/StateBlock";

import type {
  IdentityRisk,
} from "../types/cloudguard";

import "../styles/identity.css";


const PREVIEW_ROWS = 4;
const PREVIEW_CHIPS = 8;


function Identity() {
  const {
    selectedScan,
    loading: scansLoading,
  } = useScanContext();

  const scanId =
    selectedScan?.scan_id ?? null;

  const query = useScanQuery(
    getScanIdentityRisks,
    scanId,
    { enabled: Boolean(scanId) },
  );

  const identities = useMemo(
    () => query.data ?? [],
    [query.data],
  );

  const [selectedId, setSelectedId] =
    useState<string | null>(null);

  // Derived selection: keep the user's choice
  // while it exists in the current data, and
  // fall back to the highest-priority (first)
  // identity when data arrives or the scan
  // changes.
  const selectedIdentity =
    identities.find(
      (identity) =>
        identity.identity_id === selectedId,
    ) ?? identities[0] ?? null;


  const metrics = useMemo(() => {
    const highPrivilege = identities.filter(
      (identity) => {
        const severity =
          identity.severity.toLowerCase();

        return (
          severity === "critical"
          || severity === "high"
        );
      },
    ).length;

    const sensitiveReach = identities.filter(
      (identity) =>
        identity.sensitive_resources.length > 0,
    ).length;

    const exposed = identities.filter(
      (identity) =>
        identity.exposed_workloads.length > 0,
    ).length;

    return {
      highPrivilege,
      sensitiveReach,
      exposed,
    };
  }, [identities]);


  let content: React.ReactNode;

  if (!scanId) {
    content = scansLoading ? (
      <LoadingState label="Loading scan context…" />
    ) : (
      <EmptyState
        icon="scans"
        title="No scan selected"
        body={
          "Select or start a scan from the "
          + "sidebar to review identity analysis."
        }
      />
    );
  } else if (query.loading) {
    content = (
      <LoadingState label="Analyzing IAM identities…" />
    );
  } else if (query.error) {
    content = (
      <ErrorState
        error={query.error}
        resourceLabel="identity analysis"
        onRetry={query.retry}
      />
    );
  } else if (identities.length === 0) {
    content = (
      <EmptyState
        icon="identity"
        title="No IAM identities discovered"
        body={
          "The selected scan did not observe "
          + "any IAM users, roles, or instance "
          + "profiles to assess."
        }
      />
    );
  } else {
    content = (
      <>
        <section
          className="stat-grid"
          style={{ "--i": 1 } as CSSProperties}
          aria-label="Identity risk summary"
        >
          <div className="stat">
            <span className="stat-label">
              <Icon name="identity" size={13} />
              Identities assessed
            </span>

            <span className="stat-value">
              {identities.length}
            </span>
          </div>

          <div className="stat">
            <span className="stat-label">
              <Icon name="shield" size={13} />
              High privilege
            </span>

            <span className="stat-value id-value-danger">
              {metrics.highPrivilege}
            </span>

            <span className="stat-foot">
              Critical or high privilege-risk
            </span>
          </div>

          <div className="stat">
            <span className="stat-label">
              <Icon name="lock" size={13} />
              Reach sensitive
            </span>

            <span className="stat-value id-value-warning">
              {metrics.sensitiveReach}
            </span>

            <span className="stat-foot">
              Can reach sensitive resources
            </span>
          </div>

          <div className="stat">
            <span className="stat-label">
              <Icon name="globe" size={13} />
              Exposed workloads
            </span>

            <span className="stat-value">
              {metrics.exposed}
            </span>

            <span className="stat-foot">
              Linked to exposed workloads
            </span>
          </div>
        </section>


        <section
          className="identity-layout"
          style={{ "--i": 2 } as CSSProperties}
        >
          <div className="panel">
            <div className="panel-header">
              <h3 className="panel-title">
                Risk prioritization
              </h3>

              <span className="badge badge-neutral badge-sm no-dot">
                {identities.length}
              </span>
            </div>

            <ul
              className="identity-list"
              aria-label="Identities by risk"
            >
              {identities.map((identity) => (
                <li key={identity.identity_id}>
                  <IdentityListItem
                    identity={identity}
                    selected={
                      identity.identity_id
                      === selectedIdentity?.identity_id
                    }
                    onSelect={() =>
                      setSelectedId(
                        identity.identity_id,
                      )
                    }
                  />
                </li>
              ))}
            </ul>
          </div>


          <div className="panel identity-detail-panel">
            {selectedIdentity ? (
              <IdentityDetails
                identity={selectedIdentity}
              />
            ) : (
              <EmptyState
                icon="identity"
                title="Select an identity"
                body={
                  "Choose an identity from the "
                  + "list to inspect its privilege "
                  + "risk."
                }
              />
            )}
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
            IDENTITY SECURITY
          </p>

          <h2>Identity &amp; IAM Risk</h2>

          <p className="page-subtitle">
            Contextual analysis of observed IAM
            permissions, workload exposure,
            sensitive-resource access, and
            attack-path participation.
          </p>
        </div>

        {identities.length > 0 && (
          <span className="badge badge-info badge-lg no-dot">
            {identities.length} identities assessed
          </span>
        )}
      </header>

      {content}
    </div>
  );
}


function IdentityListItem({
  identity,
  selected,
  onSelect,
}: {
  identity: IdentityRisk;
  selected: boolean;
  onSelect: () => void;
}) {
  const inAttackPath =
    identity.attack_paths.length > 0;

  return (
    <button
      type="button"
      className={
        `identity-item${selected ? " selected" : ""}`
      }
      aria-current={selected || undefined}
      onClick={onSelect}
    >
      <span className="identity-item-top">
        <span className="identity-item-name truncate">
          {identity.identity_name}
        </span>

        <span
          className={
            "badge badge-sm "
            + severityBadgeClass(identity.severity)
          }
        >
          {identity.severity.toUpperCase()}
        </span>
      </span>

      <span className="identity-item-meta">
        <span
          className={
            "badge badge-sm no-dot "
            + identityTypeBadgeClass(
              identity.identity_type,
            )
          }
        >
          {formatIdentityType(identity.identity_type)}
        </span>

        <span
          className="identity-meta"
          title="Observed permissions"
        >
          <Icon name="shield" size={12} />
          {identity.permissions.length}
        </span>

        <span
          className="identity-meta"
          title="Sensitive resources reachable"
        >
          <Icon name="lock" size={12} />
          {identity.sensitive_resources.length}
        </span>

        <span
          className="identity-meta"
          title="Exposed workload relationships"
        >
          <Icon name="globe" size={12} />
          {identity.exposed_workloads.length}
        </span>

        {inAttackPath && (
          <span
            className="identity-meta id-meta-danger"
            title="Participates in an attack path (privilege-escalation indicator)"
          >
            <Icon name="paths" size={12} />
            {identity.attack_paths.length}
          </span>
        )}
      </span>
    </button>
  );
}


function IdentityDetails({
  identity,
}: {
  identity: IdentityRisk;
}) {
  const score = clampScore(identity.risk_score);

  return (
    <>
      <div className="panel-header">
        <div className="grow">
          <p className="eyebrow">
            IDENTITY PROFILE
          </p>

          <h3 className="identity-detail-name">
            {identity.identity_name}
          </h3>

          <div className="chip-row mt-2">
            <span
              className={
                "badge badge-sm no-dot "
                + identityTypeBadgeClass(
                  identity.identity_type,
                )
              }
            >
              {formatIdentityType(
                identity.identity_type,
              )}
            </span>

            <span
              className={
                "badge badge-sm "
                + severityBadgeClass(
                  identity.severity,
                )
              }
            >
              {identity.severity.toUpperCase()} RISK
            </span>

            {identity.attack_paths.length > 0 && (
              <span className="badge badge-sm badge-danger no-dot">
                <Icon name="paths" size={11} />
                In {identity.attack_paths.length}{" "}
                attack path
                {identity.attack_paths.length === 1
                  ? ""
                  : "s"}
              </span>
            )}
          </div>
        </div>

        <div className="identity-score">
          <span className="identity-score-label">
            Risk score
          </span>

          <div className="riskbar-with-value">
            <div className="riskbar">
              <div
                className={
                  "riskbar-fill "
                  + severityBarClass(identity.severity)
                }
                style={{ width: `${score}%` }}
              />
            </div>

            <span className="riskbar-value">
              {identity.risk_score}
            </span>
          </div>
        </div>
      </div>


      <div className="panel-body">
        <section className="identity-section">
          <h4 className="identity-section-title">
            <Icon name="warning" size={13} />
            Privilege-escalation signals
            <span className="badge badge-sm badge-neutral no-dot">
              {identity.risk_factors.length}
            </span>
          </h4>

          {identity.risk_factors.length === 0 ? (
            <p className="muted">
              No contextual risk factors were
              detected for this identity.
            </p>
          ) : (
            <ul className="id-factors">
              {identity.risk_factors.map(
                (factor) => (
                  <li
                    className="id-factor"
                    key={factor}
                  >
                    <Icon name="alert" size={13} />
                    <span>{factor}</span>
                  </li>
                ),
              )}
            </ul>
          )}
        </section>


        <section className="identity-section">
          <h4 className="identity-section-title">
            <Icon name="shield" size={13} />
            Observed permissions
            <span className="badge badge-sm badge-neutral no-dot">
              {identity.permissions.length}
            </span>
          </h4>

          <CollapsibleRows
            items={identity.permissions}
            preview={PREVIEW_CHIPS}
            asChips
            expandLabel="Show all permissions"
            empty="No permissions were observed in the current graph."
          />
        </section>


        <div
          className={
            "identity-section "
            + "identity-section-grid"
          }
        >
          <IdentityResourceCard
            icon="lock"
            tone="danger"
            title="Sensitive resources reachable"
            items={identity.sensitive_resources}
            empty="No sensitive resources reachable."
          />

          <IdentityResourceCard
            icon="globe"
            tone="warning"
            title="Exposed workload links"
            items={identity.exposed_workloads}
            empty="No exposed workloads linked."
          />

          <IdentityResourceCard
            icon="inventory"
            tone="neutral"
            title="Connected assets"
            items={identity.connected_assets}
            empty="No connected assets."
          />
        </div>


        <section className="identity-section">
          <h4 className="identity-section-title">
            <Icon name="paths" size={13} />
            Attack path participation
            <span className="badge badge-sm badge-neutral no-dot">
              {identity.attack_paths.length}
            </span>
          </h4>

          {identity.attack_paths.length === 0 ? (
            <p className="muted">
              This identity does not participate
              in a discovered attack path.
            </p>
          ) : (
            <div className="id-paths">
              {identity.attack_paths.map(
                (path, pathIndex) => (
                  <div
                    className="id-path"
                    key={pathIndex}
                  >
                    {path.map(
                      (node, nodeIndex) => (
                        <Fragment
                          key={`${node}-${nodeIndex}`}
                        >
                          {nodeIndex > 0 && (
                            <Icon
                              name="chevron-right"
                              size={12}
                              className="id-path-arrow"
                            />
                          )}

                          <span className="id-path-node mono wrap-anywhere">
                            {node}
                          </span>
                        </Fragment>
                      ),
                    )}
                  </div>
                ),
              )}
            </div>
          )}
        </section>


        <p className="identity-disclaimer">
          <Icon name="info" size={13} />
          <span>
            CloudGuard reports observed
            permissions and graph-derived access.
            This is not a complete calculation of
            AWS effective IAM permissions.
          </span>
        </p>
      </div>
    </>
  );
}


function IdentityResourceCard({
  icon,
  tone,
  title,
  items,
  empty,
}: {
  icon: IconName;
  tone: "danger" | "warning" | "neutral";
  title: string;
  items: string[];
  empty: string;
}) {
  return (
    <div className="id-mini-card">
      <div className="id-mini-head">
        <span
          className={
            `id-mini-icon${
              tone === "neutral" ? "" : ` ${tone}`
            }`
          }
        >
          <Icon name={icon} size={13} />
        </span>

        <span className="id-mini-title">
          {title}
        </span>

        <span className="badge badge-sm badge-neutral no-dot">
          {items.length}
        </span>
      </div>

      <CollapsibleRows
        items={items}
        preview={PREVIEW_ROWS}
        expandLabel="Show all"
        empty={empty}
      />
    </div>
  );
}


/**
 * Scannable mono rows for long technical values
 * (ARNs, policy actions, asset IDs). Long lists
 * show a short preview; the remainder lives in an
 * expandable section so the page never becomes a
 * wall of policy text.
 */
function CollapsibleRows({
  items,
  preview,
  expandLabel,
  empty,
  asChips = false,
}: {
  items: string[];
  preview: number;
  expandLabel: string;
  empty: string;
  asChips?: boolean;
}) {
  if (items.length === 0) {
    return <p className="muted">{empty}</p>;
  }

  const visible = items.slice(0, preview);
  const hidden = items.slice(preview);

  return (
    <>
      {asChips ? (
        <div className="chip-row">
          {visible.map((item) => (
            <span className="chip" key={item}>
              <span className="mono wrap-anywhere">
                {item}
              </span>
            </span>
          ))}
        </div>
      ) : (
        <div className="id-rows">
          {visible.map((item) => (
            <div
              className="id-row mono"
              key={item}
            >
              {item}
            </div>
          ))}
        </div>
      )}

      {hidden.length > 0 && (
        <details className="id-disclosure mt-2">
          <summary>
            <Icon name="chevron-right" size={13} />
            {expandLabel} ({hidden.length} more)
          </summary>

          <div className="id-disclosure-body">
            <div className="id-rows">
              {hidden.map((item) => (
                <div
                  className="id-row mono"
                  key={item}
                >
                  {item}
                </div>
              ))}
            </div>
          </div>
        </details>
      )}
    </>
  );
}


function formatIdentityType(value: string) {
  return value
    .replaceAll("_", " ")
    .toUpperCase();
}


function identityTypeBadgeClass(
  value: string,
): string {
  switch (value.toLowerCase()) {
    case "iam_user":
    case "user":
      return "badge-info";
    case "instance_profile":
      return "badge-warning";
    case "iam_role":
    case "role":
    default:
      return "badge-neutral";
  }
}


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


function severityBarClass(
  severity: string,
): string {
  switch (severity.toLowerCase()) {
    case "critical":
      return "sev-critical";
    case "high":
      return "sev-high";
    case "medium":
      return "sev-medium";
    case "low":
      return "sev-low";
    default:
      return "";
  }
}


function clampScore(score: number): number {
  return Math.max(0, Math.min(100, score));
}


export default Identity;
