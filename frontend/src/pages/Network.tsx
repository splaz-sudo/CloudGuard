import {
  Fragment,
  useMemo,
  useState,
  type CSSProperties,
} from "react";

import {
  getScanNetworkRisks,
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
  ExposedService,
  NetworkRisk,
} from "../types/cloudguard";

import "../styles/network.css";


const PREVIEW_ROWS = 4;


function Network() {
  const {
    selectedScan,
    loading: scansLoading,
  } = useScanContext();

  const scanId =
    selectedScan?.scan_id ?? null;

  const query = useScanQuery(
    getScanNetworkRisks,
    scanId,
    { enabled: Boolean(scanId) },
  );

  const risks = useMemo(
    () => query.data ?? [],
    [query.data],
  );

  const [selectedId, setSelectedId] =
    useState<string | null>(null);

  // Derived selection: keep the user's choice
  // while it exists in the current data, and
  // fall back to the highest-priority (first)
  // workload when data arrives or the scan
  // changes.
  const selectedRisk =
    risks.find(
      (risk) => risk.asset_id === selectedId,
    ) ?? risks[0] ?? null;


  const metrics = useMemo(() => {
    const publicWorkloads = risks.filter(
      (risk) => Boolean(risk.public_ip),
    ).length;

    const exposedServices = risks.reduce(
      (total, risk) =>
        total + risk.exposed_services.length,
      0,
    );

    const openToWorld = risks.reduce(
      (total, risk) =>
        total
        + risk.exposed_services.filter(
          (service) =>
            service.sources.some(
              isWorldOpenSource,
            ),
        ).length,
      0,
    );

    return {
      publicWorkloads,
      exposedServices,
      openToWorld,
    };
  }, [risks]);


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
          + "sidebar to review network analysis."
        }
      />
    );
  } else if (query.loading) {
    content = (
      <LoadingState label="Analyzing network exposure…" />
    );
  } else if (query.error) {
    content = (
      <ErrorState
        error={query.error}
        resourceLabel="network analysis"
        onRetry={query.retry}
      />
    );
  } else if (risks.length === 0) {
    content = (
      <EmptyState
        icon="network"
        title="No network exposure discovered"
        body={
          "The selected scan did not flag any "
          + "workloads with network exposure "
          + "signals."
        }
      />
    );
  } else {
    content = (
      <>
        <section
          className="stat-grid"
          style={{ "--i": 1 } as CSSProperties}
          aria-label="Network exposure summary"
        >
          <div className="stat">
            <span className="stat-label">
              <Icon name="network" size={13} />
              Workloads
            </span>

            <span className="stat-value">
              {risks.length}
            </span>
          </div>

          <div className="stat">
            <span className="stat-label">
              <Icon name="globe" size={13} />
              Public workloads
            </span>

            <span className="stat-value net-value-danger">
              {metrics.publicWorkloads}
            </span>

            <span className="stat-foot">
              Reachable from the internet
            </span>
          </div>

          <div className="stat">
            <span className="stat-label">
              <Icon name="eye" size={13} />
              Exposed services
            </span>

            <span className="stat-value">
              {metrics.exposedServices}
            </span>

            <span className="stat-foot">
              Inbound service rules
            </span>
          </div>

          <div className="stat">
            <span className="stat-label">
              <Icon name="alert" size={13} />
              Open to world
            </span>

            <span className="stat-value net-value-danger">
              {metrics.openToWorld}
            </span>

            <span className="stat-foot">
              Rules open to 0.0.0.0/0 or ::/0
            </span>
          </div>
        </section>


        <section
          className="network-layout"
          style={{ "--i": 2 } as CSSProperties}
        >
          <div className="panel">
            <div className="panel-header">
              <h3 className="panel-title">
                Exposure prioritization
              </h3>

              <span className="badge badge-neutral badge-sm no-dot">
                {risks.length}
              </span>
            </div>

            <ul
              className="network-list"
              aria-label="Workloads by exposure"
            >
              {risks.map((risk) => (
                <li key={risk.asset_id}>
                  <NetworkListItem
                    risk={risk}
                    selected={
                      risk.asset_id
                      === selectedRisk?.asset_id
                    }
                    onSelect={() =>
                      setSelectedId(risk.asset_id)
                    }
                  />
                </li>
              ))}
            </ul>
          </div>


          <div className="panel network-detail-panel">
            {selectedRisk ? (
              <NetworkDetails risk={selectedRisk} />
            ) : (
              <EmptyState
                icon="network"
                title="Select a workload"
                body={
                  "Choose a workload from the "
                  + "list to inspect its exposure."
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
            NETWORK SECURITY
          </p>

          <h2>Network Exposure</h2>

          <p className="page-subtitle">
            Internet exposure, security-group
            ingress, workload identity, and
            sensitive-resource correlation.
          </p>
        </div>

        {risks.length > 0 && (
          <span className="badge badge-info badge-lg no-dot">
            {risks.length} workloads
          </span>
        )}
      </header>

      {content}
    </div>
  );
}


function NetworkListItem({
  risk,
  selected,
  onSelect,
}: {
  risk: NetworkRisk;
  selected: boolean;
  onSelect: () => void;
}) {
  const isPublic = Boolean(risk.public_ip);

  return (
    <button
      type="button"
      className={
        "network-item"
        + (isPublic ? " is-public" : "")
        + (selected ? " selected" : "")
      }
      aria-current={selected || undefined}
      onClick={onSelect}
    >
      <span className="network-item-top">
        <span className="network-item-name truncate">
          {risk.asset_name}
        </span>

        <ExposureBadge isPublic={isPublic} />
      </span>

      <span className="network-item-meta">
        <span className="mono muted wrap-anywhere">
          {risk.public_ip ?? "No public IP"}
        </span>

        <span
          className="network-meta"
          title="Exposed services"
        >
          <Icon name="eye" size={12} />
          {risk.exposed_services.length}
        </span>

        <span
          className={
            "network-meta"
            + (
              risk.sensitive_resources.length > 0
                ? " net-meta-danger"
                : ""
            )
          }
          title="Sensitive resources reachable"
        >
          <Icon name="lock" size={12} />
          {risk.sensitive_resources.length}
        </span>

        <span
          className={
            "badge badge-sm "
            + severityBadgeClass(risk.severity)
          }
        >
          {risk.severity.toUpperCase()}
        </span>

        <span className="network-item-score">
          {risk.risk_score}
        </span>
      </span>
    </button>
  );
}


function ExposureBadge({
  isPublic,
  size = "sm",
}: {
  isPublic: boolean;
  size?: "sm" | "lg";
}) {
  return isPublic ? (
    <span
      className={
        `badge badge-danger no-dot badge-${size}`
      }
    >
      <Icon name="globe" size={11} />
      PUBLIC
    </span>
  ) : (
    <span
      className={
        `badge badge-neutral no-dot badge-${size}`
      }
    >
      <Icon name="lock" size={11} />
      PRIVATE
    </span>
  );
}


function NetworkDetails({
  risk,
}: {
  risk: NetworkRisk;
}) {
  const isPublic = Boolean(risk.public_ip);
  const score = clampScore(risk.risk_score);

  return (
    <>
      <div className="panel-header">
        <div className="grow">
          <p className="eyebrow">
            WORKLOAD PROFILE
          </p>

          <h3 className="network-detail-name">
            {risk.asset_name}
          </h3>

          <p className="mono muted wrap-anywhere mt-2">
            {risk.asset_id}
          </p>

          <div className="chip-row mt-2">
            <ExposureBadge
              isPublic={isPublic}
              size="lg"
            />

            <span
              className={
                "badge badge-sm "
                + severityBadgeClass(risk.severity)
              }
            >
              {risk.severity.toUpperCase()} RISK
            </span>

            {risk.attack_paths.length > 0 && (
              <span className="badge badge-sm badge-danger no-dot">
                <Icon name="paths" size={11} />
                In {risk.attack_paths.length}{" "}
                attack path
                {risk.attack_paths.length === 1
                  ? ""
                  : "s"}
              </span>
            )}
          </div>
        </div>

        <div className="network-score">
          <span className="network-score-label">
            Risk score
          </span>

          <div className="riskbar-with-value">
            <div className="riskbar">
              <div
                className={
                  "riskbar-fill "
                  + severityBarClass(risk.severity)
                }
                style={{ width: `${score}%` }}
              />
            </div>

            <span className="riskbar-value">
              {risk.risk_score}
            </span>
          </div>

          <p className="stat-foot mt-2">
            {risk.public_ip ? (
              <>
                Public IP{" "}
                <span className="mono wrap-anywhere">
                  {risk.public_ip}
                </span>
              </>
            ) : (
              "No public IP assigned"
            )}
          </p>
        </div>
      </div>


      <div className="panel-body">
        <section className="network-section">
          <h4 className="network-section-title">
            <Icon name="globe" size={13} />
            Inbound exposure
            <span className="badge badge-sm badge-neutral no-dot">
              {risk.exposed_services.length}
            </span>
          </h4>

          {risk.exposed_services.length === 0 ? (
            <p className="muted">
              No internet-accessible inbound
              services were detected.
            </p>
          ) : (
            <div className="table-wrap">
              <div className="table-scroll">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th scope="col">Service</th>
                      <th scope="col">Source</th>
                      <th scope="col">
                        Security group
                      </th>
                    </tr>
                  </thead>

                  <tbody>
                    {risk.exposed_services.map(
                      (service, index) => (
                        <ServiceRuleRow
                          key={
                            `${service.security_group_id}-${index}`
                          }
                          service={service}
                        />
                      ),
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </section>


        <div
          className={
            "network-section "
            + "network-section-grid"
          }
        >
          <NetworkResourceCard
            icon="shield"
            tone="neutral"
            title="Security groups"
            items={risk.security_groups}
            empty="No security groups."
          />

          <NetworkResourceCard
            icon="identity"
            tone="warning"
            title="Attached identities"
            items={risk.attached_identities}
            empty="No IAM identities."
          />

          <NetworkResourceCard
            icon="lock"
            tone="danger"
            title="Sensitive resources"
            items={risk.sensitive_resources}
            empty="No sensitive resources."
          />

          <NetworkResourceCard
            icon="network"
            tone="neutral"
            title="Private address"
            items={
              risk.metadata.private_ip
                ? [
                  String(
                    risk.metadata.private_ip,
                  ),
                ]
                : []
            }
            empty="No private IP recorded."
          />
        </div>


        <section className="network-section">
          <h4 className="network-section-title">
            <Icon name="warning" size={13} />
            Risk factors
            <span className="badge badge-sm badge-neutral no-dot">
              {risk.risk_factors.length}
            </span>
          </h4>

          {risk.risk_factors.length === 0 ? (
            <p className="muted">
              No contextual network risk factors
              were detected.
            </p>
          ) : (
            <ul className="net-factors">
              {risk.risk_factors.map((factor) => (
                <li
                  className="net-factor"
                  key={factor}
                >
                  <Icon name="alert" size={13} />
                  <span>{factor}</span>
                </li>
              ))}
            </ul>
          )}
        </section>


        <section className="network-section">
          <h4 className="network-section-title">
            <Icon name="paths" size={13} />
            Attack path correlation
            <span className="badge badge-sm badge-neutral no-dot">
              {risk.attack_paths.length}
            </span>
          </h4>

          {risk.attack_paths.length === 0 ? (
            <p className="muted">
              This workload does not participate
              in a discovered attack path.
            </p>
          ) : (
            <div className="net-paths">
              {risk.attack_paths.map(
                (path, pathIndex) => (
                  <div
                    className="net-path"
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
                              className="net-path-arrow"
                            />
                          )}

                          <span className="net-path-node mono wrap-anywhere">
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


        <p className="network-disclaimer">
          <Icon name="info" size={13} />
          <span>
            Network risk is calculated from
            CloudGuard&apos;s observed public
            addressing, security-group ingress,
            graph relationships, and attack
            paths. The score is a CloudGuard
            contextual risk score, not an
            AWS-native severity.
          </span>
        </p>
      </div>
    </>
  );
}


/**
 * One inbound rule: port range + protocol chips,
 * source CIDRs, and the owning security group.
 * Technical values stay mono and wrap safely.
 */
function ServiceRuleRow({
  service,
}: {
  service: ExposedService;
}) {
  return (
    <tr>
      <td>
        <span className="chip-row net-chips">
          <span className="chip">
            <span className="mono">
              {service.protocol.toUpperCase()}
            </span>
          </span>

          <span className="chip">
            <span className="mono">
              {formatPortRange(service)}
            </span>
          </span>
        </span>
      </td>

      <td>
        <span className="chip-row net-chips">
          {service.sources.map((source) =>
            isWorldOpenSource(source) ? (
              <span
                className="chip net-chip-danger"
                key={source}
              >
                <Icon name="globe" size={11} />
                <span className="mono wrap-anywhere">
                  {source}
                </span>
              </span>
            ) : (
              <span className="chip" key={source}>
                <span className="mono wrap-anywhere">
                  {source}
                </span>
              </span>
            ),
          )}
        </span>
      </td>

      <td>
        <div className="net-sg">
          <span className="secondary">
            {service.security_group_name}
          </span>

          <span className="mono muted wrap-anywhere">
            {service.security_group_id}
          </span>
        </div>
      </td>
    </tr>
  );
}


function NetworkResourceCard({
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
  const visible = items.slice(0, PREVIEW_ROWS);
  const hidden = items.slice(PREVIEW_ROWS);

  return (
    <div className="net-mini-card">
      <div className="net-mini-head">
        <span
          className={
            `net-mini-icon${
              tone === "neutral" ? "" : ` ${tone}`
            }`
          }
        >
          <Icon name={icon} size={13} />
        </span>

        <span className="net-mini-title">
          {title}
        </span>

        <span className="badge badge-sm badge-neutral no-dot">
          {items.length}
        </span>
      </div>

      {items.length === 0 ? (
        <p className="muted">{empty}</p>
      ) : (
        <>
          <div className="net-rows">
            {visible.map((item) => (
              <div
                className="net-row mono"
                key={item}
              >
                {item}
              </div>
            ))}
          </div>

          {hidden.length > 0 && (
            <details className="net-disclosure mt-2">
              <summary>
                <Icon
                  name="chevron-right"
                  size={13}
                />
                Show all ({hidden.length} more)
              </summary>

              <div className="net-disclosure-body">
                <div className="net-rows">
                  {hidden.map((item) => (
                    <div
                      className="net-row mono"
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
      )}
    </div>
  );
}


function formatPortRange(
  service: ExposedService,
): string {
  if (
    service.from_port === null
    || service.to_port === null
  ) {
    return "ALL";
  }

  if (service.from_port === service.to_port) {
    return `${service.from_port}`;
  }

  return `${service.from_port}-${service.to_port}`;
}


function isWorldOpenSource(source: string): boolean {
  const normalized = source.trim();

  return (
    normalized === "0.0.0.0/0"
    || normalized === "::/0"
  );
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


export default Network;
