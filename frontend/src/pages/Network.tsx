import {
  useEffect,
  useMemo,
  useState,
} from "react";

import {
  getScanNetworkRisks,
} from "../services/api";

import {
  useScanContext,
} from "../context/ScanContext";

import type {
  ExposedService,
  NetworkRisk,
} from "../types/cloudguard";


function Network() {
  const { selectedScan } =
    useScanContext();

  const scanId =
    selectedScan?.scan_id ?? null;

  const [risks, setRisks] =
    useState<NetworkRisk[]>([]);

  const [
    selectedRisk,
    setSelectedRisk,
  ] = useState<NetworkRisk | null>(
    null,
  );

  const [loading, setLoading] =
    useState(true);

  const [error, setError] =
    useState<string | null>(null);


  useEffect(() => {
    if (!scanId) {
      return;
    }

    const currentScanId: string = scanId;

    async function loadNetworkRisks() {
      setLoading(true);
      setError(null);

      try {
        const data =
          await getScanNetworkRisks(
            currentScanId,
          );

        setRisks(data);

        if (data.length > 0) {
          setSelectedRisk(data[0]);
        } else {
          setSelectedRisk(null);
        }
      } catch (requestError) {
        setError(
          requestError instanceof Error
            ? requestError.message
            : (
              "Unable to load network " +
              "risk analysis."
            ),
        );
      } finally {
        setLoading(false);
      }
    }

    loadNetworkRisks();
  }, [scanId]);


  const metrics = useMemo(() => {
    const publicAssets = risks.filter(
      (risk) => Boolean(risk.public_ip),
    ).length;

    const exposedServices = risks.reduce(
      (total, risk) =>
        total +
        risk.exposed_services.length,
      0,
    );

    const highRisk = risks.filter(
      (risk) => {
        const severity =
          risk.severity.toLowerCase();

        return (
          severity === "high" ||
          severity === "critical"
        );
      },
    ).length;

    const sensitivePaths = risks.filter(
      (risk) =>
        risk.sensitive_resources.length >
        0 &&
        risk.attack_paths.length > 0,
    ).length;

    return {
      publicAssets,
      exposedServices,
      highRisk,
      sensitivePaths,
    };
  }, [risks]);


  if (loading) {
    return (
      <section className="page-state">
        Analyzing network exposure...
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
            NETWORK SECURITY
          </p>

          <h2>
            Network Exposure
          </h2>

          <p className="subtitle">
            Internet exposure, security-group
            ingress, workload identity, and
            sensitive-resource correlation.
          </p>
        </div>

        <div className="environment-badge">
          {risks.length} WORKLOADS
        </div>
      </header>


      <section className="network-metrics">
        <NetworkMetric
          label="Public Assets"
          value={metrics.publicAssets}
        />

        <NetworkMetric
          label="Exposed Services"
          value={metrics.exposedServices}
        />

        <NetworkMetric
          label="High Risk"
          value={metrics.highRisk}
        />

        <NetworkMetric
          label="Sensitive Paths"
          value={metrics.sensitivePaths}
        />
      </section>


      {risks.length === 0 ? (
        <section className="panel">
          <div className="page-state">
            No network risks were discovered.
          </div>
        </section>
      ) : (
        <section className="network-layout">
          <div className="network-list-panel">
            <div className="network-list-header">
              <div>
                <p className="eyebrow">
                  WORKLOADS
                </p>

                <h3>
                  Exposure Prioritization
                </h3>
              </div>
            </div>

            <div className="network-list">
              {risks.map((risk) => (
                <button
                  key={risk.asset_id}
                  type="button"
                  className={
                    selectedRisk?.asset_id ===
                    risk.asset_id
                      ? (
                        "network-list-item " +
                        "selected"
                      )
                      : "network-list-item"
                  }
                  onClick={() =>
                    setSelectedRisk(risk)
                  }
                >
                  <div>
                    <strong>
                      {risk.asset_name}
                    </strong>

                    <span>
                      {risk.public_ip ??
                        "No public IP"}
                    </span>
                  </div>

                  <div className="network-score">
                    <span
                      className={
                        `network-severity ${
                          risk.severity
                            .toLowerCase()
                        }`
                      }
                    >
                      {risk.severity
                        .toUpperCase()}
                    </span>

                    <strong>
                      {risk.risk_score}
                    </strong>
                  </div>
                </button>
              ))}
            </div>
          </div>


          <div className="network-details-panel">
            {selectedRisk && (
              <NetworkDetails
                risk={selectedRisk}
              />
            )}
          </div>
        </section>
      )}
    </>
  );
}


function NetworkMetric({
  label,
  value,
}: {
  label: string;
  value: number;
}) {
  return (
    <article className="network-metric">
      <span>{label}</span>
      <strong>{value}</strong>
    </article>
  );
}


function NetworkDetails({
  risk,
}: {
  risk: NetworkRisk;
}) {
  return (
    <>
      <div className="network-detail-header">
        <div>
          <p className="eyebrow">
            WORKLOAD PROFILE
          </p>

          <h3>
            {risk.asset_name}
          </h3>

          <p>
            {risk.public_ip
              ? `Public IP: ${risk.public_ip}`
              : "No public IP"}
          </p>
        </div>

        <div className="network-risk-score">
          <span>Risk Score</span>

          <strong>
            {risk.risk_score}
          </strong>

          <small
            className={
              `network-severity ${
                risk.severity
                  .toLowerCase()
              }`
            }
          >
            {risk.severity.toUpperCase()}
          </small>
        </div>
      </div>


      <div className="network-section">
        <p className="details-section-title">
          Internet Exposure
        </p>

        {risk.exposed_services.length ===
        0 ? (
          <p className="details-text">
            No internet-accessible inbound
            services were detected.
          </p>
        ) : (
          <div className="network-service-list">
            {risk.exposed_services.map(
              (service, index) => (
                <ServiceCard
                  key={
                    `${service.security_group_id}-${index}`
                  }
                  service={service}
                  asset={risk.asset_name}
                />
              ),
            )}
          </div>
        )}
      </div>


      <div className="network-section-grid">
        <NetworkResourceCard
          title="Security Groups"
          values={risk.security_groups}
          empty="No security groups."
        />

        <NetworkResourceCard
          title="Attached Identities"
          values={
            risk.attached_identities
          }
          empty="No IAM identities."
          warning
        />

        <NetworkResourceCard
          title="Sensitive Resources"
          values={
            risk.sensitive_resources
          }
          empty="No sensitive resources."
          danger
        />

        <NetworkResourceCard
          title="Private Address"
          values={
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


      <div className="network-section">
        <p className="details-section-title">
          Risk Factors
        </p>

        {risk.risk_factors.length === 0 ? (
          <p className="details-text">
            No contextual network risk
            factors were detected.
          </p>
        ) : (
          <div className="network-risk-factors">
            {risk.risk_factors.map(
              (factor) => (
                <div
                  className="network-risk-factor"
                  key={factor}
                >
                  <span>!</span>
                  <p>{factor}</p>
                </div>
              ),
            )}
          </div>
        )}
      </div>


      <div className="network-section">
        <p className="details-section-title">
          Attack Path Correlation
        </p>

        {risk.attack_paths.length === 0 ? (
          <p className="details-text">
            This workload does not participate
            in a discovered attack path.
          </p>
        ) : (
          <div className="network-paths">
            {risk.attack_paths.map(
              (path, pathIndex) => (
                <div
                  className="network-path"
                  key={pathIndex}
                >
                  {path.map(
                    (node, nodeIndex) => (
                      <div
                        key={
                          `${node}-${nodeIndex}`
                        }
                      >
                        <span>
                          {node}
                        </span>

                        {nodeIndex <
                          path.length - 1 && (
                          <b>→</b>
                        )}
                      </div>
                    ),
                  )}
                </div>
              ),
            )}
          </div>
        )}
      </div>


      <div className="network-disclaimer">
        Network risk is calculated from
        CloudGuard's observed public addressing,
        security-group ingress, graph
        relationships, and attack paths. The
        score is a CloudGuard contextual risk
        score, not an AWS-native severity.
      </div>
    </>
  );
}


function ServiceCard({
  service,
  asset,
}: {
  service: ExposedService;
  asset: string;
}) {
  return (
    <div className="network-service-card">
      <div className="network-service-route">
        <span className="network-source">
          {service.sources.join(", ")}
        </span>

        <b>→</b>

        <span className="network-port">
          {formatService(service)}
        </span>

        <b>→</b>

        <span className="network-target">
          {asset}
        </span>
      </div>

      <div className="network-service-meta">
        <span>
          {service.security_group_name}
        </span>

        <code>
          {service.security_group_id}
        </code>
      </div>
    </div>
  );
}


function NetworkResourceCard({
  title,
  values,
  empty,
  warning = false,
  danger = false,
}: {
  title: string;
  values: string[];
  empty: string;
  warning?: boolean;
  danger?: boolean;
}) {
  return (
    <div className="network-resource-card">
      <p className="details-section-title">
        {title}
      </p>

      {values.length === 0 ? (
        <p className="details-text">
          {empty}
        </p>
      ) : (
        <div className="network-resource-list">
          {values.map((value) => (
            <div
              key={value}
              className={[
                "network-resource",
                warning ? "warning" : "",
                danger ? "danger" : "",
              ].join(" ")}
            >
              {value}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}


function formatService(
  service: ExposedService,
) {
  const protocol =
    service.protocol.toUpperCase();

  if (
    service.from_port === null ||
    service.to_port === null
  ) {
    return `${protocol} / ALL`;
  }

  if (
    service.from_port ===
    service.to_port
  ) {
    return (
      `${protocol} / ` +
      `${service.from_port}`
    );
  }

  return (
    `${protocol} / ` +
    `${service.from_port}-` +
    `${service.to_port}`
  );
}


export default Network;