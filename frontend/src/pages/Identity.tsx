import {
  useEffect,
  useMemo,
  useState,
} from "react";

import {
  getIdentityRisks,
} from "../services/api";

import type {
  IdentityRisk,
} from "../types/cloudguard";


function Identity() {
  const [identities, setIdentities] =
    useState<IdentityRisk[]>([]);

  const [
    selectedIdentity,
    setSelectedIdentity,
  ] = useState<IdentityRisk | null>(
    null,
  );

  const [loading, setLoading] =
    useState(true);

  const [error, setError] =
    useState<string | null>(null);


  useEffect(() => {
    async function loadIdentityRisks() {
      try {
        const data =
          await getIdentityRisks();

        setIdentities(data);

        if (data.length > 0) {
          setSelectedIdentity(data[0]);
        }
      } catch (requestError) {
        setError(
          requestError instanceof Error
            ? requestError.message
            : (
              "Unable to load identity " +
              "risk analysis."
            ),
        );
      } finally {
        setLoading(false);
      }
    }

    loadIdentityRisks();
  }, []);


  const metrics = useMemo(() => {
    const critical = identities.filter(
      (identity) =>
        identity.severity.toLowerCase() ===
        "critical",
    ).length;

    const high = identities.filter(
      (identity) =>
        identity.severity.toLowerCase() ===
        "high",
    ).length;

    const exposed = identities.filter(
      (identity) =>
        identity.exposed_workloads.length > 0,
    ).length;

    const sensitive = identities.filter(
      (identity) =>
        identity.sensitive_resources.length >
        0,
    ).length;

    return {
      critical,
      high,
      exposed,
      sensitive,
    };
  }, [identities]);


  if (loading) {
    return (
      <section className="page-state">
        Analyzing IAM identities...
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
            IDENTITY SECURITY
          </p>

          <h2>
            Identity & IAM Risk
          </h2>

          <p className="subtitle">
            Contextual analysis of observed IAM
            permissions, workload exposure,
            sensitive-resource access, and
            attack-path participation.
          </p>
        </div>

        <div className="environment-badge">
          {identities.length} IDENTITIES
        </div>
      </header>


      <section className="identity-metrics">
        <IdentityMetric
          label="Critical"
          value={metrics.critical}
        />

        <IdentityMetric
          label="High Risk"
          value={metrics.high}
        />

        <IdentityMetric
          label="Exposed Workload"
          value={metrics.exposed}
        />

        <IdentityMetric
          label="Sensitive Access"
          value={metrics.sensitive}
        />
      </section>


      {identities.length === 0 ? (
        <section className="panel">
          <div className="page-state">
            No IAM identities were discovered.
          </div>
        </section>
      ) : (
        <section className="identity-layout">
          <div className="identity-list-panel">
            <div className="identity-list-header">
              <div>
                <p className="eyebrow">
                  IDENTITIES
                </p>

                <h3>
                  Risk Prioritization
                </h3>
              </div>
            </div>

            <div className="identity-list">
              {identities.map(
                (identity) => (
                  <button
                    key={
                      identity.identity_id
                    }
                    type="button"
                    className={
                      selectedIdentity
                        ?.identity_id ===
                      identity.identity_id
                        ? (
                          "identity-list-item " +
                          "selected"
                        )
                        : "identity-list-item"
                    }
                    onClick={() =>
                      setSelectedIdentity(
                        identity,
                      )
                    }
                  >
                    <div>
                      <strong>
                        {
                          identity
                            .identity_name
                        }
                      </strong>

                      <span>
                        {formatIdentityType(
                          identity
                            .identity_type,
                        )}
                      </span>
                    </div>

                    <div className="identity-score">
                      <span
                        className={
                          `identity-severity ${
                            identity.severity
                              .toLowerCase()
                          }`
                        }
                      >
                        {
                          identity
                            .severity
                            .toUpperCase()
                        }
                      </span>

                      <strong>
                        {
                          identity
                            .risk_score
                        }
                      </strong>
                    </div>
                  </button>
                ),
              )}
            </div>
          </div>


          <div className="identity-details-panel">
            {selectedIdentity && (
              <IdentityDetails
                identity={
                  selectedIdentity
                }
              />
            )}
          </div>
        </section>
      )}
    </>
  );
}


function IdentityMetric({
  label,
  value,
}: {
  label: string;
  value: number;
}) {
  return (
    <article className="identity-metric">
      <span>{label}</span>
      <strong>{value}</strong>
    </article>
  );
}


function IdentityDetails({
  identity,
}: {
  identity: IdentityRisk;
}) {
  return (
    <>
      <div className="identity-detail-header">
        <div>
          <p className="eyebrow">
            IDENTITY PROFILE
          </p>

          <h3>
            {identity.identity_name}
          </h3>

          <p>
            {formatIdentityType(
              identity.identity_type,
            )}
          </p>
        </div>

        <div className="identity-risk-score">
          <span>Risk Score</span>

          <strong>
            {identity.risk_score}
          </strong>

          <small
            className={
              `identity-severity ${
                identity.severity
                  .toLowerCase()
              }`
            }
          >
            {identity.severity.toUpperCase()}
          </small>
        </div>
      </div>


      <div className="identity-section">
        <p className="details-section-title">
          Risk Factors
        </p>

        {identity.risk_factors.length ===
        0 ? (
          <p className="details-text">
            No contextual risk factors were
            detected.
          </p>
        ) : (
          <div className="risk-factor-list">
            {identity.risk_factors.map(
              (factor) => (
                <div
                  className="risk-factor"
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


      <div className="identity-section">
        <p className="details-section-title">
          Observed Permissions
        </p>

        {identity.permissions.length === 0 ? (
          <p className="details-text">
            No permissions were observed in
            the current graph.
          </p>
        ) : (
          <div className="permission-list">
            {identity.permissions.map(
              (permission) => (
                <span
                  className="permission-chip"
                  key={permission}
                >
                  {permission}
                </span>
              ),
            )}
          </div>
        )}
      </div>


      <div className="identity-section-grid">
        <IdentityResourceList
          title="Exposed Workloads"
          resources={
            identity.exposed_workloads
          }
          empty="No exposed workloads."
          warning
        />

        <IdentityResourceList
          title="Sensitive Resources"
          resources={
            identity.sensitive_resources
          }
          empty="No sensitive resources."
          danger
        />
      </div>


      <div className="identity-section">
        <p className="details-section-title">
          Connected Assets
        </p>

        <div className="identity-resource-list">
          {identity.connected_assets.length ===
          0 ? (
            <p className="details-text">
              No connected assets.
            </p>
          ) : (
            identity.connected_assets.map(
              (asset) => (
                <div
                  className="identity-resource"
                  key={asset}
                >
                  {asset}
                </div>
              ),
            )
          )}
        </div>
      </div>


      <div className="identity-section">
        <p className="details-section-title">
          Attack Path Participation
        </p>

        {identity.attack_paths.length ===
        0 ? (
          <p className="details-text">
            This identity does not participate
            in a discovered attack path.
          </p>
        ) : (
          <div className="identity-paths">
            {identity.attack_paths.map(
              (path, pathIndex) => (
                <div
                  className="identity-path"
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


      <div className="identity-disclaimer">
        CloudGuard currently reports observed
        permissions and graph-derived access.
        This is not a complete calculation of
        AWS effective IAM permissions.
      </div>
    </>
  );
}


function IdentityResourceList({
  title,
  resources,
  empty,
  warning = false,
  danger = false,
}: {
  title: string;
  resources: string[];
  empty: string;
  warning?: boolean;
  danger?: boolean;
}) {
  return (
    <div className="identity-resource-card">
      <p className="details-section-title">
        {title}
      </p>

      {resources.length === 0 ? (
        <p className="details-text">
          {empty}
        </p>
      ) : (
        <div className="identity-resource-list">
          {resources.map(
            (resource) => (
              <div
                key={resource}
                className={[
                  "identity-resource",
                  warning
                    ? "warning"
                    : "",
                  danger
                    ? "danger"
                    : "",
                ].join(" ")}
              >
                {resource}
              </div>
            ),
          )}
        </div>
      )}
    </div>
  );
}


function formatIdentityType(
  value: string,
) {
  return value
    .replaceAll("_", " ")
    .toUpperCase();
}


export default Identity;