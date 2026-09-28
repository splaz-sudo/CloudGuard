import {
  useCallback,
  useEffect,
  useState,
} from "react";

import {
  CloudGuardAPIError,
  getFindings,
  getOverview,
} from "../services/api";

import type {
  Finding,
  Overview as OverviewData,
} from "../types/cloudguard";


function Overview() {
  const [overview, setOverview] =
    useState<OverviewData | null>(null);

  const [findings, setFindings] =
    useState<Finding[]>([]);

  const [loading, setLoading] =
    useState(true);

  const [error, setError] =
    useState<CloudGuardAPIError | null>(null);

  const loadDashboard =
    useCallback(async () => {
      setLoading(true);
      setError(null);

      try {
        const [
          overviewData,
          findingsData,
        ] = await Promise.all([
          getOverview(),
          getFindings(),
        ]);

        setOverview(overviewData);
        setFindings(findingsData);
      } catch (requestError) {
        if (
          requestError
          instanceof CloudGuardAPIError
        ) {
          setError(requestError);
        } else {
          setError(
            new CloudGuardAPIError(
              "Unable to load the CloudGuard dashboard.",
            ),
          );
        }
      } finally {
        setLoading(false);
      }
    }, []);

  useEffect(() => {
    void loadDashboard();
  }, [loadDashboard]);

  if (loading) {
    return (
      <section className="page-state">
        Analyzing cloud environment...
      </section>
    );
  }

  if (error || !overview) {
    return (
      <section className="page-state error-message">
        <div>
          <h2>
            CloudGuard API unavailable
          </h2>

          <p>
            The dashboard cannot connect to the
            CloudGuard backend. Make sure the API
            service is running, then try again.
          </p>

          {error?.status && (
            <p>
              HTTP status: {error.status}
            </p>
          )}

          {error?.requestId && (
            <p>
              Request ID:{" "}
              <code>
                {error.requestId}
              </code>
            </p>
          )}

          <button
            type="button"
            onClick={() => {
              void loadDashboard();
            }}
          >
            Retry
          </button>
        </div>
      </section>
    );
  }

  return (
    <>
      <header className="topbar">
        <div>
          <p className="eyebrow">
            SECURITY OVERVIEW
          </p>

          <h2>Cloud Security Posture</h2>

          <p className="subtitle">
            Contextual risk analysis across cloud
            assets and relationships.
          </p>
        </div>

        <div className="environment-badge">
          LOCAL LAB
        </div>
      </header>

      <section className="metric-grid">
        <MetricCard
          label="Highest Risk"
          value={overview.highest_risk_score}
          detail="/ 100"
          risk
        />

        <MetricCard
          label="Cloud Assets"
          value={overview.assets}
          detail={
            `${overview.sensitive_assets} sensitive`
          }
        />

        <MetricCard
          label="Attack Paths"
          value={overview.attack_paths}
          detail="To sensitive resources"
        />

        <MetricCard
          label="Findings"
          value={overview.findings}
          detail={
            `Across ${overview.relationships} relationships`
          }
        />
      </section>

      <section className="content-grid">
        <article className="panel">
          <div className="panel-header">
            <div>
              <p className="eyebrow">
                RISK DISTRIBUTION
              </p>

              <h3>Security Posture</h3>
            </div>

            <span className="live-label">
              LIVE
            </span>
          </div>

          <div className="severity-list">
            <SeverityRow
              name="Critical"
              value={overview.severity.critical}
              severity="critical"
            />

            <SeverityRow
              name="High"
              value={overview.severity.high}
              severity="high"
            />

            <SeverityRow
              name="Medium"
              value={overview.severity.medium}
              severity="medium"
            />

            <SeverityRow
              name="Low"
              value={overview.severity.low}
              severity="low"
            />
          </div>

          <div className="exposure-summary">
            <span>
              Internet-exposed assets
            </span>

            <strong>
              {
                overview
                  .internet_exposed_assets
              }
            </strong>
          </div>
        </article>

        <article className="panel">
          <div className="panel-header">
            <div>
              <p className="eyebrow">
                ATTACK SURFACE
              </p>

              <h3>Exposure Summary</h3>
            </div>
          </div>

          <div className="attack-summary">
            <div className="attack-node">
              Internet
            </div>

            <span className="arrow">
              →
            </span>

            <div className="attack-node">
              EC2
            </div>

            <span className="arrow">
              →
            </span>

            <div className="attack-node">
              IAM Role
            </div>

            <span className="arrow">
              →
            </span>

            <div className="attack-node sensitive">
              S3
            </div>
          </div>

          <p className="attack-description">
            CloudGuard discovered a reachable
            path from the public internet to a
            sensitive storage resource.
          </p>
        </article>
      </section>

      <section className="panel findings-panel">
        <div className="panel-header">
          <div>
            <p className="eyebrow">
              PRIORITIZED RISKS
            </p>

            <h3>Security Findings</h3>
          </div>

          <span className="finding-count">
            {findings.length} findings
          </span>
        </div>

        <div className="findings-list">
          {findings.map((finding) => (
            <article
              className="finding"
              key={finding.id}
            >
              <div className="finding-main">
                <span
                  className={
                    `severity-badge ${
                      finding.severity
                        .toLowerCase()
                    }`
                  }
                >
                  {finding.severity}
                </span>

                <div>
                  <h4>
                    {finding.title}
                  </h4>

                  <p>
                    {finding.description}
                  </p>

                  <div className="finding-assets">
                    {
                      finding
                        .affected_assets
                        .map((asset) => (
                          <span key={asset}>
                            {asset}
                          </span>
                        ))
                    }
                  </div>
                </div>
              </div>

              <div className="finding-risk">
                <span>Risk</span>

                <strong>
                  {finding.risk_score}
                </strong>
              </div>
            </article>
          ))}
        </div>
      </section>
    </>
  );
}


type MetricCardProps = {
  label: string;
  value: number;
  detail: string;
  risk?: boolean;
};


function MetricCard({
  label,
  value,
  detail,
  risk = false,
}: MetricCardProps) {
  return (
    <article
      className={
        risk
          ? "metric-card risk-card"
          : "metric-card"
      }
    >
      <span className="metric-label">
        {label}
      </span>

      <strong
        className={
          risk
            ? "risk-score"
            : undefined
        }
      >
        {value}
      </strong>

      <span className="metric-detail">
        {detail}
      </span>
    </article>
  );
}


type SeverityRowProps = {
  name: string;
  value: number;
  severity: string;
};


function SeverityRow({
  name,
  value,
  severity,
}: SeverityRowProps) {
  const width =
    value === 0
      ? "0%"
      : `${Math.min(
          value * 35,
          100,
        )}%`;

  return (
    <div className="severity-row">
      <div className="severity-meta">
        <span>{name}</span>

        <strong>
          {value}
        </strong>
      </div>

      <div className="severity-track">
        <div
          className={
            `severity-fill ${severity}`
          }
          style={{ width }}
        />
      </div>
    </div>
  );
}


export default Overview;