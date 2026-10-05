import "../styles/remediations.css";

import {
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";

import { useLocation } from "react-router-dom";

import Icon from "../components/Icon";

import {
  EmptyState,
  ErrorState,
  SkeletonCard,
} from "../components/StateBlock";

import {
  CloudGuardAPIError,
  getScanPrioritizedRemediations,
  simulateScanRemediation,
} from "../services/api";

import {
  useScanContext,
} from "../context/ScanContext";

import type {
  Remediation,
  SimulationResult,
} from "../types/cloudguard";


function Remediations() {
  const { selectedScan } =
    useScanContext();

  const scanId =
    selectedScan?.scan_id ?? null;

  const location = useLocation();

  const requestedRemediationId = (
    location.state as { remediationId?: string } | null
  )?.remediationId;

  const autoSimulatedRef = useRef<string | null>(null);

  const [remediations, setRemediations] =
    useState<Remediation[]>([]);

  const [loading, setLoading] =
    useState(true);

  const [error, setError] =
    useState<CloudGuardAPIError | null>(null);

  const [simulations, setSimulations] =
    useState<
      Record<string, SimulationResult>
    >({});

  const [simulating, setSimulating] =
    useState<Record<string, boolean>>({});

  const [simulationErrors, setSimulationErrors] =
    useState<Record<string, string>>({});


  const loadRemediations =
    useCallback(async () => {
      if (!scanId) {
        return;
      }

      setLoading(true);
      setError(null);

      try {
        const data =
          await getScanPrioritizedRemediations(
            scanId,
          );

        setRemediations(data);
        setSimulations({});
      } catch (requestError) {
        if (
          requestError
          instanceof CloudGuardAPIError
        ) {
          setError(requestError);
        } else {
          setError(
            new CloudGuardAPIError(
              "Unable to load remediations.",
            ),
          );
        }
      } finally {
        setLoading(false);
      }
    }, [scanId]);


  useEffect(() => {
    void loadRemediations();
  }, [loadRemediations]);

  // A fix handed over from the Overview page runs its simulation once the
  // matching remediation for the current scan has loaded.
  useEffect(() => {
    if (!requestedRemediationId || loading) {
      return;
    }

    if (autoSimulatedRef.current === requestedRemediationId) {
      return;
    }

    const isKnown = remediations.some(
      (entry) =>
        entry.remediation_id === requestedRemediationId,
    );

    if (!isKnown) {
      return;
    }

    autoSimulatedRef.current = requestedRemediationId;
    void runSimulation(requestedRemediationId);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [requestedRemediationId, loading, remediations]);


  async function runSimulation(
    remediationId: string,
  ) {
    if (!scanId) {
      return;
    }

    setSimulating((current) => ({
      ...current,
      [remediationId]: true,
    }));

    setSimulationErrors((current) => ({
      ...current,
      [remediationId]: "",
    }));

    try {
      const result =
        await simulateScanRemediation(
          scanId,
          remediationId,
        );

      setSimulations((current) => ({
        ...current,
        [remediationId]: result,
      }));
    } catch (requestError) {
      const message =
        requestError instanceof Error
          ? requestError.message
          : "Simulation request failed.";

      setSimulationErrors((current) => ({
        ...current,
        [remediationId]: message,
      }));
    } finally {
      setSimulating((current) => ({
        ...current,
        [remediationId]: false,
      }));
    }
  }


  const pageHeader = (
    <header className="topbar">
      <div>
        <p className="eyebrow">
          Remediation
        </p>

        <h2>
          What Should I Fix First?
        </h2>

        <p className="page-subtitle">
          Recommendations ranked by simulated
          impact on attack paths and
          CloudGuard risk. Simulation is
          read-only and never modifies cloud
          resources.
        </p>
      </div>

      {!loading && !error && (
        <span className="badge badge-neutral badge-lg no-dot">
          {remediations.length} remediation
          {remediations.length === 1
            ? ""
            : "s"}
        </span>
      )}
    </header>
  );


  if (loading) {
    return (
      <div className="page">
        {pageHeader}

        <div
          className="rem-list"
          aria-busy="true"
          aria-label="Loading remediations"
        >
          <SkeletonCard lines={4} />
          <SkeletonCard lines={4} />
          <SkeletonCard lines={4} />
        </div>
      </div>
    );
  }


  if (error) {
    return (
      <div className="page">
        {pageHeader}

        <ErrorState
          error={error}
          resourceLabel="remediation analysis"
          onRetry={() => {
            void loadRemediations();
          }}
        />
      </div>
    );
  }


  return (
    <div className="page">
      {pageHeader}

      {remediations.length === 0 ? (
        <EmptyState
          icon="remediate"
          title="No remediations identified"
          body="The current analysis did not surface any supported remediation actions for this scan."
        />
      ) : (
        <section
          className="rem-list"
          aria-label="Prioritized remediations"
        >
          {remediations.map(
            (remediation, index) => (
              <RemediationCard
                key={
                  remediation.remediation_id
                }
                rank={index + 1}
                remediation={remediation}
                simulation={
                  simulations[
                    remediation
                      .remediation_id
                  ]
                }
                simulating={
                  simulating[
                    remediation
                      .remediation_id
                  ] ?? false
                }
                simulationError={
                  simulationErrors[
                    remediation
                      .remediation_id
                  ] ?? null
                }
                onSimulate={() => {
                  void runSimulation(
                    remediation
                      .remediation_id,
                  );
                }}
              />
            ),
          )}
        </section>
      )}
    </div>
  );
}


type RemediationCardProps = {
  rank: number;
  remediation: Remediation;
  simulation: SimulationResult | undefined;
  simulating: boolean;
  simulationError: string | null;
  onSimulate: () => void;
};


function RemediationCard({
  rank,
  remediation,
  simulation,
  simulating,
  simulationError,
  onSimulate,
}: RemediationCardProps) {
  const findingCount =
    remediation.finding_ids.length;

  const riskDelta =
    remediation.risk_reduction;

  return (
    <article className="panel rem-card">
      <div className="rem-card-head">
        <span
          className="rem-rank"
          aria-label={`Rank ${rank}`}
        >
          {rank}
        </span>

        <div className="rem-head-main">
          <div className="rem-badges">
            <span
              className={`badge no-dot ${priorityBadgeClass(
                remediation.priority,
              )}`}
              title="Remediation priority"
            >
              {priorityLabel(
                remediation.priority,
              )}
            </span>

            <span className="badge badge-neutral no-dot">
              {formatActionType(
                remediation.action_type,
              )}
            </span>
          </div>

          <h3 className="rem-title">
            {remediation.title}
          </h3>

          <p className="rem-desc">
            {remediation.description}
          </p>
        </div>

        <div className="rem-delta">
          {riskDelta !== null ? (
            <>
              <span
                className="badge badge-success badge-lg no-dot"
                title="Simulated risk reduction — no changes were made"
              >
                &minus;{riskDelta} risk
              </span>

              {remediation.risk_reduction_percent
                !== null && (
                <span className="rem-delta-note">
                  &minus;
                  {Math.round(
                    remediation
                      .risk_reduction_percent,
                  )}
                  % projected
                </span>
              )}
            </>
          ) : (
            <span className="badge badge-neutral badge-lg no-dot">
              Risk delta &mdash;
            </span>
          )}
        </div>
      </div>

      <div className="rem-stats">
        <RemediationMetric
          label="Attack paths affected"
          value={String(
            remediation.paths_affected,
          )}
        />

        <RemediationMetric
          label="Findings addressed"
          value={String(findingCount)}
        />

        <RemediationMetric
          label="Risk before"
          value={formatNullable(
            remediation.risk_before,
          )}
        />

        <RemediationMetric
          label="Risk after (projected)"
          value={formatNullable(
            remediation.risk_after,
          )}
        />
      </div>

      {remediation.affected_resources.length
        > 0 && (
        <div className="rem-resources">
          <span className="rem-label">
            Affected resources
          </span>

          <div className="chip-row">
            {remediation.affected_resources.map(
              (resource) => (
                <span
                  className="chip"
                  key={resource}
                >
                  <span className="mono">
                    {resource}
                  </span>
                </span>
              ),
            )}
          </div>
        </div>
      )}

      <details className="rem-details">
        <summary className="rem-details-summary">
          <Icon
            name="chevron-right"
            size={14}
            className="rem-details-chev"
          />
          Evidence, expected effect &amp;
          manual steps
        </summary>

        <div className="rem-details-body">
          <p className="rem-label">
            Evidence
          </p>

          <ul className="rem-evidence">
            {remediation.evidence.map(
              (item) => (
                <li key={item}>{item}</li>
              ),
            )}
          </ul>

          <p className="rem-label">
            Expected effect
          </p>

          <p className="rem-text">
            {remediation.expected_effect}
          </p>

          {remediation.manual_steps.length
            > 0 && (
            <>
              <p className="rem-label">
                Manual steps
              </p>

              <ol className="rem-steps">
                {remediation.manual_steps.map(
                  (step) => (
                    <li key={step}>
                      {step}
                    </li>
                  ),
                )}
              </ol>
            </>
          )}
        </div>
      </details>

      <div className="rem-actions">
        <button
          type="button"
          className="btn btn-primary"
          disabled={simulating}
          onClick={onSimulate}
        >
          {simulating ? (
            <>
              <span
                className="btn-spinner"
                aria-hidden="true"
              />
              Simulating&hellip;
            </>
          ) : (
            <>
              <Icon name="play" size={14} />
              {simulation
                ? "Re-run Simulation"
                : "Simulate Fix"}
            </>
          )}
        </button>

        {simulationError && (
          <p
            className="rem-sim-error"
            role="alert"
          >
            <Icon name="alert" size={14} />
            {simulationError}
          </p>
        )}
      </div>

      {simulation && (
        <SimulationPanel
          simulation={simulation}
        />
      )}
    </article>
  );
}


function RemediationMetric({
  label,
  value,
}: {
  label: string;
  value: string;
}) {
  return (
    <div className="rem-stat">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}


function SimulationPanel({
  simulation,
}: {
  simulation: SimulationResult;
}) {
  const { before, after, impact } =
    simulation;

  return (
    <section
      className="sim-panel"
      aria-label="Simulated result — no changes were made to AWS"
    >
      <div
        className="sim-disclaimer"
        role="note"
      >
        <Icon name="info" size={14} />
        <span>
          <strong>SIMULATED</strong>
          {" — no changes were made to AWS. "}
          This is a read-only preview.
        </span>
      </div>

      <div className="sim-flow">
        <SimStateCard
          label="Before"
          highestRisk={before.highest_risk}
          attackPaths={before.attack_paths}
          findings={before.findings}
        />

        <div className="sim-connector">
          <span
            className="sim-connector-arrow"
            aria-hidden="true"
          >
            <Icon
              name="chevron-right"
              size={16}
            />
          </span>

          <span className="sim-connector-chip">
            &minus;{impact.risk_reduction}{" "}
            risk (
            {Math.round(
              impact.risk_reduction_percent,
            )}
            %)
          </span>

          <span className="sim-connector-sub">
            &minus;{impact.paths_removed}{" "}
            attack path
            {impact.paths_removed === 1
              ? ""
              : "s"}
          </span>
        </div>

        <SimStateCard
          label="After (simulated)"
          highestRisk={after.highest_risk}
          attackPaths={after.attack_paths}
          findings={after.findings}
          after
        />
      </div>

      <p className="sim-note">
        {simulation.note}
      </p>
    </section>
  );
}


function SimStateCard({
  label,
  highestRisk,
  attackPaths,
  findings,
  after = false,
}: {
  label: string;
  highestRisk: number;
  attackPaths: number;
  findings: number;
  after?: boolean;
}) {
  return (
    <div
      className={
        after
          ? "sim-state sim-state-after"
          : "sim-state"
      }
    >
      <p className="sim-state-label">
        {label}
      </p>

      <div className="sim-state-metrics">
        <div className="sim-metric">
          <span>Highest risk</span>
          <strong>{highestRisk}</strong>
        </div>

        <div className="sim-metric">
          <span>Attack paths</span>
          <strong>{attackPaths}</strong>
        </div>

        <div className="sim-metric">
          <span>Findings</span>
          <strong>{findings}</strong>
        </div>
      </div>
    </div>
  );
}


function priorityLabel(
  priority: number | null,
) {
  return priority === null
    ? "Unranked"
    : `P${priority}`;
}


function priorityBadgeClass(
  priority: number | null,
) {
  switch (priority) {
    case 1:
      return "badge-critical";
    case 2:
      return "badge-high";
    case 3:
      return "badge-medium";
    default:
      return "badge-neutral";
  }
}


function formatActionType(
  value: string,
) {
  return value
    .replaceAll("_", " ")
    .toUpperCase();
}


function formatNullable(
  value: number | null,
) {
  return value === null
    ? "—"
    : String(value);
}


export default Remediations;
