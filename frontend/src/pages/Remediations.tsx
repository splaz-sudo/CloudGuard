import {
  useCallback,
  useEffect,
  useState,
} from "react";

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


  if (loading) {
    return (
      <section className="page-state">
        Evaluating remediations against the
        current security state...
      </section>
    );
  }


  if (error) {
    return (
      <section className="page-state error-message">
        <div>
          <h2>
            CloudGuard API unavailable
          </h2>

          <p>
            Remediation analysis could not be
            loaded. Make sure the API service is
            running, then try again.
          </p>

          {error.status && (
            <p>
              HTTP status: {error.status}
            </p>
          )}

          <button
            type="button"
            onClick={() => {
              void loadRemediations();
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
            REMEDIATION
          </p>

          <h2>
            What Should I Fix First?
          </h2>

          <p className="subtitle">
            Recommendations ranked by simulated
            impact on attack paths and
            CloudGuard risk. Simulation is
            read-only and never modifies cloud
            resources.
          </p>
        </div>

        <div className="environment-badge">
          {remediations.length} REMEDIATION
          {remediations.length === 1
            ? ""
            : "S"}
        </div>
      </header>

      {remediations.length === 0 ? (
        <section className="panel">
          <p className="details-text">
            No supported remediation conditions
            were detected in the current
            analysis.
          </p>
        </section>
      ) : (
        <section className="remediation-list">
          {remediations.map(
            (remediation) => (
              <RemediationCard
                key={
                  remediation.remediation_id
                }
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
    </>
  );
}


type RemediationCardProps = {
  remediation: Remediation;
  simulation: SimulationResult | undefined;
  simulating: boolean;
  simulationError: string | null;
  onSimulate: () => void;
};


function RemediationCard({
  remediation,
  simulation,
  simulating,
  simulationError,
  onSimulate,
}: RemediationCardProps) {
  return (
    <article className="panel remediation-card">
      <div className="remediation-header">
        <span className="remediation-rank">
          #{remediation.priority ?? "—"}
        </span>

        <div className="remediation-heading">
          <h3>{remediation.title}</h3>

          <span className="remediation-action">
            {formatActionType(
              remediation.action_type,
            )}
          </span>
        </div>
      </div>

      <p className="details-text">
        {remediation.description}
      </p>

      <div className="finding-assets">
        {remediation.affected_resources.map(
          (resource) => (
            <span key={resource}>
              {resource}
            </span>
          ),
        )}
      </div>

      <div className="remediation-metrics">
        <RemediationMetric
          label="Attack paths affected"
          value={String(
            remediation.paths_affected,
          )}
        />

        <RemediationMetric
          label="Paths removed"
          value={formatNullable(
            remediation.paths_removed,
          )}
        />

        <RemediationMetric
          label="Risk before"
          value={formatNullable(
            remediation.risk_before,
          )}
        />

        <RemediationMetric
          label="Risk after"
          value={formatNullable(
            remediation.risk_after,
          )}
        />

        <RemediationMetric
          label="Risk reduction"
          value={formatNullable(
            remediation.risk_reduction,
          )}
        />
      </div>

      <div className="details-divider" />

      <p className="details-section-title">
        Evidence
      </p>

      <ul className="remediation-evidence">
        {remediation.evidence.map((item) => (
          <li key={item}>{item}</li>
        ))}
      </ul>

      <p className="details-section-title">
        Expected effect
      </p>

      <p className="details-text">
        {remediation.expected_effect}
      </p>

      <button
        type="button"
        className="simulate-button"
        disabled={simulating}
        onClick={onSimulate}
      >
        {simulating
          ? "SIMULATING..."
          : "SIMULATE FIX"}
      </button>

      {simulationError && (
        <p className="simulation-error">
          {simulationError}
        </p>
      )}

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
    <div className="remediation-metric">
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
  return (
    <div className="simulation-panel">
      <div className="simulation-header">
        <span className="simulation-badge">
          SIMULATION ONLY
        </span>

        <p className="simulation-note">
          {simulation.note}
        </p>
      </div>

      <div className="simulation-grid">
        <div className="simulation-column">
          <p className="eyebrow">BEFORE</p>

          <SimulationRow
            label="Highest risk"
            value={
              simulation.before.highest_risk
            }
          />

          <SimulationRow
            label="Attack paths"
            value={
              simulation.before.attack_paths
            }
          />

          <SimulationRow
            label="Findings"
            value={
              simulation.before.findings
            }
          />
        </div>

        <div className="simulation-column">
          <p className="eyebrow">AFTER</p>

          <SimulationRow
            label="Highest risk"
            value={
              simulation.after.highest_risk
            }
          />

          <SimulationRow
            label="Attack paths"
            value={
              simulation.after.attack_paths
            }
          />

          <SimulationRow
            label="Findings"
            value={
              simulation.after.findings
            }
          />
        </div>

        <div className="simulation-column">
          <p className="eyebrow">IMPACT</p>

          <SimulationRow
            label="Paths removed"
            value={
              simulation.impact.paths_removed
            }
          />

          <SimulationRow
            label="Risk reduction"
            value={
              simulation.impact
                .risk_reduction
            }
          />

          <SimulationRow
            label="Reduction %"
            value={
              simulation.impact
                .risk_reduction_percent
            }
          />
        </div>
      </div>
    </div>
  );
}


function SimulationRow({
  label,
  value,
}: {
  label: string;
  value: number;
}) {
  return (
    <div className="simulation-row">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
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
