import Icon from "../Icon";
import { RiskGauge } from "./RiskGauge";
import { StatusBadge } from "./StatusBadge";
import { MetricStrip } from "./MetricStrip";

export interface SimulationState {
  highestRisk: number;
  attackPaths: number;
  findings: number;
}

export interface SimulationImpact {
  pathsRemoved: number;
  removedPathIds: string[];
  riskReduction: number;
  riskReductionPercent: number;
}

export interface SimulationDiffProps {
  before: SimulationState;
  after: SimulationState;
  impact: SimulationImpact;
  remediationTitle?: string;
  remediationActionType?: string;
  note?: string;
  className?: string;
  animate?: boolean;
}

export function SimulationDiff({
  before,
  after,
  impact,
  remediationTitle,
  remediationActionType,
  note,
  className = "",
  animate = true,
}: SimulationDiffProps) {
  const riskDelta = after.highestRisk - before.highestRisk;
  const pathsDelta = after.attackPaths - before.attackPaths;
  const findingsDelta = after.findings - before.findings;

  return (
    <section
      className={`simulation-diff ${animate ? "animate" : ""} ${className}`}
      role="region"
      aria-label="Remediation simulation result — read-only, no cloud changes"
    >
      <div className="sim-diff-header">
        <div className="sim-diff-title-group">
          {remediationTitle && <h4 className="sim-diff-title">{remediationTitle}</h4>}
          {remediationActionType && (
            <StatusBadge variant="info" size="sm" showDot={false}>
              {remediationActionType.replace(/_/g, " ").toUpperCase()}
            </StatusBadge>
          )}
        </div>

        <StatusBadge variant="simulated" size="md" icon="info">
          SIMULATED — READ-ONLY
        </StatusBadge>
      </div>

      <div className="sim-diff-flow">
        <SimStateCard
          label="BEFORE"
          state={before}
          variant="before"
          animate={animate}
        />

        <div className="sim-diff-connector">
          <div className="sim-diff-arrow" aria-hidden="true">
            <Icon name="chevron-right" size={18} />
          </div>

          <div className="sim-diff-deltas">
            <MetricStrip
              label="Risk"
              value={riskDelta > 0 ? `+${riskDelta}` : riskDelta < 0 ? `${riskDelta}` : "±0"}
              tone={riskDelta > 0 ? "danger" : riskDelta < 0 ? "success" : "neutral"}
              icon={riskDelta > 0 ? "warning" : riskDelta < 0 ? "check" : "info"}
            />

            <MetricStrip
              label="Attack Paths"
              value={pathsDelta > 0 ? `+${pathsDelta}` : pathsDelta < 0 ? `${pathsDelta}` : "±0"}
              tone={pathsDelta > 0 ? "danger" : pathsDelta < 0 ? "success" : "neutral"}
              icon={pathsDelta > 0 ? "warning" : pathsDelta < 0 ? "check" : "info"}
            />

            <MetricStrip
              label="Findings"
              value={findingsDelta > 0 ? `+${findingsDelta}` : findingsDelta < 0 ? `${findingsDelta}` : "±0"}
              tone={findingsDelta > 0 ? "danger" : findingsDelta < 0 ? "success" : "neutral"}
              icon={findingsDelta > 0 ? "warning" : findingsDelta < 0 ? "check" : "info"}
            />
          </div>
        </div>

        <SimStateCard
          label="AFTER (SIMULATED)"
          state={after}
          variant="after"
          animate={animate}
        />
      </div>

      {impact.pathsRemoved > 0 && (
        <div className="sim-diff-impact">
          <div className="sim-diff-impact-main">
            <StatusBadge variant="success" size="md" icon="check">
              {impact.pathsRemoved} attack path{impact.pathsRemoved === 1 ? "" : "s"} removed
            </StatusBadge>

            <div className="sim-diff-risk-reduction">
              <span className="sim-diff-reduction-label">Risk reduction</span>
              <span className="sim-diff-reduction-value tone-success">
                −{impact.riskReduction} ({Math.round(impact.riskReductionPercent)}%)
              </span>
            </div>
          </div>

          {impact.removedPathIds.length > 0 && (
            <details className="sim-diff-removed-paths">
              <summary>
                <Icon name="chevron-right" size={12} />
                Removed path IDs
              </summary>
              <div className="chip-row">
                {impact.removedPathIds.map((id, i) => (
                  <span key={i} className="chip mono">{id}</span>
                ))}
              </div>
            </details>
          )}
        </div>
      )}

      {note && (
        <p className="sim-diff-note">
          <Icon name="info" size={12} />
          {note}
        </p>
      )}
    </section>
  );
}

function SimStateCard({
  label,
  state,
  variant,
  animate,
}: {
  label: string;
  state: SimulationState;
  variant: "before" | "after";
  animate: boolean;
}) {
  return (
    <article className={`sim-state-card ${variant}`}>
      <header className="sim-state-header">
        <span className="sim-state-label">{label}</span>
        {variant === "after" && (
          <StatusBadge variant="simulated" size="sm" showDot={false}>
            SIMULATED
          </StatusBadge>
        )}
      </header>

      <div className="sim-state-metrics">
        <MetricStrip
          label="Highest Risk"
          value={state.highestRisk}
          icon="warning"
          tone={state.highestRisk >= 75 ? "critical" : state.highestRisk >= 50 ? "high" : state.highestRisk >= 25 ? "medium" : "low"}
        />

        <MetricStrip
          label="Attack Paths"
          value={state.attackPaths}
          icon="paths"
          tone={state.attackPaths > 0 ? "warning" : "success"}
        />

        <MetricStrip
          label="Findings"
          value={state.findings}
          icon="findings"
          tone={state.findings > 10 ? "warning" : state.findings > 0 ? "info" : "success"}
        />
      </div>

      <RiskGauge
        score={state.highestRisk}
        size={100}
        strokeWidth={6}
        showLabel={false}
        showValue={true}
        animate={animate}
        className="sim-state-gauge"
      />
    </article>
  );
}

export function SimulationDiffCompact({
  before,
  after,
  impact,
  className = "",
  animate = true,
}: {
  before: SimulationState;
  after: SimulationState;
  impact: SimulationImpact;
  className?: string;
  animate?: boolean;
}) {
  const riskDelta = after.highestRisk - before.highestRisk;
  const tone = riskDelta > 0 ? "danger" : riskDelta < 0 ? "success" : "neutral";

  return (
    <div className={`sim-diff-compact ${className}`}>
      <div className="sim-diff-compact-flow">
        <div className="sim-diff-compact-state">
          <span className="sim-diff-compact-label">Before</span>
          <RiskGauge score={before.highestRisk} size={60} strokeWidth={4} showLabel={false} animate={animate} />
          <div className="sim-diff-compact-metrics">
            <span>{before.attackPaths} paths</span>
            <span>{before.findings} findings</span>
          </div>
        </div>

        <div className="sim-diff-compact-connector">
          <Icon name="chevron-right" size={16} />
          <span className={`sim-diff-compact-delta tone-${tone}`}>
            {riskDelta > 0 ? `+${riskDelta}` : `${riskDelta}`} risk
          </span>
          <span className="sim-diff-compact-delta tone-success">
            −{impact.pathsRemoved} paths
          </span>
        </div>

        <div className="sim-diff-compact-state after">
          <span className="sim-diff-compact-label">After</span>
          <RiskGauge score={after.highestRisk} size={60} strokeWidth={4} showLabel={false} animate={animate} />
          <div className="sim-diff-compact-metrics">
            <span>{after.attackPaths} paths</span>
            <span>{after.findings} findings</span>
          </div>
        </div>
      </div>

      <StatusBadge variant="simulated" size="sm" icon="info">
        SIMULATED — NO CLOUD CHANGES
      </StatusBadge>
    </div>
  );
}