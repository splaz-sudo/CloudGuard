import { type CSSProperties } from "react";
import { Fragment } from "react";
import { type IconName } from "../Icon";
import Icon from "../Icon";
import { ResourceNode, type ResourceType } from "./ResourceNode";
import { normalizeResourceType } from "./resourceTypes";
import { type RelationshipType } from "./RelationshipEdge";

export interface AttackPathHop {
  source: string;
  target: string;
  relationship_type: RelationshipType;
  reason: string;
  evidence?: string | null;
  configuration?: string | null;
  impact?: string | null;
  permissions?: string[];
  confidence?: "HIGH" | "MEDIUM" | "LOW";
}

export interface AttackPathChainProps {
  nodes: string[];
  hops: AttackPathHop[];
  sensitiveTarget?: boolean;
  selectedHopIndex?: number | null;
  onSelectHop?: (index: number | null) => void;
  onSelectNode?: (nodeId: string) => void;
  onSelectEdge?: (hop: AttackPathHop) => void;
  compact?: boolean;
  animate?: boolean;
  className?: string;
  "aria-label"?: string;
}

function nodeTypeFromId(nodeId: string): ResourceType {
  const separator = nodeId.indexOf(":");
  return normalizeResourceType(separator === -1 ? nodeId : nodeId.slice(0, separator));
}

function nodeLabel(nodeId: string): string {
  const separator = nodeId.indexOf(":");
  return separator === -1 ? nodeId : nodeId.slice(separator + 1);
}

export function AttackPathChain({
  nodes,
  hops,
  sensitiveTarget = false,
  selectedHopIndex,
  onSelectHop,
  onSelectNode,
  compact = false,
  className = "",
  "aria-label": ariaLabel,
}: AttackPathChainProps) {
  return (
    <div
      className={`attack-path-chain ${compact ? "compact" : ""} ${className}`}
      role="img"
      aria-label={ariaLabel ?? `Attack path with ${nodes.length} nodes and ${hops.length} hops`}
    >
      <div className="apc-visual">
        {nodes.map((nodeId, nodeIndex) => {
          const isLast = nodeIndex === nodes.length - 1;
          const isSensitiveTarget = isLast && sensitiveTarget;
          const hop = hops[nodeIndex - 1];
          const isSelectedHop = selectedHopIndex === nodeIndex - 1;
          const isSelectedNode = false; // would be passed in

          return (
            <Fragment key={`${nodeId}-${nodeIndex}`}>
              {nodeIndex > 0 && hop && (
                <button
                  type="button"
                  className={`apc-edge ${isSelectedHop ? "selected" : ""}`}
                  onClick={() => onSelectHop?.(nodeIndex - 1)}
                  aria-pressed={isSelectedHop}
                  aria-label={`Hop ${nodeIndex}: ${hop.relationship_type.replace(/_/g, " ")}`}
                >
                  <span className="apc-edge-label">
                    {hop.relationship_type.replace(/_/g, " ")}
                  </span>
                  <Icon name="chevron-right" size={compact ? 10 : 12} />
                </button>
              )}

              <div
                className={`apc-node ${isSensitiveTarget ? "sensitive-target" : ""} ${isSelectedNode ? "selected" : ""}`}
                title={nodeId}
              >
                <ResourceNode
                  type={nodeTypeFromId(nodeId)}
                  name={nodeLabel(nodeId)}
                  id={nodeId}
                  sensitive={isSensitiveTarget}
                  size={compact ? "sm" : "md"}
                  showType={!compact}
                  showFlags={!compact}
                  showRisk={false}
                  onClick={onSelectNode ? () => onSelectNode(nodeId) : undefined}
                />
              </div>
            </Fragment>
          );
        })}
      </div>

      {!compact && hops.length > 0 && (
        <div className="apc-hops-detail">
          {hops.map((hop, hopIndex) => {
            const isOpen = selectedHopIndex === hopIndex;

            return (
              <div
                key={`${hop.source}-${hop.target}-${hopIndex}`}
                className="apc-hop"
              >
                <button
                  type="button"
                  className={`apc-hop-header ${isOpen ? "open" : ""}`}
                  onClick={() => onSelectHop?.(isOpen ? null : hopIndex)}
                  aria-expanded={isOpen}
                >
                  <span className="apc-hop-num">Hop {hopIndex + 1}</span>
                  <RelationshipBadge type={hop.relationship_type} size="sm" />
                  {hop.confidence && (
                    <ConfidenceBadge confidence={hop.confidence} />
                  )}
                  <span className="apc-hop-route mono">
                    {nodeLabel(hop.source)} → {nodeLabel(hop.target)}
                  </span>
                </button>

                {isOpen && (
                  <div className="apc-hop-detail" style={{ animation: "expand var(--dur-expand) var(--ease-out)" } as CSSProperties}>
                    <div className="apc-hop-field">
                      <span className="apc-hop-field-label">Why it works</span>
                      <p className="apc-hop-field-value">{hop.reason}</p>
                    </div>

                    {hop.evidence && (
                      <div className="apc-hop-field">
                        <span className="apc-hop-field-label">Evidence</span>
                        <p className="apc-hop-field-value mono">{hop.evidence}</p>
                      </div>
                    )}

                    {hop.configuration && (
                      <div className="apc-hop-field">
                        <span className="apc-hop-field-label">Configuration</span>
                        <p className="apc-hop-field-value mono">{hop.configuration}</p>
                      </div>
                    )}

                    {hop.impact && (
                      <div className="apc-hop-field">
                        <span className="apc-hop-field-label">Impact</span>
                        <p className="apc-hop-field-value">{hop.impact}</p>
                      </div>
                    )}

                    {hop.permissions && hop.permissions.length > 0 && (
                      <div className="apc-hop-field">
                        <span className="apc-hop-field-label">Permissions</span>
                        <div className="chip-row">
                          {hop.permissions.map((p, i) => (
                            <span key={i} className="chip mono">{p}</span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function RelationshipBadge({
  type,
  size = "sm",
}: {
  type: RelationshipType;
  size?: "sm" | "md";
}) {
  const meta: Record<RelationshipType, { label: string; icon: IconName }> = {
    exposed_to: { label: "EXPOSED_TO", icon: "globe" },
    can_access: { label: "CAN_ACCESS", icon: "eye" },
    can_read: { label: "CAN_READ", icon: "eye" },
    can_write: { label: "CAN_WRITE", icon: "remediate" },
    assumes: { label: "ASSUMES", icon: "identity" },
    trusts: { label: "TRUSTS", icon: "shield" },
    connected_to: { label: "CONNECTED_TO", icon: "network" },
    member_of: { label: "MEMBER_OF", icon: "inventory" },
    unknown: { label: "RELATED", icon: "chevron-right" },
  };

  const m = meta[type];
  return (
    <span className={`relationship-badge ${size}`}>
      <Icon name={m.icon} size={size === "sm" ? 9 : 11} />
      {m.label}
    </span>
  );
}

function ConfidenceBadge({
  confidence,
}: {
  confidence: "HIGH" | "MEDIUM" | "LOW";
}) {
  return (
    <span className={`confidence-badge ${confidence.toLowerCase()}`}>
      {confidence}
    </span>
  );
}

export function AttackPathSummary({
  path,
  rank,
  onSelect,
  selected = false,
  className = "",
}: {
  path: {
    path_id: string;
    nodes: string[];
    hop_count: number;
    sensitive_target: boolean;
    severity: string;
    risk_score: number;
    explanation: string;
    confidence?: "HIGH" | "MEDIUM" | "LOW";
  };
  rank: number;
  onSelect: () => void;
  selected?: boolean;
  className?: string;
}) {
  const routeTitle = path.nodes.map(nodeLabel).join(" → ");

  return (
    <button
      type="button"
      className={`attack-path-summary ${selected ? "selected" : ""} ${className}`}
      onClick={onSelect}
      aria-pressed={selected}
    >
      <div className="aps-header">
        <span className="aps-rank">#{rank}</span>
        <span className={`aps-severity sev-${path.severity.toLowerCase()}`}>
          {path.severity.toUpperCase()}
        </span>
        <span className="aps-hops">{path.hop_count} {path.hop_count === 1 ? "hop" : "hops"}</span>
      </div>

      <div className="aps-route" title={routeTitle}>
        {path.nodes.map((nodeId, index) => (
          <Fragment key={`${nodeId}-${index}`}>
            {index > 0 && <Icon name="chevron-right" size={11} className="aps-arrow" />}
            <span className="aps-node mono">{nodeLabel(nodeId)}</span>
          </Fragment>
        ))}
        {path.sensitive_target && <Icon name="lock" size={11} className="aps-sensitive" />}
      </div>

      <div className="aps-risk">
        <div className="aps-risk-bar">
          <div
            className={`aps-risk-fill sev-${path.severity.toLowerCase()}`}
            style={{ width: `${Math.min(100, path.risk_score)}%` } as CSSProperties}
          />
        </div>
        <span className="aps-risk-value">{Math.round(path.risk_score)}</span>
      </div>

      {path.confidence && (
        <ConfidenceBadge confidence={path.confidence} />
      )}
    </button>
  );
}