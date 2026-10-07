import { type IconName } from "../Icon";
import Icon from "../Icon";
import { StatusBadge, type StatusVariant } from "./StatusBadge";

export type RelationshipType =
  | "exposed_to"
  | "can_access"
  | "can_read"
  | "can_write"
  | "assumes"
  | "trusts"
  | "connected_to"
  | "member_of"
  | "unknown";

export interface RelationshipEdgeProps {
  type: RelationshipType;
  source?: string;
  target?: string;
  permissions?: string[];
  evidence?: string;
  showLabel?: boolean;
  showDirection?: boolean;
  inline?: boolean;
  className?: string;
}

const RELATIONSHIP_META: Record<RelationshipType, { label: string; icon: IconName; color: StatusVariant; description: string }> = {
  exposed_to: { label: "Exposed To", icon: "globe", color: "critical", description: "Direct internet exposure" },
  can_access: { label: "Can Access", icon: "eye", color: "high", description: "Generic access permission" },
  can_read: { label: "Can Read", icon: "eye", color: "medium", description: "Read permission on resource" },
  can_write: { label: "Can Write", icon: "remediate", color: "high", description: "Write permission on resource" },
  assumes: { label: "Assumes", icon: "identity", color: "warning", description: "Role assumption / instance profile" },
  trusts: { label: "Trusts", icon: "shield", color: "medium", description: "Trust relationship" },
  connected_to: { label: "Connected To", icon: "network", color: "neutral", description: "Network connectivity" },
  member_of: { label: "Member Of", icon: "inventory", color: "info", description: "Group / membership" },
  unknown: { label: "Related", icon: "chevron-right", color: "neutral", description: "Unknown relationship" },
};

export function RelationshipEdge({
  type,
  source,
  target,
  permissions,
  evidence,
  showLabel = true,
  showDirection = true,
  inline = false,
  className = "",
}: RelationshipEdgeProps) {
  const meta = RELATIONSHIP_META[type];

  if (inline) {
    return (
      <span className={`relationship-edge-inline ${className}`} title={evidence}>
        {source && <span className="rel-source mono">{source}</span>}
        {showDirection && <Icon name="chevron-right" size={12} className="rel-arrow" />}
        {showLabel && (
          <StatusBadge variant={meta.color} size="sm" icon={meta.icon} showDot={false}>
            {meta.label}
          </StatusBadge>
        )}
        {target && <span className="rel-target mono">{target}</span>}
        {permissions && permissions.length > 0 && (
          <span className="rel-permissions">
            {permissions.map((p, i) => (
              <span key={i} className="rel-perm mono">{p}</span>
            ))}
          </span>
        )}
      </span>
    );
  }

  return (
    <div className={`relationship-edge ${className}`}>
      {showLabel && (
        <div className="rel-header">
          <StatusBadge variant={meta.color} size="sm" icon={meta.icon} showDot={false}>
            {meta.label}
          </StatusBadge>
          {evidence && <span className="rel-evidence mono" title={evidence}>{evidence}</span>}
        </div>
      )}

      <div className="rel-connection">
        {source && (
          <span className="rel-node source mono" title={source}>
            {source}
          </span>
        )}

        {showDirection && (
          <Icon name="chevron-right" size={14} className="rel-arrow" />
        )}

        {target && (
          <span className="rel-node target mono" title={target}>
            {target}
          </span>
        )}
      </div>

      {permissions && permissions.length > 0 && (
        <div className="rel-permissions">
          {permissions.map((p, i) => (
            <span key={i} className="rel-perm mono">{p}</span>
          ))}
        </div>
      )}

      {evidence && (
        <details className="rel-evidence-detail">
          <summary>Evidence</summary>
          <p className="mono">{evidence}</p>
        </details>
      )}
    </div>
  );
}

export function RelationshipBadge({
  type,
  size = "md",
  showDot = true,
  className = "",
}: {
  type: RelationshipType;
  size?: "sm" | "md" | "lg";
  showDot?: boolean;
  className?: string;
}) {
  const meta = RELATIONSHIP_META[type];

  return (
    <StatusBadge variant={meta.color} size={size} showDot={showDot} icon={meta.icon} className={className}>
      {meta.label}
    </StatusBadge>
  );
}

export function RelationshipChain({
  relationships,
  className = "",
}: {
  relationships: Array<{
    type: RelationshipType;
    source: string;
    target: string;
    permissions?: string[];
  }>;
  className?: string;
}) {
  return (
    <div className={`relationship-chain ${className}`}>
      {relationships.map((rel, index) => (
        <span key={index} className="rel-chain-link">
          {index > 0 && <Icon name="chevron-right" size={11} className="rel-chain-arrow" />}
          <RelationshipEdge
            type={rel.type}
            source={index === 0 ? rel.source : undefined}
            target={rel.target}
            permissions={rel.permissions}
            inline
            showLabel={true}
            showDirection={false}
          />
        </span>
      ))}
    </div>
  );
}