import { type CSSProperties } from "react";
import { type IconName } from "../Icon";
import Icon from "../Icon";
import { StatusBadge, type StatusVariant } from "./StatusBadge";
import { normalizeResourceType, type ResourceType } from "./resourceTypes";

export type { ResourceType };

export type ResourceNodeSize = "sm" | "md" | "lg";

export interface ResourceNodeProps {
  type: ResourceType;
  name: string;
  id?: string;
  sensitive?: boolean;
  internetExposed?: boolean;
  riskScore?: number;
  size?: ResourceNodeSize;
  showType?: boolean;
  showRisk?: boolean;
  showFlags?: boolean;
  className?: string;
  onClick?: () => void;
  "aria-label"?: string;
}

const TYPE_META: Record<ResourceType, { label: string; icon: IconName; color: StatusVariant }> = {
  internet: { label: "Internet", icon: "globe", color: "low" },
  ec2: { label: "EC2", icon: "inventory", color: "info" },
  iam_user: { label: "IAM User", icon: "identity", color: "warning" },
  iam_role: { label: "IAM Role", icon: "identity", color: "warning" },
  s3_bucket: { label: "S3 Bucket", icon: "lock", color: "success" },
  rds: { label: "RDS", icon: "lock", color: "success" },
  lambda: { label: "Lambda", icon: "inventory", color: "info" },
  secret: { label: "Secret", icon: "lock", color: "critical" },
  security_group: { label: "Security Group", icon: "network", color: "neutral" },
  vpc: { label: "VPC", icon: "network", color: "neutral" },
  unknown: { label: "Resource", icon: "inventory", color: "neutral" },
};

const SIZE_CLASSES: Record<ResourceNodeSize, string> = {
  sm: "res-node-sm",
  md: "",
  lg: "res-node-lg",
};

export function ResourceNode({
  type,
  name,
  id,
  sensitive = false,
  internetExposed = false,
  riskScore,
  size = "md",
  showType = true,
  showRisk = false,
  showFlags = true,
  className = "",
  onClick,
  "aria-label": ariaLabel,
}: ResourceNodeProps) {
  type = normalizeResourceType(type);
  const meta = TYPE_META[type];
  const riskBand = riskScore !== undefined
    ? riskScore >= 75 ? "critical"
    : riskScore >= 50 ? "high"
    : riskScore >= 25 ? "medium"
    : "low"
    : null;

  const handleClick = onClick ? (e: React.MouseEvent) => { e.stopPropagation(); onClick(); } : undefined;

  return (
    <button
      type="button"
      className={`resource-node ${SIZE_CLASSES[size]} ${sensitive ? "sensitive" : ""} ${internetExposed ? "exposed" : ""} ${className}`}
      onClick={handleClick}
      aria-label={ariaLabel ?? `${meta.label}: ${name}${sensitive ? ", sensitive" : ""}${internetExposed ? ", internet exposed" : ""}`}
      disabled={!onClick}
    >
      <span className="resource-node-icon" style={{ color: `var(--res-${type})` } as CSSProperties}>
        <Icon name={meta.icon} size={size === "sm" ? 11 : size === "lg" ? 16 : 13} />
      </span>

      <div className="resource-node-content">
        {showType && (
          <span className="resource-node-type">
            <StatusBadge variant={meta.color} size="sm" showDot={false}>
              {meta.label}
            </StatusBadge>
          </span>
        )}

        <span className="resource-node-name" title={name}>{name}</span>

        {id && (
          <span className="resource-node-id mono" title={id}>
            {id.length > 28 ? `${id.slice(0, 28)}…` : id}
          </span>
        )}
      </div>

      {showFlags && (sensitive || internetExposed) && (
        <div className="resource-node-flags">
          {sensitive && (
            <StatusBadge variant="critical" size="sm" icon="lock" showDot={false}>
              Sensitive
            </StatusBadge>
          )}
          {internetExposed && (
            <StatusBadge variant="warning" size="sm" icon="globe" showDot={false}>
              Exposed
            </StatusBadge>
          )}
        </div>
      )}

      {showRisk && riskScore !== undefined && riskBand && (
        <StatusBadge variant={riskBand} size="sm" showDot={false}>
          {riskScore}
        </StatusBadge>
      )}
    </button>
  );
}

export function ResourceChip({
  type,
  name,
  sensitive = false,
  internetExposed = false,
  className = "",
}: {
  type: ResourceType;
  name: string;
  sensitive?: boolean;
  internetExposed?: boolean;
  className?: string;
}) {
  type = normalizeResourceType(type);
  const meta = TYPE_META[type];

  return (
    <span className={`resource-chip ${sensitive ? "sensitive" : ""} ${internetExposed ? "exposed" : ""} ${className}`}>
      <span style={{ display: "inline-flex", color: `var(--res-${type})` }}>
        <Icon name={meta.icon} size={11} />
      </span>
      <span className="resource-chip-name">{name}</span>
      {sensitive && <Icon name="lock" size={9} className="resource-chip-flag critical" />}
      {internetExposed && <Icon name="globe" size={9} className="resource-chip-flag warning" />}
    </span>
  );
}

export function ResourceTypeBadge({
  type,
  size = "md",
  showDot = true,
  className = "",
}: {
  type: ResourceType;
  size?: "sm" | "md" | "lg";
  showDot?: boolean;
  className?: string;
}) {
  const meta = TYPE_META[normalizeResourceType(type)];

  return (
    <StatusBadge variant={meta.color} size={size} showDot={showDot} className={className}>
      {meta.label}
    </StatusBadge>
  );
}