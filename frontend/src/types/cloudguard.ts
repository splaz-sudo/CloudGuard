export type AssetType =
  | "internet"
  | "ec2"
  | "iam_user"
  | "iam_role"
  | "s3_bucket"
  | "rds"
  | "lambda"
  | "secret"
  | "security_group"
  | "vpc";


export interface CloudAsset {
  id: string;
  name: string;
  asset_type: AssetType;
  account_id: string | null;
  region: string | null;
  sensitive: boolean;
  internet_exposed: boolean;
  metadata: Record<string, string>;
}


export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}


export interface Overview {
  mode: string;
  assets: number;
  relationships: number;
  sensitive_assets: number;
  internet_exposed_assets: number;
  attack_paths: number;
  findings: number;
  severity: SeverityCounts;
  highest_risk_score: number;
}


export interface Finding {
  id: string;
  title: string;
  description: string;
  severity: string;
  category: string;
  affected_assets: string[];
  evidence: string[];
  remediation: string | null;
  risk_score: number;
}


export type RelationshipType =
  | "exposed_to"
  | "can_access"
  | "can_read"
  | "can_write"
  | "assumes"
  | "trusts"
  | "connected_to"
  | "member_of";


export interface Relationship {
  source: string;
  target: string;
  relationship_type: RelationshipType;
  permissions: string[];
  evidence: string | null;
}


export interface AttackPath {
  source: string;
  target: string;
  nodes: string[];
  hop_count: number;
  sensitive_target: boolean;
  relationships: Relationship[];
}


export interface IdentityRisk {
  identity_id: string;
  identity_name: string;
  identity_type: string;
  risk_score: number;
  severity: string;

  permissions: string[];
  connected_assets: string[];
  exposed_workloads: string[];
  sensitive_resources: string[];

  attack_paths: string[][];
  risk_factors: string[];

  metadata: Record<
    string,
    string | number | boolean | null
  >;
}


export interface ExposedService {
  protocol: string;
  from_port: number | null;
  to_port: number | null;
  sources: string[];

  security_group_id: string;
  security_group_name: string;
}


export interface NetworkRisk {
  asset_id: string;
  asset_name: string;

  risk_score: number;
  severity: string;

  public_ip: string | null;

  security_groups: string[];
  exposed_services: ExposedService[];

  attached_identities: string[];
  sensitive_resources: string[];

  attack_paths: string[][];
  risk_factors: string[];

  metadata: Record<
    string,
    string | number | boolean | null
  >;
}


export type ComplianceStatus =
  | "NON_COMPLIANT"
  | "NOT_ASSESSED";


export interface FrameworkSummary {
  framework: string;
  total_controls: number;
  non_compliant: number;
  not_assessed: number;
}


export interface ComplianceControl {
  framework: string;

  control_id: string;
  title: string;
  description: string;

  status: ComplianceStatus;

  related_findings: string[];
  affected_assets: string[];
  evidence: string[];
  remediation: string[];
}


export interface ComplianceReport {
  frameworks: FrameworkSummary[];
  controls: ComplianceControl[];
  mapped_findings: number;
}


export interface ReportSummary {
  mode: string;

  total_assets: number;
  total_relationships: number;

  sensitive_assets: number;
  internet_exposed_assets: number;

  attack_paths: number;
  findings: number;

  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
  info_findings: number;

  highest_risk_score: number;
}


export interface ReportAttackPath {
  nodes: string[];
  hop_count: number;
  sensitive_target: boolean;
}


export interface ReportFinding {
  id: string;
  title: string;
  description: string;

  severity: string;
  category: string;

  risk_score: number;

  affected_assets: string[];
  evidence: string[];

  remediation: string | null;
}


export interface ReportIdentityRisk {
  identity_id: string;
  identity_name: string;
  identity_type: string;

  risk_score: number;
  severity: string;

  permissions: string[];
  exposed_workloads: string[];
  sensitive_resources: string[];

  attack_paths: string[][];
  risk_factors: string[];
}


export interface ReportNetworkRisk {
  asset_id: string;
  asset_name: string;

  risk_score: number;
  severity: string;

  public_ip: string | null;

  security_groups: string[];
  exposed_services: ExposedService[];

  attached_identities: string[];
  sensitive_resources: string[];

  attack_paths: string[][];
  risk_factors: string[];
}


export interface ReportComplianceSummary {
  frameworks: number;
  mapped_controls: number;
  non_compliant_controls: number;
  not_assessed_controls: number;
  mapped_findings: number;
}


export interface SecurityReport {
  report_name: string;
  report_version: string;
  assessment_mode: string;

  scope_note: string;
  limitations: string[];

  summary: ReportSummary;

  assets: CloudAsset[];

  attack_paths: ReportAttackPath[];

  findings: ReportFinding[];

  identity_risks: ReportIdentityRisk[];

  network_risks: ReportNetworkRisk[];

  compliance: ReportComplianceSummary;

  compliance_controls: ComplianceControl[];
}