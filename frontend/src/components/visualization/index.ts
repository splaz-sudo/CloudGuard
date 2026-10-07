// CloudGuard Security Console 2.0 — Shared Visualization Primitives
// Design System Components

import "./visualization.css";

export { StatusBadge, SeverityBadge, ChangeStatusBadge, SimulationBadge, type StatusVariant, type StatusSize } from "./StatusBadge";
export { RiskGauge, InlineRiskGauge, type RiskGaugeProps } from "./RiskGauge";
export { RiskBar, RiskBarWithDelta, SegmentedRiskBar, type RiskBarProps } from "./RiskBar";
export { SeverityDistribution, SegmentedSeverityBar, SeverityLegend, type SeverityCounts, type SeverityDistributionProps } from "./SeverityDistribution";
export { MetricStrip, StatCard, DeltaIndicator, MiniTrend, type MetricStripProps, type StatCardProps, type DeltaIndicatorProps } from "./MetricStrip";
export { ResourceNode, ResourceChip, ResourceTypeBadge, type ResourceType, type ResourceNodeProps } from "./ResourceNode";
export { normalizeResourceType } from "./resourceTypes";
export { RelationshipEdge, RelationshipBadge, RelationshipChain, type RelationshipType, type RelationshipEdgeProps } from "./RelationshipEdge";
export { SecurityPanel, PanelSection, PanelGrid, PanelRow, PanelKeyValue, type SecurityPanelProps, type PanelSectionProps } from "./SecurityPanel";
export { InspectorPanel, ExpandableSection, CollapsibleRows, ChipRow, type InspectorPanelProps, type ExpandableSectionProps } from "./InspectorPanel";
export { AttackPathChain, AttackPathSummary, type AttackPathHop, type AttackPathChainProps } from "./AttackPathChain";
export { SimulationDiff, SimulationDiffCompact, type SimulationState, type SimulationImpact, type SimulationDiffProps } from "./SimulationDiff";
export { CoverageMatrix, CoverageLimitations, CollectorStatusBadge, type CollectorResult, type CollectorStatus, type CoverageMatrixProps } from "./CoverageMatrix";
export { Sparkline, MultiSparkline, SparklineWithAxis, type SparklineProps, type MultiSparklineProps, type SparklineWithAxisProps } from "./Sparkline";