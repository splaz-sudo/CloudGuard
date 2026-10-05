import {
  Fragment,
  useCallback,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

import {
  Background,
  BackgroundVariant,
  Controls,
  Handle,
  MarkerType,
  MiniMap,
  Panel,
  Position,
  ReactFlow,
  ReactFlowProvider,
  useNodesState,
  useReactFlow,
  type Edge,
  type Node,
  type NodeProps,
  type NodeTypes,
  type OnNodesChange,
  type OnSelectionChangeParams,
} from "@xyflow/react";

import "@xyflow/react/dist/style.css";

import "../styles/attackpaths.css";

import {
  CloudGuardAPIError,
  getScanAssets,
  getScanAttackPaths,
  getScanRelationships,
} from "../services/api";

import {
  useScanContext,
} from "../context/ScanContext";

import Icon, { type IconName } from "../components/Icon";

import {
  EmptyState,
  ErrorState,
  LoadingState,
} from "../components/StateBlock";

import type {
  AttackPath,
  AttackPathHop,
  CloudAsset,
  Relationship,
} from "../types/cloudguard";


/* ============================================
   Node type system

   Derived ONLY from fields the API provides:
   - asset_type === "internet"          → Internet
   - asset.sensitive === true           → Sensitive resource
   - asset_type iam_role / iam_user     → Identity
   - other known asset types            → Workload
   - anything else (defensive fallback) → Resource (neutral)
   ============================================ */

type NodeCategory =
  | "internet"
  | "workload"
  | "identity"
  | "sensitive"
  | "resource";

const KNOWN_WORKLOAD_TYPES = new Set<string>([
  "ec2",
  "lambda",
  "s3_bucket",
  "rds",
  "security_group",
  "vpc",
]);

function getNodeCategory(
  asset: CloudAsset,
): NodeCategory {
  if (asset.asset_type === "internet") {
    return "internet";
  }

  if (asset.sensitive) {
    return "sensitive";
  }

  if (
    asset.asset_type === "iam_role"
    || asset.asset_type === "iam_user"
  ) {
    return "identity";
  }

  if (KNOWN_WORKLOAD_TYPES.has(asset.asset_type)) {
    return "workload";
  }

  return "resource";
}

const CATEGORY_META: Record<
  NodeCategory,
  { label: string; icon: IconName }
> = {
  internet: { label: "Internet", icon: "globe" },
  workload: { label: "Workload", icon: "inventory" },
  identity: { label: "Identity", icon: "identity" },
  sensitive: {
    label: "Sensitive resource",
    icon: "lock",
  },
  resource: { label: "Resource", icon: "inventory" },
};

const LEGEND_CATEGORIES: NodeCategory[] = [
  "internet",
  "workload",
  "identity",
  "sensitive",
];

const MINIMAP_NODE_COLORS: Record<NodeCategory, string> = {
  internet: "var(--sev-low)",
  workload: "var(--accent)",
  identity: "var(--warning)",
  sensitive: "var(--sev-critical)",
  resource: "var(--neutral)",
};


/* ---------- Severity / risk helpers ---------- */

type SevClass =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "neutral";

function severityClass(
  value: string | undefined,
): SevClass {
  const normalized = (value ?? "")
    .trim()
    .toLowerCase();

  if (
    normalized === "critical"
    || normalized === "high"
    || normalized === "medium"
    || normalized === "low"
  ) {
    return normalized;
  }

  return "neutral";
}

function riskFillClass(sev: SevClass): string {
  return sev === "neutral" ? "" : `sev-${sev}`;
}

function riskPercent(score: number): string {
  const clamped = Math.max(0, Math.min(100, score));
  return `${clamped}%`;
}

function confidenceBadgeClass(
  value: string | undefined,
): string {
  switch ((value ?? "").toUpperCase()) {
    case "HIGH":
      return "badge-success";
    case "MEDIUM":
      return "badge-warning";
    default:
      return "badge-neutral";
  }
}

function formatLabel(value: string): string {
  return value
    .replaceAll("_", " ")
    .toUpperCase();
}

function relationshipKey(
  source: string,
  target: string,
  type: string,
): string {
  return `${source}->${target}->${type}`;
}

function prefersReducedMotion(): boolean {
  return (
    typeof window !== "undefined"
    && window.matchMedia(
      "(prefers-reduced-motion: reduce)",
    ).matches
  );
}


/* ============================================
   Lane layout (presentation only — positions
   never change graph truth, just place nodes
   in kill-chain columns: Internet → Workload
   → Identity → Sensitive)
   ============================================ */

const LANE_X = [0, 360, 720, 1080];
const NODE_H = 96;
const NODE_GAP = 30;

function laneIndex(category: NodeCategory): number {
  switch (category) {
    case "internet":
      return 0;
    case "identity":
      return 2;
    case "sensitive":
      return 3;
    case "workload":
    case "resource":
      return 1;
  }
}

function layoutNodes(
  assets: CloudAsset[],
  categories: Map<string, NodeCategory>,
  onPathIds: Set<string>,
): Map<string, { x: number; y: number }> {
  const lanes: CloudAsset[][] = [[], [], [], []];

  for (const asset of assets) {
    const category =
      categories.get(asset.id) ?? "resource";
    lanes[laneIndex(category)].push(asset);
  }

  for (const lane of lanes) {
    lane.sort((left, right) => {
      const leftOnPath = onPathIds.has(left.id) ? 0 : 1;
      const rightOnPath =
        onPathIds.has(right.id) ? 0 : 1;

      if (leftOnPath !== rightOnPath) {
        return leftOnPath - rightOnPath;
      }

      return left.name.localeCompare(right.name);
    });
  }

  const maxCount = Math.max(
    1,
    ...lanes.map((lane) => lane.length),
  );
  const maxHeight =
    maxCount * (NODE_H + NODE_GAP);

  const positions = new Map<
    string,
    { x: number; y: number }
  >();

  lanes.forEach((lane, laneIdx) => {
    const laneHeight =
      lane.length * (NODE_H + NODE_GAP);
    const offsetY =
      (maxHeight - laneHeight) / 2;

    lane.forEach((asset, index) => {
      positions.set(asset.id, {
        x: LANE_X[laneIdx],
        y: offsetY + index * (NODE_H + NODE_GAP),
      });
    });
  });

  return positions;
}


/* ============================================
   Custom node card
   ============================================ */

type AssetNodeData = {
  asset: CloudAsset;
  category: NodeCategory;
  /** Attack paths (API) that include this node */
  pathCount: number;
  /** Highest risk_score among those paths */
  maxRisk: number | null;
  maxRiskSeverity: SevClass;
  inSelectedPath: boolean;
  dimmed: boolean;
};

type AssetFlowNode = Node<AssetNodeData, "cgAsset">;

function AssetNodeCard({
  data,
}: NodeProps<AssetFlowNode>) {
  const { asset, category } = data;
  const meta = CATEGORY_META[category];

  return (
    <div
      className={
        `ap-node ap-node--${category}`
        + (data.inSelectedPath ? " is-path" : "")
        + (data.dimmed ? " is-dim" : "")
      }
    >
      <Handle
        type="target"
        position={Position.Left}
        isConnectable={false}
      />

      <div className="ap-node-head">
        <span className="ap-node-icon">
          <Icon name={meta.icon} size={12} />
        </span>

        <span className="ap-node-type">
          {meta.label}
        </span>

        {data.maxRisk !== null && (
          <span
            className={
              `badge badge-sm no-dot `
              + `badge-${data.maxRiskSeverity}`
            }
            title={
              "Highest attack-path risk through "
              + `this asset: ${Math.round(data.maxRisk)}`
            }
          >
            {Math.round(data.maxRisk)}
          </span>
        )}
      </div>

      <p
        className="ap-node-name truncate"
        title={asset.name}
      >
        {asset.name}
      </p>

      <p
        className="ap-node-id mono truncate"
        title={asset.id}
      >
        {asset.id}
      </p>

      {(asset.internet_exposed || asset.sensitive) && (
        <div className="ap-node-flags">
          {asset.internet_exposed && (
            <span className="ap-flag ap-flag--exposed">
              <Icon name="globe" size={9} />
              Exposed
            </span>
          )}

          {asset.sensitive && (
            <span className="ap-flag ap-flag--sensitive">
              <Icon name="lock" size={9} />
              Sensitive
            </span>
          )}
        </div>
      )}

      <Handle
        type="source"
        position={Position.Right}
        isConnectable={false}
      />
    </div>
  );
}

const nodeTypes: NodeTypes = {
  cgAsset: AssetNodeCard,
};


/* ============================================
   Main page
   ============================================ */

function AttackPaths() {
  const {
    selectedScan,
    loading: scansLoading,
  } = useScanContext();

  const scanId =
    selectedScan?.scan_id ?? null;

  const [assets, setAssets] =
    useState<CloudAsset[]>([]);

  const [relationships, setRelationships] =
    useState<Relationship[]>([]);

  const [attackPaths, setAttackPaths] =
    useState<AttackPath[]>([]);

  const [selectedAsset, setSelectedAsset] =
    useState<CloudAsset | null>(null);

  const [
    selectedRelationship,
    setSelectedRelationship,
  ] = useState<Relationship | null>(null);

  const [selectedPath, setSelectedPath] =
    useState<AttackPath | null>(null);

  const [selectedHopIndex, setSelectedHopIndex] =
    useState<number | null>(null);

  const [loading, setLoading] =
    useState(scanId !== null);

  const [error, setError] =
    useState<CloudGuardAPIError | null>(null);

  const [reloadKey, setReloadKey] =
    useState(0);


  /**
   * Reset all scan-scoped state when the
   * selected scan changes (derived-state
   * pattern: adjusted during render, not in
   * an effect).
   */
  const [prevScanId, setPrevScanId] =
    useState(scanId);

  if (scanId !== prevScanId) {
    setPrevScanId(scanId);
    setAssets([]);
    setRelationships([]);
    setAttackPaths([]);
    setSelectedAsset(null);
    setSelectedRelationship(null);
    setSelectedPath(null);
    setSelectedHopIndex(null);
    setError(null);
    setLoading(scanId !== null);
  }


  useEffect(() => {
    if (!scanId) {
      return;
    }

    const currentScanId: string = scanId;
    let cancelled = false;

    async function loadGraph() {
      setLoading(true);
      setError(null);

      try {
        const [
          assetData,
          relationshipData,
          pathData,
        ] = await Promise.all([
          getScanAssets(currentScanId),
          getScanRelationships(currentScanId),
          getScanAttackPaths(currentScanId),
        ]);

        if (cancelled) {
          return;
        }

        setAssets(assetData);
        setRelationships(relationshipData);
        setAttackPaths(pathData);
      } catch (requestError) {
        if (cancelled) {
          return;
        }

        setError(
          requestError instanceof CloudGuardAPIError
            ? requestError
            : new CloudGuardAPIError(
                requestError instanceof Error
                  ? requestError.message
                  : "Unable to load security graph.",
              ),
        );
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }

    loadGraph();

    return () => {
      cancelled = true;
    };
  }, [scanId, reloadKey]);

  const retry = useCallback(
    () => setReloadKey((key) => key + 1),
    [],
  );


  /* ---------- Derived graph data ---------- */

  const assetById = useMemo(
    () =>
      new Map(
        assets.map((asset) => [asset.id, asset]),
      ),
    [assets],
  );

  const categories = useMemo(
    () =>
      new Map<string, NodeCategory>(
        assets.map((asset) => [
          asset.id,
          getNodeCategory(asset),
        ]),
      ),
    [assets],
  );

  const attackPathNodeIds = useMemo(
    () =>
      new Set(
        attackPaths.flatMap((path) => path.nodes),
      ),
    [attackPaths],
  );

  /**
   * Per-asset risk, derived ONLY from attack
   * paths the API returned: how many paths pass
   * through the node and the highest risk score
   * among them. Nothing is fabricated.
   */
  const assetRisk = useMemo(() => {
    const map = new Map<
      string,
      {
        score: number;
        severity: SevClass;
        count: number;
      }
    >();

    for (const path of attackPaths) {
      const pathSeverity =
        severityClass(path.severity);

      for (const nodeId of path.nodes) {
        const current = map.get(nodeId);

        if (
          !current
          || path.risk_score > current.score
        ) {
          map.set(nodeId, {
            score: path.risk_score,
            severity: pathSeverity,
            count: (current?.count ?? 0) + 1,
          });
        } else {
          map.set(nodeId, {
            ...current,
            count: current.count + 1,
          });
        }
      }
    }

    return map;
  }, [attackPaths]);

  /** Paths ranked by API risk score (display order). */
  const rankedPaths = useMemo(
    () =>
      [...attackPaths].sort(
        (left, right) =>
          right.risk_score - left.risk_score,
      ),
    [attackPaths],
  );

  const selectedPathNodeIds = useMemo(
    () => new Set(selectedPath?.nodes ?? []),
    [selectedPath],
  );

  const selectedPathEdgeKeys = useMemo(
    () =>
      new Set(
        (selectedPath?.relationships ?? []).map(
          (relationship) =>
            relationshipKey(
              relationship.source,
              relationship.target,
              relationship.relationship_type,
            ),
        ),
      ),
    [selectedPath],
  );


  /* ---------- Flow nodes / edges ---------- */

  const [flowNodes, setFlowNodes, onNodesChange] =
    useNodesState<AssetFlowNode>([]);

  useEffect(() => {
    const positions = layoutNodes(
      assets,
      categories,
      attackPathNodeIds,
    );

    setFlowNodes((current) => {
      const currentById = new Map(
        current.map((node) => [node.id, node]),
      );

      return assets.map(
        (asset): AssetFlowNode => {
          const existing =
            currentById.get(asset.id);
          const category =
            categories.get(asset.id) ?? "resource";
          const risk = assetRisk.get(asset.id);
          const inSelectedPath =
            selectedPathNodeIds.has(asset.id);

          return {
            ...existing,
            id: asset.id,
            type: "cgAsset",
            position:
              existing?.position
              ?? positions.get(asset.id)
              ?? { x: 0, y: 0 },
            data: {
              asset,
              category,
              pathCount: risk?.count ?? 0,
              maxRisk: risk ? risk.score : null,
              maxRiskSeverity:
                risk?.severity ?? "neutral",
              inSelectedPath,
              dimmed:
                selectedPath !== null
                && !inSelectedPath,
            },
            selected:
              selectedAsset?.id === asset.id,
          };
        },
      );
    });
  }, [
    assets,
    categories,
    assetRisk,
    attackPathNodeIds,
    selectedPathNodeIds,
    selectedAsset,
    selectedPath,
    setFlowNodes,
  ]);


  const edges = useMemo<Edge[]>(
    () =>
      relationships.map(
        (relationship, index) => {
          const key = relationshipKey(
            relationship.source,
            relationship.target,
            relationship.relationship_type,
          );

          const onAnyPath = attackPaths.some(
            (path) =>
              path.relationships.some(
                (pathRelationship) =>
                  relationshipKey(
                    pathRelationship.source,
                    pathRelationship.target,
                    pathRelationship
                      .relationship_type,
                  ) === key,
              ),
          );

          const inSelectedPath =
            selectedPathEdgeKeys.has(key);

          const isSelected =
            selectedRelationship
              ?.relationship_id
            === relationship.relationship_id;

          const dimmed =
            selectedPath !== null
            && !inSelectedPath;

          let stroke = "var(--border-strong)";
          let strokeWidth = 1.4;

          if (onAnyPath) {
            stroke = "var(--text-muted)";
            strokeWidth = 1.6;
          }

          if (inSelectedPath) {
            stroke = "var(--accent)";
            strokeWidth = 2.4;
          }

          if (isSelected) {
            stroke = "var(--accent-strong)";
            strokeWidth = 2.6;
          }

          if (dimmed) {
            stroke = "var(--border-subtle)";
            strokeWidth = 1.2;
          }

          return {
            id: `${key}#${index}`,
            source: relationship.source,
            target: relationship.target,
            label: formatLabel(
              relationship.relationship_type,
            ),
            className: [
              "ap-edge",
              inSelectedPath
                ? "ap-edge--active"
                : "",
              dimmed ? "ap-edge--dim" : "",
            ]
              .filter(Boolean)
              .join(" "),
            interactionWidth: 18,
            markerEnd: {
              type: MarkerType.ArrowClosed,
              width: 15,
              height: 15,
              color: stroke,
            },
            style: { stroke, strokeWidth },
            data: { relationship },
            selected: isSelected,
          };
        },
      ),
    [
      relationships,
      attackPaths,
      selectedPathEdgeKeys,
      selectedRelationship,
      selectedPath,
    ],
  );


  /* ---------- Selection handlers ---------- */

  /**
   * Single entry point for node/edge selection —
   * handles both mouse clicks and keyboard
   * (Tab + Enter) selection via React Flow's
   * built-in a11y. Pane clicks clear the
   * node/edge selection but keep the active
   * attack path.
   */
  const handleSelectionChange = useCallback(
    ({
      nodes: selNodes,
      edges: selEdges,
    }: OnSelectionChangeParams<
      AssetFlowNode,
      Edge
    >) => {
      const node =
        selNodes[selNodes.length - 1];

      if (node) {
        const asset = node.data.asset;
        setSelectedAsset(asset);
        setSelectedRelationship(null);
        setSelectedPath((previous) =>
          previous
          && previous.nodes.includes(asset.id)
            ? previous
            : null,
        );
        setSelectedHopIndex(null);
        return;
      }

      const edge =
        selEdges[selEdges.length - 1];

      if (edge) {
        const relationship =
          edge.data?.relationship as
            | Relationship
            | undefined;

        if (relationship) {
          setSelectedRelationship(relationship);
          setSelectedAsset(null);
          setSelectedPath((previous) =>
            previous
            && previous.relationships.some(
              (item) =>
                item.relationship_id
                === relationship.relationship_id,
            )
              ? previous
              : null,
          );
          setSelectedHopIndex(null);
        }
        return;
      }

      setSelectedAsset(null);
      setSelectedRelationship(null);
    },
    [],
  );

  const handlePathSelect = useCallback(
    (path: AttackPath) => {
      setSelectedPath((previous) =>
        previous?.path_id === path.path_id
          ? null
          : path,
      );
      setSelectedAsset(null);
      setSelectedRelationship(null);
      setSelectedHopIndex(null);
    },
    [],
  );

  const handleHopSelect = useCallback(
    (index: number | null) => {
      setSelectedHopIndex(index);
    },
    [],
  );


  /* ---------- State branches ---------- */

  const topbar = (
    <header className="topbar">
      <div>
        <p className="eyebrow">
          SECURITY GRAPH
        </p>

        <h2>Attack Path Explorer</h2>

        <p className="page-subtitle">
          Investigate how network exposure,
          identities, permissions, and sensitive
          resources combine into exploitable
          attack paths.
        </p>
      </div>

      {!loading && !error && scanId && (
        <div
          className="ap-stats"
          aria-label="Graph statistics"
        >
          <span className="ap-stat">
            <span className="ap-stat-value">
              {assets.length}
            </span>
            <span className="ap-stat-label">
              Assets
            </span>
          </span>

          <span className="ap-stat">
            <span className="ap-stat-value">
              {relationships.length}
            </span>
            <span className="ap-stat-label">
              Relationships
            </span>
          </span>

          <span className="ap-stat">
            <span className="ap-stat-value">
              {attackPaths.length}
            </span>
            <span className="ap-stat-label">
              Attack paths
            </span>
          </span>
        </div>
      )}
    </header>
  );


  if (scansLoading || loading) {
    return (
      <div className="page">
        {topbar}

        <div className="panel">
          <LoadingState label="Building security graph…" />
        </div>
      </div>
    );
  }


  if (error) {
    return (
      <div className="page">
        {topbar}

        <div className="panel">
          <ErrorState
            error={error}
            resourceLabel="attack paths"
            onRetry={retry}
          />
        </div>
      </div>
    );
  }


  if (!scanId) {
    return (
      <div className="page">
        {topbar}

        <div className="panel">
          <EmptyState
            icon="scans"
            title="No scan selected"
            body="Choose a scan from the sidebar to explore its security graph and attack paths."
          />
        </div>
      </div>
    );
  }


  if (assets.length === 0) {
    return (
      <div className="page">
        {topbar}

        <div className="panel">
          <EmptyState
            icon="paths"
            title="No attack paths to explore"
            body="This scan returned no assets, so there is no security graph to render. Run a scan against an environment with resources to see attack paths here."
          />
        </div>
      </div>
    );
  }


  const selectedRisk = selectedAsset
    ? assetRisk.get(selectedAsset.id) ?? null
    : null;

  const selectedPathRank = selectedPath
    ? rankedPaths.findIndex(
        (path) =>
          path.path_id === selectedPath.path_id,
      ) + 1
    : 0;


  return (
    <div className="page">
      {topbar}

      <ReactFlowProvider>
        <section
          className="ap-layout"
          aria-label="Attack path explorer"
        >
          <PathPanel
            paths={rankedPaths}
            assetById={assetById}
            selectedPath={selectedPath}
            onSelect={handlePathSelect}
          />

          <GraphPanel
            flowNodes={flowNodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onSelectionChange={
              handleSelectionChange
            }
          />

          <aside
            className="panel ap-inspector"
            aria-label="Inspector"
          >
            <div className="panel-header">
              <span className="panel-title">
                Inspector
              </span>
            </div>

            <div className="ap-inspector-body">
              {selectedAsset ? (
                <AssetInspector
                  asset={selectedAsset}
                  category={
                    categories.get(
                      selectedAsset.id,
                    ) ?? "resource"
                  }
                  risk={selectedRisk}
                />
              ) : selectedRelationship ? (
                <RelationshipInspector
                  relationship={
                    selectedRelationship
                  }
                  assetById={assetById}
                />
              ) : selectedPath ? (
                <PathInspector
                  path={selectedPath}
                  rank={
                    selectedPathRank > 0
                      ? selectedPathRank
                      : 1
                  }
                  assetById={assetById}
                  categories={categories}
                  relationships={relationships}
                  selectedHopIndex={
                    selectedHopIndex
                  }
                  onSelectHop={handleHopSelect}
                />
              ) : (
                <InspectorSummary
                  assetCount={assets.length}
                  relationshipCount={
                    relationships.length
                  }
                  attackPaths={attackPaths}
                />
              )}
            </div>
          </aside>
        </section>
      </ReactFlowProvider>
    </div>
  );
}


/* ============================================
   Path list panel
   ============================================ */

function PathPanel({
  paths,
  assetById,
  selectedPath,
  onSelect,
}: {
  paths: AttackPath[];
  assetById: Map<string, CloudAsset>;
  selectedPath: AttackPath | null;
  onSelect: (path: AttackPath) => void;
}) {
  const { fitView } = useReactFlow();

  const nameOf = (id: string) =>
    assetById.get(id)?.name ?? id;

  const handleSelect = (path: AttackPath) => {
    const isSelected =
      selectedPath?.path_id === path.path_id;

    onSelect(path);

    if (!isSelected) {
      fitView({
        nodes: path.nodes.map((id) => ({ id })),
        padding: 0.35,
        duration: prefersReducedMotion()
          ? 0
          : 220,
      });
    }
  };

  return (
    <aside
      className="panel ap-paths"
      aria-label="Attack paths"
    >
      <div className="panel-header">
        <span className="panel-title">
          Attack paths
        </span>

        <span className="badge badge-neutral badge-sm no-dot ap-panel-count">
          {paths.length}
        </span>
      </div>

      <div className="ap-paths-body">
        {paths.length === 0 ? (
          <EmptyState
            icon="paths"
            title="No attack paths"
            body="No exploitable paths to sensitive resources were discovered in this scan."
          />
        ) : (
          paths.map((path, index) => {
            const sev = severityClass(
              path.severity,
            );
            const isSelected =
              selectedPath?.path_id
              === path.path_id;

            const routeTitle = path.nodes
              .map((id) => nameOf(id))
              .join(" → ");

            return (
              <button
                key={
                  path.path_id
                  || `${path.source}-${path.target}-${index}`
                }
                type="button"
                className={
                  isSelected
                    ? "ap-path selected"
                    : "ap-path"
                }
                aria-pressed={isSelected}
                onClick={() =>
                  handleSelect(path)
                }
              >
                <span className="ap-path-head">
                  <span className="ap-path-rank">
                    #{index + 1}
                  </span>

                  <span
                    className={
                      `badge badge-sm no-dot `
                      + `badge-${sev}`
                    }
                  >
                    {sev === "neutral"
                      ? "UNRATED"
                      : sev.toUpperCase()}
                  </span>

                  <span className="ap-path-hops">
                    {path.hop_count}{" "}
                    {path.hop_count === 1
                      ? "hop"
                      : "hops"}
                  </span>
                </span>

                <span
                  className="ap-path-route"
                  title={routeTitle}
                >
                  {path.nodes.map(
                    (nodeId, nodeIndex) => (
                      <Fragment
                        key={`${nodeId}-${nodeIndex}`}
                      >
                        {nodeIndex > 0 && (
                          <span
                            className="ap-arrow"
                            aria-hidden="true"
                          >
                            →
                          </span>
                        )}

                        <span className="wrap-anywhere">
                          {nameOf(nodeId)}
                        </span>
                      </Fragment>
                    ),
                  )}

                  {path.sensitive_target && (
                    <Icon
                      name="lock"
                      size={11}
                    />
                  )}
                </span>

                <span className="riskbar-with-value ap-path-riskbar">
                  <span className="riskbar">
                    <span
                      className={
                        `riskbar-fill `
                        + riskFillClass(sev)
                      }
                      style={{
                        width: riskPercent(
                          path.risk_score,
                        ),
                      }}
                    />
                  </span>

                  <span className="riskbar-value">
                    {Math.round(path.risk_score)}
                  </span>
                </span>
              </button>
            );
          })
        )}
      </div>
    </aside>
  );
}


/* ============================================
   Graph panel
   ============================================ */

function GraphPanel({
  flowNodes,
  edges,
  onNodesChange,
  onSelectionChange,
}: {
  flowNodes: AssetFlowNode[];
  edges: Edge[];
  onNodesChange: OnNodesChange<AssetFlowNode>;
  onSelectionChange: (
    params: OnSelectionChangeParams<
      AssetFlowNode,
      Edge
    >,
  ) => void;
}) {
  const { fitView } = useReactFlow();

  const handleFitView = () => {
    fitView({
      padding: 0.2,
      duration: prefersReducedMotion()
        ? 0
        : 220,
    });
  };

  return (
    <div
      className="panel ap-graph"
      aria-label="Security graph"
    >
      <div className="ap-graph-toolbar">
        <span className="ap-graph-hint">
          <Icon name="info" size={12} />
          Scroll to zoom · drag to pan · click a
          node or edge to inspect it
        </span>

        <button
          type="button"
          className="btn btn-secondary btn-sm"
          onClick={handleFitView}
        >
          <Icon name="search" size={13} />
          Fit view
        </button>
      </div>

      <div className="ap-canvas">
        <ReactFlow
          nodes={flowNodes}
          edges={edges}
          nodeTypes={nodeTypes}
          onNodesChange={onNodesChange}
          onSelectionChange={onSelectionChange}
          fitView
          fitViewOptions={{
            padding: 0.2,
            maxZoom: 1.05,
          }}
          minZoom={0.25}
          maxZoom={1.75}
          nodesDraggable
          nodesConnectable={false}
          elementsSelectable
          deleteKeyCode={null}
          colorMode="dark"
          attributionPosition="top-left"
          defaultMarkerColor="var(--border-strong)"
        >
          <Background
            variant={BackgroundVariant.Dots}
            gap={22}
            size={1.2}
            color="var(--border-subtle)"
          />

          <MiniMap
            pannable
            zoomable
            nodeStrokeWidth={3}
            nodeColor={(node) =>
              MINIMAP_NODE_COLORS[
                (
                  node.data as
                    | AssetNodeData
                    | undefined
                )?.category ?? "resource"
              ]
            }
          />

          <Controls
            showInteractive={false}
            position="bottom-right"
          />

          <Panel
            position="bottom-left"
            className="ap-legend"
            aria-label="Node type legend"
          >
            <p className="ap-legend-title">
              Node types
            </p>

            {LEGEND_CATEGORIES.map((category) => (
              <span
                key={category}
                className={
                  `ap-legend-item `
                  + `ap-legend-item--${category}`
                }
              >
                <span
                  className={
                    `ap-legend-dot `
                    + `ap-legend-dot--${category}`
                  }
                />
                <Icon
                  name={
                    CATEGORY_META[category].icon
                  }
                  size={11}
                />
                {CATEGORY_META[category].label}
              </span>
            ))}
          </Panel>
        </ReactFlow>
      </div>
    </div>
  );
}


/* ============================================
   Inspector: asset
   ============================================ */

function AssetInspector({
  asset,
  category,
  risk,
}: {
  asset: CloudAsset;
  category: NodeCategory;
  risk: {
    score: number;
    severity: SevClass;
    count: number;
  } | null;
}) {
  const meta = CATEGORY_META[category];

  return (
    <div>
      <p className="eyebrow">ASSET</p>

      <h3 className="ap-insp-title wrap-anywhere">
        {asset.name}
      </h3>

      <div className="ap-insp-badges">
        <span className="badge badge-neutral no-dot">
          <Icon name={meta.icon} size={11} />
          {meta.label}
        </span>

        <span className="badge badge-neutral no-dot">
          {formatLabel(asset.asset_type)}
        </span>

        {asset.sensitive && (
          <span className="badge badge-critical">
            Sensitive
          </span>
        )}

        {asset.internet_exposed && (
          <span className="badge badge-warning">
            Internet exposed
          </span>
        )}
      </div>

      <p className="ap-insp-section">
        Identifiers
      </p>

      <DetailRow
        label="Asset ID"
        value={asset.id}
        mono
      />

      <DetailRow
        label="Region"
        value={asset.region ?? "Global"}
      />

      <DetailRow
        label="Account"
        value={
          asset.account_id ?? "Not applicable"
        }
        mono={asset.account_id !== null}
      />

      <p className="ap-insp-section">
        Exposure
      </p>

      <DetailRow
        label="Internet exposed"
        value={asset.internet_exposed ? "Yes" : "No"}
      />

      <DetailRow
        label="Sensitive"
        value={asset.sensitive ? "Yes" : "No"}
      />

      <DetailRow
        label="On attack paths"
        value={String(risk?.count ?? 0)}
      />

      {risk && (
        <div className="ap-insp-block">
          <p className="ap-insp-label">
            Highest path risk
          </p>

          <div className="riskbar-with-value">
            <div className="riskbar">
              <div
                className={
                  `riskbar-fill `
                  + riskFillClass(risk.severity)
                }
                style={{
                  width: riskPercent(risk.score),
                }}
              />
            </div>

            <span className="riskbar-value">
              {Math.round(risk.score)}
            </span>
          </div>
        </div>
      )}

      {Object.keys(asset.metadata).length > 0 && (
        <>
          <p className="ap-insp-section">
            Metadata
          </p>

          {Object.entries(asset.metadata).map(
            ([key, value]) => (
              <DetailRow
                key={key}
                label={key}
                value={value || "—"}
              />
            ),
          )}
        </>
      )}
    </div>
  );
}


/* ============================================
   Inspector: relationship (edge)
   ============================================ */

function RelationshipInspector({
  relationship,
  assetById,
}: {
  relationship: Relationship;
  assetById: Map<string, CloudAsset>;
}) {
  return (
    <div>
      <p className="eyebrow">RELATIONSHIP</p>

      <h3 className="ap-insp-title">
        {formatLabel(
          relationship.relationship_type,
        )}
      </h3>

      <EndpointRow
        label="Source"
        id={relationship.source}
        assetById={assetById}
      />

      <EndpointRow
        label="Target"
        id={relationship.target}
        assetById={assetById}
      />

      <DetailRow
        label="Type"
        value={formatLabel(
          relationship.relationship_type,
        )}
      />

      <p className="ap-insp-section">Evidence</p>

      <p className="ap-insp-text wrap-anywhere">
        {relationship.evidence
          ?? "No additional evidence recorded."}
      </p>

      {relationship.permissions.length > 0 && (
        <>
          <p className="ap-insp-section">
            Permissions
          </p>

          <div className="chip-row">
            {relationship.permissions.map(
              (permission) => (
                <span
                  key={permission}
                  className="chip"
                >
                  <span className="mono wrap-anywhere">
                    {permission}
                  </span>
                </span>
              ),
            )}
          </div>
        </>
      )}
    </div>
  );
}


/* ============================================
   Inspector: attack path
   ============================================ */

function PathInspector({
  path,
  rank,
  assetById,
  categories,
  relationships,
  selectedHopIndex,
  onSelectHop,
}: {
  path: AttackPath;
  rank: number;
  assetById: Map<string, CloudAsset>;
  categories: Map<string, NodeCategory>;
  relationships: Relationship[];
  selectedHopIndex: number | null;
  onSelectHop: (index: number | null) => void;
}) {
  const sev = severityClass(path.severity);

  const nameOf = (id: string) =>
    assetById.get(id)?.name ?? id;

  const remediations = path.hops
    .map((hop, index) => {
      const relationship = relationships.find(
        (item) =>
          item.source === hop.source
          && item.target === hop.target,
      );

      if (!relationship) {
        return null;
      }

      const suggestions: string[] = [];

      if (
        hop.relationship_type === "exposed_to"
      ) {
        suggestions.push(
          `Restrict security group ingress for ${nameOf(hop.source)}`,
        );
      }

      if (hop.relationship_type === "assumes") {
        suggestions.push(
          `Review instance profile attachment for ${nameOf(hop.source)}`,
        );
      }

      if (
        hop.relationship_type === "can_read"
      ) {
        suggestions.push(
          `Restrict read permissions on ${nameOf(hop.target)}`,
        );
      }

      if (
        hop.relationship_type === "can_write"
      ) {
        suggestions.push(
          `Remove write permissions on ${nameOf(hop.target)}`,
        );
      }

      if (suggestions.length === 0) {
        return null;
      }

      return { hop, index, suggestions };
    })
    .filter(
      (item): item is NonNullable<typeof item> =>
        item !== null,
    );

  return (
    <div>
      <p className="eyebrow">
        ATTACK PATH #{rank}
      </p>

      <h3 className="ap-insp-title wrap-anywhere">
        {nameOf(path.source)} →{" "}
        {nameOf(path.target)}
      </h3>

      <div className="ap-insp-badges">
        <span
          className={
            `badge no-dot badge-${sev}`
          }
        >
          {sev === "neutral"
            ? "UNRATED"
            : sev.toUpperCase()}
        </span>

        <span className="badge badge-neutral no-dot">
          {path.hop_count}{" "}
          {path.hop_count === 1 ? "hop" : "hops"}
        </span>

        {path.sensitive_target && (
          <span className="badge badge-critical no-dot">
            <Icon name="lock" size={11} />
            Sensitive target
          </span>
        )}

        {path.confidence && (
          <span
            className={
              `badge no-dot `
              + confidenceBadgeClass(
                path.confidence,
              )
            }
          >
            Confidence: {path.confidence}
          </span>
        )}
      </div>

      <div className="riskbar-with-value">
        <div className="riskbar">
          <div
            className={
              `riskbar-fill `
              + riskFillClass(sev)
            }
            style={{
              width: riskPercent(
                path.risk_score,
              ),
            }}
          />
        </div>

        <span className="riskbar-value">
          {Math.round(path.risk_score)}
        </span>
      </div>

      <p className="ap-insp-section">Route</p>

      <ol className="ap-route">
        {path.nodes.map((nodeId, nodeIndex) => {
          const asset = assetById.get(nodeId);
          const category = asset
            ? categories.get(nodeId) ?? "resource"
            : "resource";

          return (
            <li
              key={`${nodeId}-${nodeIndex}`}
              className="ap-route-item"
            >
              {nodeIndex > 0 && (
                <span
                  className="ap-arrow"
                  aria-hidden="true"
                >
                  →
                </span>
              )}

              <span
                className={
                  `ap-route-node `
                  + `ap-route-node--${category}`
                }
                title={nodeId}
              >
                <Icon
                  name={
                    CATEGORY_META[category].icon
                  }
                  size={11}
                />
                <span className="wrap-anywhere">
                  {nameOf(nodeId)}
                </span>
              </span>
            </li>
          );
        })}
      </ol>

      {path.explanation && (
        <>
          <p className="ap-insp-section">
            Explanation
          </p>

          <p className="ap-insp-text wrap-anywhere">
            {path.explanation}
          </p>
        </>
      )}

      <p className="ap-insp-section">
        Hop-by-hop
      </p>

      {path.hops.map((hop, hopIndex) => {
        const isOpen =
          selectedHopIndex === hopIndex;

        return (
          <Fragment
            key={`${hop.source}-${hop.target}-${hopIndex}`}
          >
            <button
              type="button"
              className={
                isOpen
                  ? "ap-hop selected"
                  : "ap-hop"
              }
              aria-expanded={isOpen}
              onClick={() =>
                onSelectHop(
                  isOpen ? null : hopIndex,
                )
              }
            >
              <span className="ap-hop-top">
                <span className="ap-hop-num">
                  Hop {hopIndex + 1}
                </span>

                <span className="badge badge-sm no-dot badge-neutral">
                  {formatLabel(
                    hop.relationship_type,
                  )}
                </span>

                {hop.confidence && (
                  <span
                    className={
                      `badge badge-sm no-dot `
                      + confidenceBadgeClass(
                        hop.confidence,
                      )
                    }
                  >
                    {hop.confidence}
                  </span>
                )}
              </span>

              <span
                className="ap-hop-route wrap-anywhere"
                title={`${hop.source} → ${hop.target}`}
              >
                {nameOf(hop.source)} →{" "}
                {nameOf(hop.target)}
              </span>
            </button>

            {isOpen && (
              <HopDetail
                hop={hop}
                nameOf={nameOf}
              />
            )}
          </Fragment>
        );
      })}

      {remediations.length > 0 && (
        <>
          <p className="ap-insp-section">
            Remediation opportunities
          </p>

          <ul className="ap-remediate-list">
            {remediations.map((item) => (
              <li
                key={`${item.hop.source}-${item.hop.target}`}
              >
                <Icon
                  name="remediate"
                  size={12}
                />
                <span className="wrap-anywhere">
                  <strong>
                    Hop {item.index + 1}:
                  </strong>{" "}
                  {item.suggestions.join("; ")}
                </span>
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
}


function HopDetail({
  hop,
  nameOf,
}: {
  hop: AttackPathHop;
  nameOf: (id: string) => string;
}) {
  return (
    <div className="ap-hop-detail">
      <InspBlock label="Hop">
        <p
          className="ap-insp-text wrap-anywhere"
          title={`${hop.source} → ${hop.target}`}
        >
          {nameOf(hop.source)} →{" "}
          {nameOf(hop.target)}
        </p>
      </InspBlock>

      <InspBlock label="Why it works">
        <p className="ap-insp-text wrap-anywhere">
          {hop.reason}
        </p>
      </InspBlock>

      {hop.evidence && (
        <InspBlock label="Evidence">
          <p className="ap-insp-text wrap-anywhere">
            {hop.evidence}
          </p>
        </InspBlock>
      )}

      {hop.configuration && (
        <InspBlock label="Configuration">
          <p className="ap-insp-text wrap-anywhere">
            {hop.configuration}
          </p>
        </InspBlock>
      )}

      {hop.impact && (
        <InspBlock label="Impact">
          <p className="ap-insp-text wrap-anywhere">
            {hop.impact}
          </p>
        </InspBlock>
      )}

      {hop.permissions.length > 0 && (
        <InspBlock label="Permissions">
          <div className="chip-row">
            {hop.permissions.map(
              (permission) => (
                <span
                  key={permission}
                  className="chip"
                >
                  <span className="mono wrap-anywhere">
                    {permission}
                  </span>
                </span>
              ),
            )}
          </div>
        </InspBlock>
      )}
    </div>
  );
}


/* ============================================
   Inspector: default summary
   ============================================ */

function InspectorSummary({
  assetCount,
  relationshipCount,
  attackPaths,
}: {
  assetCount: number;
  relationshipCount: number;
  attackPaths: AttackPath[];
}) {
  const highestRisk =
    attackPaths.length > 0
      ? Math.max(
          ...attackPaths.map(
            (path) => path.risk_score,
          ),
        )
      : null;

  return (
    <div>
      <p className="eyebrow">INSPECTOR</p>

      <h3 className="ap-insp-title">
        Nothing selected
      </h3>

      <p className="ap-insp-text">
        Select an attack path from the list to
        trace it through the graph, or click a
        node or edge to inspect its security
        context.
      </p>

      <p className="ap-insp-section">
        At a glance
      </p>

      <DetailRow
        label="Assets"
        value={String(assetCount)}
      />

      <DetailRow
        label="Relationships"
        value={String(relationshipCount)}
      />

      <DetailRow
        label="Attack paths"
        value={String(attackPaths.length)}
      />

      {highestRisk !== null && (
        <DetailRow
          label="Highest path risk"
          value={String(Math.round(highestRisk))}
        />
      )}
    </div>
  );
}


/* ============================================
   Small shared bits
   ============================================ */

function DetailRow({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="ap-row">
      <span className="ap-row-label">
        {label}
      </span>

      <strong
        className={
          `ap-row-value wrap-anywhere`
          + (mono ? " mono" : "")
        }
        title={value}
      >
        {value}
      </strong>
    </div>
  );
}


function EndpointRow({
  label,
  id,
  assetById,
}: {
  label: string;
  id: string;
  assetById: Map<string, CloudAsset>;
}) {
  const asset = assetById.get(id);

  return (
    <div className="ap-row">
      <span className="ap-row-label">
        {label}
      </span>

      <span
        className={
          `ap-row-value wrap-anywhere`
          + (asset ? "" : " mono")
        }
        title={id}
      >
        {asset?.name ?? id}
      </span>
    </div>
  );
}


function InspBlock({
  label,
  children,
}: {
  label: string;
  children: ReactNode;
}) {
  return (
    <div className="ap-insp-block">
      <p className="ap-insp-label">{label}</p>
      {children}
    </div>
  );
}


export default AttackPaths;
