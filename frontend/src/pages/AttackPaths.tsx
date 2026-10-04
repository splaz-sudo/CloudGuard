import {
  useEffect,
  useMemo,
  useState,
} from "react";

import {
  Background,
  Controls,
  MarkerType,
  MiniMap,
  ReactFlow,
  type Edge,
  type Node,
} from "@xyflow/react";

import "@xyflow/react/dist/style.css";

import {
  getAssets,
  getAttackPaths,
  getRelationships,
} from "../services/api";

import type {
  AttackPath,
  CloudAsset,
  Relationship,
} from "../types/cloudguard";


type AssetNodeData = {
  label: string;
  asset: CloudAsset;
};


function AttackPaths() {
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

  const [loading, setLoading] =
    useState(true);

  const [error, setError] =
    useState<string | null>(null);


  useEffect(() => {
    async function loadGraph() {
      try {
        const [
          assetData,
          relationshipData,
          pathData,
        ] = await Promise.all([
          getAssets(),
          getRelationships(),
          getAttackPaths(),
        ]);

        setAssets(assetData);
        setRelationships(
          relationshipData,
        );
        setAttackPaths(pathData);
      } catch (requestError) {
        setError(
          requestError instanceof Error
            ? requestError.message
            : "Unable to load security graph.",
        );
      } finally {
        setLoading(false);
      }
    }

    loadGraph();
  }, []);


  const attackPathNodeIds = useMemo(() => {
    return new Set(
      attackPaths.flatMap(
        (path) => path.nodes,
      ),
    );
  }, [attackPaths]);


  const nodes = useMemo<Node<AssetNodeData>[]>(
    () =>
      assets.map((asset, index) => {
        const position =
          getNodePosition(
            asset,
            index,
          );

        const onAttackPath =
          attackPathNodeIds.has(
            asset.id,
          );

        return {
          id: asset.id,
          position,
          data: {
            label: asset.name,
            asset,
          },
          style: {
            width: 190,
            padding: 14,
            borderRadius: 10,
            border: getNodeBorder(
              asset,
              onAttackPath,
            ),
            background:
              getNodeBackground(asset),
            color: "#e8eef9",
            fontSize: 12,
            fontWeight: 700,
            boxShadow:
              onAttackPath
                ? "0 0 24px rgba(90, 125, 255, 0.16)"
                : "none",
          },
        };
      }),
    [assets, attackPathNodeIds],
  );


  const edges = useMemo<Edge[]>(
    () =>
      relationships.map(
        (relationship, index) => {
          const onAttackPath =
            attackPaths.some(
              (path) =>
                path.relationships.some(
                  (pathRelationship) =>
                    pathRelationship.source ===
                      relationship.source &&
                    pathRelationship.target ===
                      relationship.target &&
                    pathRelationship
                      .relationship_type ===
                      relationship
                        .relationship_type,
                ),
            );

          return {
            id: [
              relationship.source,
              relationship.target,
              relationship
                .relationship_type,
              index,
            ].join("-"),
            source:
              relationship.source,
            target:
              relationship.target,
            label: formatRelationship(
              relationship
                .relationship_type,
            ),
            markerEnd: {
              type: MarkerType.ArrowClosed,
            },
            animated: onAttackPath,
            style: {
              strokeWidth:
                onAttackPath ? 2.5 : 1.5,
              stroke:
                onAttackPath
                  ? "#6f8fff"
                  : "#46546a",
            },
            labelStyle: {
              fill: "#9baac0",
              fontSize: 10,
              fontWeight: 700,
            },
            labelBgStyle: {
              fill: "#0d1420",
              fillOpacity: 0.95,
            },
            data: {
              relationship,
            },
          };
        },
      ),
    [relationships, attackPaths],
  );


  if (loading) {
    return (
      <section className="page-state">
        Building security graph...
      </section>
    );
  }


  if (error) {
    return (
      <section className="page-state error-message">
        {error}
      </section>
    );
  }


  return (
    <>
      <header className="topbar">
        <div>
          <p className="eyebrow">
            SECURITY GRAPH
          </p>

          <h2>
            Attack Path Explorer
          </h2>

          <p className="subtitle">
            Investigate how network exposure,
            identities, permissions, and sensitive
            resources combine into exploitable
            security paths.
          </p>
        </div>

        <div className="graph-header-stats">
          <span className="environment-badge">
            {assets.length} ASSETS
          </span>

          <span className="environment-badge">
            {relationships.length} RELATIONSHIPS
          </span>

          <span className="environment-badge">
            {attackPaths.length} ATTACK PATH
            {attackPaths.length === 1
              ? ""
              : "S"}
          </span>
        </div>
      </header>

      <section className="graph-layout">
        <div className="graph-panel">
          <div className="graph-toolbar">
            <div>
              <span className="status-dot" />
              Security graph
            </div>

            <span>
              Click a node or relationship
              to inspect it
            </span>
          </div>

          <div className="graph-canvas">
            <ReactFlow
              nodes={nodes}
              edges={edges}
              fitView
              fitViewOptions={{
                padding: 0.25,
              }}
              minZoom={0.35}
              maxZoom={1.8}
              nodesDraggable
              nodesConnectable={false}
              elementsSelectable
              onNodeClick={(
                _event,
                node,
              ) => {
                setSelectedAsset(
                  node.data.asset,
                );

                setSelectedRelationship(
                  null,
                );
              }}
              onEdgeClick={(
                _event,
                edge,
              ) => {
                const relationship =
                  edge.data
                    ?.relationship as
                    | Relationship
                    | undefined;

                if (!relationship) {
                  return;
                }

                setSelectedRelationship(
                  relationship,
                );

                setSelectedAsset(null);
              }}
              onPaneClick={() => {
                setSelectedAsset(null);
                setSelectedRelationship(
                  null,
                );
              }}
            >
              <Background
                gap={24}
                size={1}
              />

              <MiniMap
                pannable
                zoomable
                nodeStrokeWidth={3}
              />

              <Controls />
            </ReactFlow>
          </div>
        </div>

        <aside className="graph-details">
          {selectedAsset ? (
            <AssetDetails
              asset={selectedAsset}
            />
          ) : selectedRelationship ? (
            <RelationshipDetails
              relationship={
                selectedRelationship
              }
            />
          ) : (
            <GraphSummary
              attackPaths={attackPaths}
            />
          )}
        </aside>
      </section>
    </>
  );
}


function AssetDetails({
  asset,
}: {
  asset: CloudAsset;
}) {
  return (
    <div>
      <p className="eyebrow">
        ASSET DETAILS
      </p>

      <h3 className="details-title">
        {asset.name}
      </h3>

      <div className="details-badges">
        <span className="asset-type">
          {formatAssetType(
            asset.asset_type,
          )}
        </span>

        {asset.sensitive && (
          <span className="detail-danger">
            SENSITIVE
          </span>
        )}

        {asset.internet_exposed && (
          <span className="detail-warning">
            EXPOSED
          </span>
        )}
      </div>

      <DetailRow
        label="Asset ID"
        value={asset.id}
      />

      <DetailRow
        label="Region"
        value={asset.region ?? "Global"}
      />

      <DetailRow
        label="Account"
        value={
          asset.account_id ??
          "Not applicable"
        }
      />

      <DetailRow
        label="Internet exposed"
        value={
          asset.internet_exposed
            ? "Yes"
            : "No"
        }
      />

      <DetailRow
        label="Sensitive"
        value={
          asset.sensitive
            ? "Yes"
            : "No"
        }
      />

      {Object.keys(
        asset.metadata,
      ).length > 0 && (
        <>
          <div className="details-divider" />

          <p className="details-section-title">
            Metadata
          </p>

          {Object.entries(
            asset.metadata,
          ).map(([key, value]) => (
            <DetailRow
              key={key}
              label={key}
              value={value || "—"}
            />
          ))}
        </>
      )}
    </div>
  );
}


function RelationshipDetails({
  relationship,
}: {
  relationship: Relationship;
}) {
  return (
    <div>
      <p className="eyebrow">
        RELATIONSHIP
      </p>

      <h3 className="details-title">
        {formatRelationship(
          relationship
            .relationship_type,
        )}
      </h3>

      <DetailRow
        label="Source"
        value={relationship.source}
      />

      <DetailRow
        label="Target"
        value={relationship.target}
      />

      <DetailRow
        label="Type"
        value={formatRelationship(
          relationship
            .relationship_type,
        )}
      />

      <div className="details-divider" />

      <p className="details-section-title">
        Evidence
      </p>

      <p className="details-text">
        {relationship.evidence ??
          "No additional evidence recorded."}
      </p>

      {relationship.permissions.length >
        0 && (
        <>
          <div className="details-divider" />

          <p className="details-section-title">
            Permissions
          </p>

          <div className="permission-list">
            {relationship.permissions.map(
              (permission) => (
                <span
                  key={permission}
                  className="permission-chip"
                >
                  {permission}
                </span>
              ),
            )}
          </div>
        </>
      )}
    </div>
  );
}


function GraphSummary({
  attackPaths,
}: {
  attackPaths: AttackPath[];
}) {
  return (
    <div>
      <p className="eyebrow">
        PATH ANALYSIS
      </p>

      <h3 className="details-title">
        Security Graph
      </h3>

      <p className="details-text">
        Select an asset or relationship
        in the graph to inspect its
        security context.
      </p>

      <div className="details-divider" />

      <p className="details-section-title">
        Discovered Attack Paths
      </p>

      {attackPaths.length === 0 ? (
        <p className="details-text">
          No paths to sensitive
          resources were discovered.
        </p>
      ) : (
        <div className="path-list">
          {attackPaths.map(
            (path, index) => (
              <div
                className="path-card"
                key={`${path.source}-${path.target}-${index}`}
              >
                <div className="path-card-header">
                  <strong>
                    Attack Path{" "}
                    {index + 1}
                  </strong>

                  <span>
                    {path.hop_count} hops
                  </span>
                </div>

                <div className="path-chain">
                  {path.nodes.map(
                    (node, nodeIndex) => (
                      <div
                        key={
                          `${node}-${nodeIndex}`
                        }
                      >
                        <span>
                          {node}
                        </span>

                        {nodeIndex <
                          path.nodes
                            .length -
                            1 && (
                          <b>↓</b>
                        )}
                      </div>
                    ),
                  )}
                </div>

                {path.sensitive_target && (
                  <span className="path-sensitive">
                    Sensitive target
                  </span>
                )}
              </div>
            ),
          )}
        </div>
      )}
    </div>
  );
}


function DetailRow({
  label,
  value,
}: {
  label: string;
  value: string;
}) {
  return (
    <div className="detail-row">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}


function getNodePosition(
  asset: CloudAsset,
  index: number,
) {
  const positions: Record<
    string,
    { x: number; y: number }
  > = {
    internet: {
      x: 50,
      y: 190,
    },
    ec2: {
      x: 330,
      y: 190,
    },
    iam_role: {
      x: 610,
      y: 190,
    },
    s3_bucket: {
      x: 890,
      y: 190,
    },
    iam_user: {
      x: 330,
      y: 390,
    },
    security_group: {
      x: 330,
      y: 20,
    },
    vpc: {
      x: 50,
      y: 20,
    },
    rds: {
      x: 890,
      y: 390,
    },
    lambda: {
      x: 610,
      y: 390,
    },
    secret: {
      x: 890,
      y: 540,
    },
  };

  const base =
    positions[asset.asset_type];

  if (base) {
    return {
      x: base.x,
      y:
        base.y +
        index * 5,
    };
  }

  return {
    x: 100 + index * 220,
    y: 500,
  };
}


function getNodeBackground(
  asset: CloudAsset,
) {
  if (asset.sensitive) {
    return "#24141c";
  }

  if (asset.internet_exposed) {
    return "#21180f";
  }

  if (
    asset.asset_type === "internet"
  ) {
    return "#161b27";
  }

  if (
    asset.asset_type === "iam_role" ||
    asset.asset_type === "iam_user"
  ) {
    return "#121b2c";
  }

  return "#101925";
}


function getNodeBorder(
  asset: CloudAsset,
  onAttackPath: boolean,
) {
  if (asset.sensitive) {
    return "1px solid #8a3d55";
  }

  if (asset.internet_exposed) {
    return "1px solid #80522f";
  }

  if (onAttackPath) {
    return "1px solid #4968bd";
  }

  return "1px solid #2b3a50";
}


function formatAssetType(
  value: string,
) {
  return value
    .replaceAll("_", " ")
    .toUpperCase();
}


function formatRelationship(
  value: string,
) {
  return value
    .replaceAll("_", " ")
    .toUpperCase();
}


export default AttackPaths;