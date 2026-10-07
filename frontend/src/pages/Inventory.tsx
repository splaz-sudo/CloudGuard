import {
  useMemo,
  useState,
  type CSSProperties,
} from "react";

import { useScanContext } from "../context/ScanContext";
import { getScanAssets } from "../services/api";
import { useScanQuery } from "../hooks/useApiQuery";

import Icon from "../components/Icon";
import {
  MultiSelect,
  SearchInput,
  Select,
} from "../components/FormControls";
import {
  EmptyState,
  ErrorState,
  LoadingState,
} from "../components/StateBlock";

import {
  ResourceNode,
  ResourceChip,
  normalizeResourceType,
  StatusBadge,
} from "../components/visualization";

import "../styles/inventory.css";


function Inventory() {
  const { selectedScan } = useScanContext();
  const scanId = selectedScan?.scan_id ?? null;

  const assetsQuery = useScanQuery(
    getScanAssets,
    scanId,
  );

  const [search, setSearch] = useState("");

  const [typeFilter, setTypeFilter] =
    useState<string[]>([]);

  const [regionFilter, setRegionFilter] =
    useState<string[]>([]);

  const [exposureFilter, setExposureFilter] =
    useState<"all" | "exposed" | "internal">("all");

  const [sensitivityFilter, setSensitivityFilter] =
    useState<"all" | "sensitive" | "standard">("all");

  const assets = useMemo(
    () => assetsQuery.data ?? [],
    [assetsQuery.data],
  );

  // Available filter options
  const availableTypes = useMemo(
    () =>
      [
        ...new Set(
          assets.map((asset) => asset.asset_type),
        ),
      ].sort(),
    [assets],
  );

  const availableRegions = useMemo(
    () =>
      [
        ...new Set(
          assets
            .map((asset) => asset.region ?? "Global")
            .filter((region) => region),
        ),
      ].sort(),
    [assets],
  );

  // Apply all filters
  const filteredAssets = useMemo(() => {
    const queryText = search.trim().toLowerCase();

    return assets.filter((asset) => {
      // Search query
      if (
        queryText
        && !asset.name
          .toLowerCase()
          .includes(queryText)
        && !asset.id
          .toLowerCase()
          .includes(queryText)
        && !asset.asset_type
          .toLowerCase()
          .includes(queryText)
      ) {
        return false;
      }

      // Type filter
      if (
        typeFilter.length > 0
        && !typeFilter.includes(asset.asset_type)
      ) {
        return false;
      }

      // Region filter
      const assetRegion = asset.region ?? "Global";
      if (
        regionFilter.length > 0
        && !regionFilter.includes(assetRegion)
      ) {
        return false;
      }

      // Exposure filter
      if (
        exposureFilter === "exposed"
        && !asset.internet_exposed
      ) {
        return false;
      }
      if (
        exposureFilter === "internal"
        && asset.internet_exposed
      ) {
        return false;
      }

      // Sensitivity filter
      if (
        sensitivityFilter === "sensitive"
        && !asset.sensitive
      ) {
        return false;
      }
      if (
        sensitivityFilter === "standard"
        && asset.sensitive
      ) {
        return false;
      }

      return true;
    });
  }, [
    assets,
    search,
    typeFilter,
    regionFilter,
    exposureFilter,
    sensitivityFilter,
  ]);

  // Summary counts
  const totalAssets = assets.length;
  const sensitiveCount = assets.filter(
    (asset) => asset.sensitive,
  ).length;
  const exposedCount = assets.filter(
    (asset) => asset.internet_exposed,
  ).length;
  const filteredCount = filteredAssets.length;

  const clearFilters = () => {
    setSearch("");
    setTypeFilter([]);
    setRegionFilter([]);
    setExposureFilter("all");
    setSensitivityFilter("all");
  };

  return (
    <div className="page">
      <header
        className="topbar"
        style={{ "--i": 0 } as CSSProperties}
      >
        <div>
          <p className="eyebrow">CLOUD INVENTORY</p>
          <h2>Asset Inventory</h2>
          <p className="page-subtitle">
            Normalized cloud resources discovered by
            CloudGuard and represented in the security
            graph.
          </p>
        </div>

        {scanId
          && !assetsQuery.loading
          && !assetsQuery.error
          && assets.length > 0 && (
          <span className="chip inventory-count">
            <strong>{assets.length}</strong>
            assets discovered
          </span>
        )}
      </header>

      {!scanId ? (
        <EmptyState
          icon="scans"
          title="No scan selected"
          body="Select a scan from the sidebar to browse the resources it discovered."
        />
      ) : assetsQuery.error ? (
        <ErrorState
          error={assetsQuery.error}
          resourceLabel="inventory"
          onRetry={assetsQuery.retry}
        />
      ) : assetsQuery.loading ? (
        <div className="panel">
          <LoadingState label="Loading inventory…" />
        </div>
      ) : assets.length === 0 ? (
        <div className="panel">
          <EmptyState
            icon="inventory"
            title="No assets discovered"
            body="The selected scan did not discover any cloud resources."
          />
        </div>
      ) : (
        <>
          <div
            className="toolbar inventory-toolbar"
            style={{ "--i": 1 } as CSSProperties}
          >
            <div className="filter-group inventory-search-group">
              <label
                className="form-label"
                htmlFor="inventory-search"
              >
                Search
              </label>
              <SearchInput
                id="inventory-search"
                placeholder="Search by name, ID, or type..."
                value={search}
                onChange={setSearch}
              />
            </div>

            <MultiSelect
              label="Type"
              options={availableTypes.map((type) => ({
                value: type,
                label: type,
              }))}
              value={typeFilter}
              onChange={setTypeFilter}
              placeholder="All types"
            />

            <MultiSelect
              label="Region"
              options={availableRegions.map(
                (region) => ({
                  value: region,
                  label: region,
                }),
              )}
              value={regionFilter}
              onChange={setRegionFilter}
              placeholder="All regions"
            />

            <Select
              label="Exposure"
              options={[
                { value: "all", label: "All" },
                {
                  value: "exposed",
                  label: "Internet Exposed",
                },
                {
                  value: "internal",
                  label: "Internal Only",
                },
              ]}
              value={exposureFilter}
              onChange={(value) =>
                setExposureFilter(
                  value as
                    | "all"
                    | "exposed"
                    | "internal",
                )
              }
            />

            <Select
              label="Classification"
              options={[
                { value: "all", label: "All" },
                {
                  value: "sensitive",
                  label: "Sensitive",
                },
                {
                  value: "standard",
                  label: "Standard",
                },
              ]}
              value={sensitivityFilter}
              onChange={(value) =>
                setSensitivityFilter(
                  value as
                    | "all"
                    | "sensitive"
                    | "standard",
                )
              }
            />
          </div>

          <div
            className="chip-row inventory-chips"
            style={{ "--i": 2 } as CSSProperties}
          >
            <span className="chip">
              <strong>{totalAssets}</strong>
              total
            </span>
            <span className="chip">
              <Icon name="lock" size={12} />
              <strong>{sensitiveCount}</strong>
              sensitive
            </span>
            <span className="chip">
              <Icon name="globe" size={12} />
              <strong>{exposedCount}</strong>
              exposed
            </span>
            <span className="chip">
              <strong>{filteredCount}</strong>
              showing
            </span>
          </div>

          {filteredAssets.length === 0 ? (
            <div
              className="panel"
              style={{ "--i": 3 } as CSSProperties}
            >
              <EmptyState
                icon="search"
                title="No assets match your filters"
                body="Adjust the search text or clear the active filters to see matching resources."
                action={
                  <button
                    type="button"
                    className="btn btn-secondary btn-sm"
                    onClick={clearFilters}
                  >
                    <Icon name="x" size={14} />
                    Clear filters
                  </button>
                }
              />
            </div>
          ) : (
            <div
              className="table-wrap"
              style={{ "--i": 3 } as CSSProperties}
            >
              <div className="table-scroll">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th scope="col">Asset</th>
                      <th scope="col">Type</th>
                      <th scope="col">Region</th>
                      <th scope="col">Exposure</th>
                      <th scope="col">
                        Classification
                      </th>
                    </tr>
                  </thead>

                  <tbody>
                    {filteredAssets.map((asset) => (
                      <tr key={asset.id}>
                        <td className="asset-cell">
                          <ResourceNode
                            type={normalizeResourceType(asset.asset_type)}
                            name={asset.name}
                            id={asset.id}
                            sensitive={asset.sensitive}
                            internetExposed={asset.internet_exposed}
                            size="sm"
                            showType={false}
                            showRisk={false}
                            showFlags={false}
                          />
                        </td>

                        <td>
                          <ResourceChip type={normalizeResourceType(asset.asset_type)} name={asset.asset_type} />
                        </td>

                        <td>
                          {asset.region ?? "Global"}
                        </td>

                        <td>
                          {asset.internet_exposed ? (
                            <StatusBadge variant="danger" size="sm" icon="globe" showDot={false}>
                              PUBLIC
                            </StatusBadge>
                          ) : (
                            <span className="badge badge-success">
                              PRIVATE
                            </span>
                          )}
                        </td>

                        <td>
                          {asset.sensitive ? (
                            <span className="badge badge-warning no-dot">
                              <Icon
                                name="lock"
                                size={11}
                              />
                              SENSITIVE
                            </span>
                          ) : (
                            <span className="badge badge-neutral">
                              STANDARD
                            </span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}


export default Inventory;
