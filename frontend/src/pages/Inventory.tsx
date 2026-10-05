import { useEffect, useMemo, useState } from "react";

import { useScanContext } from "../context/ScanContext";
import { getScanAssets } from "../services/api";
import type { CloudAsset } from "../types/cloudguard";


function Inventory() {
  const { selectedScan } =
    useScanContext();

  const scanId =
    selectedScan?.scan_id ?? null;

  const [assets, setAssets] =
    useState<CloudAsset[]>([]);

  const [search, setSearch] =
    useState("");

  const [typeFilter, setTypeFilter] =
    useState<string[]>([]);

  const [regionFilter, setRegionFilter] =
    useState<string[]>([]);

  const [exposureFilter, setExposureFilter] =
    useState<"all" | "exposed" | "internal">("all");

  const [sensitivityFilter, setSensitivityFilter] =
    useState<"all" | "sensitive" | "standard">("all");

  const [loading, setLoading] =
    useState(true);

  const [error, setError] =
    useState<string | null>(null);

  useEffect(() => {
    if (!scanId) {
      return;
    }

    const currentScanId: string = scanId;

    async function loadAssets() {
      setLoading(true);
      setError(null);

      try {
        const data = await getScanAssets(
          currentScanId,
        );

        setAssets(data);
      } catch (requestError) {
        const message =
          requestError instanceof Error
            ? requestError.message
            : "Unable to load assets.";

        setError(message);
      } finally {
        setLoading(false);
      }
    }

    loadAssets();
  }, [scanId]);

  // Available filter options
  const availableTypes = useMemo(
    () => [
      ...new Set(assets.map((a) => a.asset_type)),
    ].sort(),
    [assets],
  );

  const availableRegions = useMemo(
    () => [
      ...new Set(
        assets
          .map((a) => a.region ?? "Global")
          .filter((r) => r),
      ),
    ].sort(),
    [assets],
  );

  // Apply all filters
  const filteredAssets = useMemo(() => {
    const query = search
      .trim()
      .toLowerCase();

    return assets.filter((asset) => {
      // Search query
      if (
        query &&
        !asset.name.toLowerCase().includes(query) &&
        !asset.id.toLowerCase().includes(query) &&
        !asset.asset_type.toLowerCase().includes(query)
      ) {
        return false;
      }

      // Type filter
      if (
        typeFilter.length > 0 &&
        !typeFilter.includes(asset.asset_type)
      ) {
        return false;
      }

      // Region filter
      const assetRegion = asset.region ?? "Global";
      if (
        regionFilter.length > 0 &&
        !regionFilter.includes(assetRegion)
      ) {
        return false;
      }

      // Exposure filter
      if (
        exposureFilter === "exposed" &&
        !asset.internet_exposed
      ) {
        return false;
      }
      if (
        exposureFilter === "internal" &&
        asset.internet_exposed
      ) {
        return false;
      }

      // Sensitivity filter
      if (
        sensitivityFilter === "sensitive" &&
        !asset.sensitive
      ) {
        return false;
      }
      if (
        sensitivityFilter === "standard" &&
        asset.sensitive
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
  const sensitiveCount = assets.filter((a) => a.sensitive).length;
  const exposedCount = assets.filter((a) => a.internet_exposed).length;
  const filteredCount = filteredAssets.length;

  if (loading) {
    return (
      <section className="page-state">
        Loading cloud inventory...
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
            CLOUD INVENTORY
          </p>

          <h2>Asset Inventory</h2>

          <p className="subtitle">
            Normalized resources discovered by
            CloudGuard.
          </p>
        </div>

        <div className="environment-badge">
          {assets.length} ASSETS
        </div>
      </header>

      <section className="panel inventory-panel">
        <div className="inventory-toolbar">
          <div>
            <h3>Cloud Resources</h3>

            <p>
              Search, filter, and inspect resources
              represented in the security graph.
            </p>
          </div>

          <div className="inventory-summary">
            <span className="summary-item">
              <strong>{totalAssets}</strong> total
            </span>
            <span className="summary-item sensitive">
              <strong>{sensitiveCount}</strong> sensitive
            </span>
            <span className="summary-item exposed">
              <strong>{exposedCount}</strong> exposed
            </span>
            <span className="summary-item filtered">
              <strong>{filteredCount}</strong> showing
            </span>
          </div>
        </div>

        <div className="inventory-filters">
          <div className="filter-group search-group">
            <label htmlFor="inventory-search">
              Search
            </label>
            <input
              id="inventory-search"
              className="inventory-search"
              type="search"
              placeholder="Search assets by name, ID, or type..."
              value={search}
              onChange={(event) =>
                setSearch(event.target.value)
              }
            />
          </div>

          <div className="filter-group">
            <label>Type</label>
            <select
              className="filter-multi"
              multiple
              value={typeFilter}
              onChange={(e) =>
                setTypeFilter(
                  Array.from(e.target.selectedOptions, (o) => o.value),
                )
              }
            >
              {availableTypes.map((type) => (
                <option key={type} value={type}>
                  {type}
                </option>
              ))}
            </select>
          </div>

          <div className="filter-group">
            <label>Region</label>
            <select
              className="filter-multi"
              multiple
              value={regionFilter}
              onChange={(e) =>
                setRegionFilter(
                  Array.from(e.target.selectedOptions, (o) => o.value),
                )
              }
            >
              {availableRegions.map((region) => (
                <option key={region} value={region}>
                  {region}
                </option>
              ))}
            </select>
          </div>

          <div className="filter-group">
            <label>Exposure</label>
            <select
              value={exposureFilter}
              onChange={(e) =>
                setExposureFilter(
                  e.target.value as "all" | "exposed" | "internal",
                )
              }
            >
              <option value="all">All</option>
              <option value="exposed">Internet Exposed</option>
              <option value="internal">Internal Only</option>
            </select>
          </div>

          <div className="filter-group">
            <label>Classification</label>
            <select
              value={sensitivityFilter}
              onChange={(e) =>
                setSensitivityFilter(
                  e.target.value as "all" | "sensitive" | "standard",
                )
              }
            >
              <option value="all">All</option>
              <option value="sensitive">Sensitive</option>
              <option value="standard">Standard</option>
            </select>
          </div>
        </div>

        <div className="inventory-table-wrapper">
          <table className="inventory-table">
            <thead>
              <tr>
                <th>Asset</th>
                <th>Type</th>
                <th>Region</th>
                <th>Exposure</th>
                <th>Classification</th>
              </tr>
            </thead>

            <tbody>
              {filteredAssets.map((asset) => (
                <tr key={asset.id}>
                  <td>
                    <div className="asset-name">
                      {asset.name}
                    </div>

                    <div className="asset-id">
                      {asset.id}
                    </div>
                  </td>

                  <td>
                    <span className="asset-type">
                      {asset.asset_type}
                    </span>
                  </td>

                  <td>
                    {asset.region ?? "Global"}
                  </td>

                  <td>
                    {asset.internet_exposed ? (
                      <span className="table-status exposed">
                        Internet exposed
                      </span>
                    ) : (
                      <span className="table-status">
                        Internal
                      </span>
                    )}
                  </td>

                  <td>
                    {asset.sensitive ? (
                      <span className="table-status sensitive">
                        Sensitive
                      </span>
                    ) : (
                      <span className="table-status">
                        Standard
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {filteredAssets.length === 0 && (
            <div className="empty-state">
              No assets match your search and filters.
            </div>
          )}
        </div>
      </section>
    </>
  );
}

export default Inventory;