import { useEffect, useMemo, useState } from "react";

import { getAssets } from "../services/api";
import type { CloudAsset } from "../types/cloudguard";


function Inventory() {
  const [assets, setAssets] =
    useState<CloudAsset[]>([]);

  const [search, setSearch] =
    useState("");

  const [loading, setLoading] =
    useState(true);

  const [error, setError] =
    useState<string | null>(null);

  useEffect(() => {
    async function loadAssets() {
      try {
        const data = await getAssets();

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
  }, []);

  const filteredAssets = useMemo(() => {
    const query = search
      .trim()
      .toLowerCase();

    if (!query) {
      return assets;
    }

    return assets.filter((asset) => {
      return (
        asset.name
          .toLowerCase()
          .includes(query) ||
        asset.id
          .toLowerCase()
          .includes(query) ||
        asset.asset_type
          .toLowerCase()
          .includes(query)
      );
    });
  }, [assets, search]);

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
              Search and inspect resources represented
              in the security graph.
            </p>
          </div>

          <input
            className="inventory-search"
            type="search"
            placeholder="Search assets..."
            value={search}
            onChange={(event) =>
              setSearch(event.target.value)
            }
          />
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
              No assets match your search.
            </div>
          )}
        </div>
      </section>
    </>
  );
}


export default Inventory;
