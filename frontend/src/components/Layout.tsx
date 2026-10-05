import {
  NavLink,
  Outlet,
} from "react-router-dom";

import { useScanContext } from "../context/ScanContext";


function Layout() {
  const navClass = ({
    isActive,
  }: {
    isActive: boolean;
  }) =>
    `nav-item ${isActive ? "active" : ""}`;

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">
            CG
          </div>

          <div>
            <h1>CloudGuard</h1>
            <span>Cloud Security</span>
          </div>
        </div>

        <ScanSelector />

        <nav className="navigation">
          <NavLink
            to="/"
            end
            className={navClass}
          >
            Overview
          </NavLink>

          <NavLink
            to="/scans"
            className={navClass}
          >
            Scans
          </NavLink>

          <NavLink
            to="/compare"
            className={navClass}
          >
            Compare
          </NavLink>

          <NavLink
            to="/inventory"
            className={navClass}
          >
            Inventory
          </NavLink>

          <NavLink
            to="/attack-paths"
            className={navClass}
          >
            Attack Paths
          </NavLink>

          <NavLink
            to="/identity"
            className={navClass}
          >
            Identity
          </NavLink>

          <NavLink
            to="/network"
            className={navClass}
          >
            Network
          </NavLink>

          <NavLink
            to="/findings"
            className={navClass}
          >
            Findings
          </NavLink>

          <NavLink
            to="/remediations"
            className={navClass}
          >
            Remediate
          </NavLink>

          <NavLink
            to="/compliance"
            className={navClass}
          >
            Compliance
          </NavLink>

          <NavLink
            to="/coverage"
            className={navClass}
          >
            Coverage
          </NavLink>

          <NavLink
            to="/reports"
            className={navClass}
          >
            Reports
          </NavLink>
        </nav>

        <div className="sidebar-footer">
          <span className="status-dot" />

          <div>
            <strong>
              Analysis Engine
            </strong>

            <span>
              Read-only
            </span>
          </div>
        </div>
      </aside>

      <main className="dashboard">
        <Outlet />
      </main>
    </div>
  );
}


function ScanSelector() {
  const {
    scans,
    selectedScan,
    selectScan,
  } = useScanContext();

  if (!selectedScan) {
    return null;
  }

  return (
    <div className="scan-selector">
      <label htmlFor="scan-selector">
        VIEWING SCAN
      </label>

      <select
        id="scan-selector"
        value={selectedScan.scan_id}
        onChange={(event) => {
          selectScan(event.target.value);
        }}
      >
        {scans.map((record) => (
          <option
            key={record.scan_id}
            value={record.scan_id}
          >
            {formatScanOption(record)}
          </option>
        ))}
      </select>

      <span
        className={
          `scan-source-badge ${
            selectedScan.source
          }`
        }
      >
        {selectedScan.source === "local_lab"
          ? "LOCAL LAB"
          : "AWS SCAN"}
      </span>
    </div>
  );
}


function formatScanOption(
  record: {
    scan_id: string;
    environment: string;
    created_at: string;
    status: string;
  },
) {
  const timestamp = record.created_at
    .replace("T", " ")
    .slice(5, 16);

  return (
    `${record.environment} · `
    + `${timestamp} · `
    + record.scan_id.slice(0, 13)
  );
}


export default Layout;