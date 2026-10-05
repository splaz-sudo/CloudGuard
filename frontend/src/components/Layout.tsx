import {
  NavLink,
  Outlet,
} from "react-router-dom";

import Icon, { type IconName } from "./Icon";

import { useScanContext } from "../context/ScanContext";


type NavItem = {
  to: string;
  label: string;
  icon: IconName;
  end?: boolean;
};


const NAV_ITEMS: NavItem[] = [
  { to: "/", label: "Overview", icon: "overview", end: true },
  { to: "/scans", label: "Scans", icon: "scans" },
  { to: "/compare", label: "Compare", icon: "swap" },
  { to: "/inventory", label: "Inventory", icon: "inventory" },
  { to: "/attack-paths", label: "Attack Paths", icon: "paths" },
  { to: "/identity", label: "Identity", icon: "identity" },
  { to: "/network", label: "Network", icon: "network" },
  { to: "/findings", label: "Findings", icon: "findings" },
  { to: "/remediations", label: "Remediate", icon: "remediate" },
  { to: "/compliance", label: "Compliance", icon: "shield" },
  { to: "/coverage", label: "Coverage", icon: "coverage" },
  { to: "/reports", label: "Reports", icon: "reports" },
];


function Layout() {
  return (
    <div className="app-shell">
      <a className="skip-link" href="#main">
        Skip to content
      </a>

      <aside className="sidebar">
        <div className="brand">
          <div
            className="brand-mark"
            aria-hidden="true"
          >
            <Icon name="shield" size={20} />
          </div>

          <div className="brand-text">
            <h1>CloudGuard</h1>
            <span>Cloud Security</span>
          </div>
        </div>

        <ScanSelector />

        <nav
          className="navigation"
          aria-label="Primary"
        >
          {NAV_ITEMS.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({
                isActive,
              }) =>
                `nav-item${
                  isActive ? " active" : ""
                }`
              }
            >
              <Icon name={item.icon} size={16} />
              <span>{item.label}</span>
            </NavLink>
          ))}
        </nav>

        <div className="sidebar-footer">
          <span
            className="status-dot"
            aria-hidden="true"
          />
          <div className="sidebar-footer-text">
            <strong>Analysis Engine</strong>
            <span>Read-only access</span>
          </div>
        </div>
      </aside>

      <main className="dashboard" id="main">
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

  const isLab =
    selectedScan.source === "local_lab";

  return (
    <div className="scan-selector">
      <label
        className="scan-selector-label"
        htmlFor="scan-selector"
      >
        Viewing scan
      </label>

      <div className="scan-selector-control">
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
      </div>

      <div className="scan-selector-meta">
        <span
          className={
            `scan-source-badge ${
              isLab ? "local_lab" : "aws"
            }`
          }
        >
          {isLab ? "LOCAL LAB" : "AWS SCAN"}
        </span>
        <span className="scan-selector-id mono">
          {selectedScan.scan_id.slice(0, 13)}
        </span>
      </div>
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
