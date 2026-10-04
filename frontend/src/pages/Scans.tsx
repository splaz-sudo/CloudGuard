import { useState } from "react";
import { useNavigate } from "react-router-dom";

import { useScanContext } from "../context/ScanContext";

import type {
  ScanRecord,
} from "../types/cloudguard";


const LOCAL_LAB_SCENARIOS = [
  "public-ec2",
  "remediated-lab",
  "two-exposed-workloads",
  "broad-iam-role",
  "private-lab",
];


function Scans() {
  const {
    scans,
    loading,
    error,
    refreshScans,
    selectScan,
    startLocalLabScan,
  } = useScanContext();

  const navigate = useNavigate();

  const [scenario, setScenario] =
    useState("public-ec2");

  const [starting, setStarting] =
    useState(false);


  async function runScan() {
    setStarting(true);

    await startLocalLabScan(scenario);

    setStarting(false);
  }


  function openScan(scanId: string) {
    selectScan(scanId);
    navigate("/");
  }


  if (loading) {
    return (
      <section className="page-state">
        Loading scan history...
      </section>
    );
  }


  if (error) {
    return (
      <section className="page-state error-message">
        <div>
          <h2>
            CloudGuard API unavailable
          </h2>

          <p>
            Scan history could not be loaded.
          </p>

          <button
            type="button"
            onClick={() => {
              void refreshScans();
            }}
          >
            Retry
          </button>
        </div>
      </section>
    );
  }


  return (
    <>
      <header className="topbar">
        <div>
          <p className="eyebrow">
            SCAN HISTORY
          </p>

          <h2>Security Scans</h2>

          <p className="subtitle">
            Immutable point-in-time security
            snapshots. Scans are never
            overwritten; a changed environment
            produces a new scan.
          </p>
        </div>

        <div className="environment-badge">
          {scans.length} SCANS
        </div>
      </header>

      <section className="panel scan-run-panel">
        <div className="scan-run-controls">
          <label htmlFor="scenario-select">
            LOCAL LAB SCENARIO
          </label>

          <select
            id="scenario-select"
            value={scenario}
            onChange={(event) => {
              setScenario(
                event.target.value,
              );
            }}
          >
            {LOCAL_LAB_SCENARIOS.map(
              (name) => (
                <option
                  key={name}
                  value={name}
                >
                  {name}
                </option>
              ),
            )}
          </select>

          <button
            type="button"
            className="simulate-button"
            disabled={starting}
            onClick={() => {
              void runScan();
            }}
          >
            {starting
              ? "SCANNING..."
              : "RUN SCAN"}
          </button>
        </div>
      </section>

      <section className="panel">
        {scans.length === 0 ? (
          <p className="details-text">
            No scans have been recorded yet.
          </p>
        ) : (
          <div className="scan-table-wrapper">
            <table className="scan-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Source</th>
                  <th>Environment</th>
                  <th>Status</th>
                  <th>Highest Risk</th>
                  <th>Assets</th>
                  <th>Findings</th>
                  <th>Paths</th>
                  <th>Scan ID</th>
                </tr>
              </thead>

              <tbody>
                {scans.map((record) => (
                  <ScanRow
                    key={record.scan_id}
                    record={record}
                    onOpen={() => {
                      openScan(
                        record.scan_id,
                      );
                    }}
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  );
}


function ScanRow({
  record,
  onOpen,
}: {
  record: ScanRecord;
  onOpen: () => void;
}) {
  const clickable =
    record.status === "completed"
    || record.status === "partial";

  return (
    <tr
      className={
        clickable
          ? "scan-row clickable"
          : "scan-row"
      }
      onClick={() => {
        if (clickable) {
          onOpen();
        }
      }}
      title={
        clickable
          ? "Open this scan"
          : record.error_message
            ?? "Scan did not complete"
      }
    >
      <td>
        {record.created_at
          .replace("T", " ")
          .slice(0, 16)}
      </td>

      <td>
        <span
          className={
            `scan-source-badge ${
              record.source
            }`
          }
        >
          {record.source === "local_lab"
            ? "LOCAL LAB"
            : "AWS"}
        </span>
      </td>

      <td>{record.environment}</td>

      <td>
        <span
          className={
            `scan-status ${record.status}`
          }
        >
          {record.status.toUpperCase()}
        </span>
      </td>

      <td>
        <strong>
          {record.highest_risk}
        </strong>
      </td>

      <td>{record.asset_count}</td>

      <td>{record.finding_count}</td>

      <td>{record.attack_path_count}</td>

      <td>
        <code>
          {record.scan_id.slice(0, 17)}
        </code>
      </td>
    </tr>
  );
}


export default Scans;
