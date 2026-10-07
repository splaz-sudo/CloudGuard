import {
  useState,
  type CSSProperties,
  type KeyboardEvent,
} from "react";

import Icon from "../components/Icon";
import AwsScanPanel from "../components/AwsScanPanel";

import {
  Button,
  Select,
} from "../components/FormControls";

import {
  EmptyState,
  ErrorState,
  SkeletonLine,
} from "../components/StateBlock";

import {
  useScanContext,
} from "../context/ScanContext";

import {
  RiskBar,
} from "../components/visualization";

import type {
  ScanRecord,
} from "../types/cloudguard";

import "../styles/scans.css";


const LOCAL_LAB_SCENARIOS = [
  "public-ec2",
  "remediated-lab",
  "two-exposed-workloads",
  "broad-iam-role",
  "private-lab",
];


/* ------------------------------------------
   Helpers
   ------------------------------------------ */

function formatTimestamp(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });
}

function relativeTime(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "";
  const diffMs = Date.now() - date.getTime();
  if (diffMs < 0) return "just now";
  const minutes = Math.floor(diffMs / 60_000);
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;
  const months = Math.floor(days / 30);
  return `${months}mo ago`;
}


/* ------------------------------------------
   Page
   ------------------------------------------ */

function Scans() {
  const {
    scans,
    selectedScan,
    loading,
    error,
    refreshScans,
    selectScan,
    startLocalLabScan,
  } = useScanContext();

  const [mode, setMode] = useState<"local" | "aws">("local");
  const [scenario, setScenario] = useState(LOCAL_LAB_SCENARIOS[0]);
  const [starting, setStarting] = useState(false);

  async function runScan() {
    setStarting(true);
    await startLocalLabScan(scenario);
    setStarting(false);
  }

  const handleRun = () => {
    void runScan();
  };

  return (
    <div className="page">
      <header className="topbar">
        <div>
          <p className="eyebrow">SCAN HISTORY</p>
          <h2>Security Scans</h2>
          <p className="page-subtitle">
            Immutable point-in-time security snapshots. Scans are
            never overwritten; a changed environment produces a
            new scan.
          </p>
        </div>

        <div className="scan-run">
          <div
            className="scan-mode-toggle"
            role="group"
            aria-label="Scan mode"
          >
            <button
              type="button"
              className={mode === "local" ? "active" : ""}
              aria-pressed={mode === "local"}
              onClick={() => setMode("local")}
            >
              Local Lab
              <span className="scan-mode-sub">demo</span>
            </button>
            <button
              type="button"
              className={mode === "aws" ? "active" : ""}
              aria-pressed={mode === "aws"}
              onClick={() => setMode("aws")}
            >
              Real AWS
              <span className="scan-mode-sub">read-only</span>
            </button>
          </div>

          {mode === "local" && (
            <>
              <Select
                label="Local lab scenario"
                aria-label="Local lab scenario"
                options={LOCAL_LAB_SCENARIOS.map((name) => ({
                  value: name,
                  label: name,
                }))}
                value={scenario}
                onChange={setScenario}
              />

              <RunScanButton starting={starting} onRun={handleRun} />
            </>
          )}
        </div>
      </header>

      {mode === "aws" && <AwsScanPanel />}

      {loading ? (
        <ScansSkeleton />
      ) : error ? (
        <ErrorState
          error={error}
          resourceLabel="scan history"
          onRetry={() => {
            void refreshScans();
          }}
        />
      ) : scans.length === 0 ? (
        <EmptyState
          icon="scans"
          title="No scans recorded yet"
          body="Run a local lab scan to generate your first security snapshot, then select it to explore the findings."
          action={
            <RunScanButton starting={starting} onRun={handleRun} />
          }
        />
      ) : (
        <section style={{ "--i": 1 } as CSSProperties}>
          <div className="scans-table-head">
            <h3 className="section-title">Recorded scans</h3>
            <span className="badge badge-neutral no-dot">
              {scans.length} scan{scans.length === 1 ? "" : "s"}
            </span>
          </div>

          <div className="table-wrap">
            <div className="table-scroll">
              <table className="data-table scans-table">
                <thead>
                  <tr>
                    <th>Environment</th>
                    <th>Scanned</th>
                    <th>Status</th>
                    <th>Highest risk</th>
                    <th className="num">Assets</th>
                    <th className="num">Findings</th>
                    <th className="num">Paths</th>
                    <th>Scan ID</th>
                  </tr>
                </thead>

                <tbody>
                  {scans.map((record) => (
                    <ScanRow
                      key={record.scan_id}
                      record={record}
                      selected={
                        selectedScan?.scan_id === record.scan_id
                      }
                      onSelect={() => selectScan(record.scan_id)}
                    />
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </section>
      )}
    </div>
  );
}


/* ------------------------------------------
   Row + controls
   ------------------------------------------ */

function RunScanButton({
  starting,
  onRun,
}: {
  starting: boolean;
  onRun: () => void;
}) {
  return (
    <Button
      variant="primary"
      loading={starting}
      onClick={onRun}
    >
      {!starting && <Icon name="play" size={14} />}
      {starting ? "Scanning…" : "Run Scan"}
    </Button>
  );
}


function ScanRow({
  record,
  selected,
  onSelect,
}: {
  record: ScanRecord;
  selected: boolean;
  onSelect: () => void;
}) {
  const { getSourceLabel, getStatusLabel } = useScanContext();

  const clickable =
    record.status === "completed"
    || record.status === "partial";

  const status = getStatusLabel(record.status);
  const statusBadge =
    status.variant === "error" ? "danger" : status.variant;

  const ago = relativeTime(record.created_at);

  function handleKeyDown(
    event: KeyboardEvent<HTMLTableRowElement>,
  ) {
    if (!clickable) return;
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      onSelect();
    }
  }

  const rowClass = [
    clickable ? "clickable" : "",
    selected ? "row-selected" : "",
  ].filter(Boolean).join(" ");

  return (
    <tr
      className={rowClass || undefined}
      onClick={clickable ? onSelect : undefined}
      onKeyDown={handleKeyDown}
      tabIndex={clickable ? 0 : undefined}
      role={clickable ? "button" : undefined}
      aria-pressed={clickable ? selected : undefined}
      aria-label={
        clickable ? `Select scan ${record.scan_id}` : undefined
      }
      title={
        clickable
          ? "Select this scan"
          : record.error_message ?? "Scan did not complete"
      }
    >
      <td>
        <div className="scan-env">
          <span className="scan-env-name">{record.environment}</span>
          <span className={`scan-source-badge ${record.source}`}>
            {getSourceLabel(record.source)}
          </span>
        </div>
      </td>

      <td>
        <span className="scan-time">
          {formatTimestamp(record.created_at)}
        </span>
        {ago && <span className="scan-time-rel">{ago}</span>}
      </td>

      <td>
        <span className={`badge badge-${statusBadge}`}>
          {status.label}
        </span>
      </td>

      <td>
        <RiskBar
          score={record.highest_risk}
          max={100}
          showValue={true}
          showLabel={false}
          height={6}
          width="100%"
        />
      </td>

      <td className="cell-num">{record.asset_count}</td>
      <td className="cell-num">{record.finding_count}</td>
      <td className="cell-num">{record.attack_path_count}</td>

      <td className="scan-id-cell">
        <span
          className="mono scan-id truncate"
          title={record.scan_id}
        >
          {record.scan_id}
        </span>
      </td>
    </tr>
  );
}


function ScansSkeleton() {
  return (
    <div
      className="table-wrap scans-skeleton"
      style={{ "--i": 1 } as CSSProperties}
      aria-hidden="true"
    >
      {Array.from({ length: 6 }, (_, i) => (
        <SkeletonLine
          key={i}
          height={14}
          width={i === 0 ? "40%" : "100%"}
        />
      ))}
    </div>
  );
}


export default Scans;
