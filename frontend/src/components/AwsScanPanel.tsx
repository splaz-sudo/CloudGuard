import { useState } from "react";

import Icon from "./Icon";

import { Button } from "./FormControls";

import {
  CloudGuardAPIError,
  describeApiError,
} from "../services/api";

import { useScanContext } from "../context/ScanContext";

import type { ScanRecord } from "../types/cloudguard";


const REGION_PATTERN = /^[a-z]{2}(-[a-z]+)+-\d$/;


type Outcome =
  | { kind: "none" }
  | { kind: "record"; record: ScanRecord }
  | { kind: "error"; message: string };


/** Parse "us-east-1, eu-west-1" into a de-duplicated list. */
function parseRegions(input: string): {
  regions: string[];
  invalid: string[];
} {
  const parts = input
    .split(/[\s,]+/)
    .map((part) => part.trim().toLowerCase())
    .filter(Boolean);

  const unique = [...new Set(parts)];

  return {
    regions: unique.filter((r) => REGION_PATTERN.test(r)),
    invalid: unique.filter((r) => !REGION_PATTERN.test(r)),
  };
}


/**
 * Real AWS assessment launcher.
 *
 * The browser never sees or sends credentials: the server resolves them from
 * its own boto3 credential chain and only issues read-only Describe/List/Get
 * calls. This panel only chooses regions and requires explicit confirmation.
 */
function AwsScanPanel() {
  const { startAwsScan } = useScanContext();

  const [regionText, setRegionText] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [running, setRunning] = useState(false);
  const [outcome, setOutcome] = useState<Outcome>({ kind: "none" });

  const { regions, invalid } = parseRegions(regionText);
  const canRun = confirmed && invalid.length === 0 && !running;

  async function run() {
    if (!canRun) return;

    setRunning(true);
    setOutcome({ kind: "none" });

    try {
      const record = await startAwsScan(regions);
      setOutcome({ kind: "record", record });
    } catch (error) {
      const api =
        error instanceof CloudGuardAPIError
          ? error
          : new CloudGuardAPIError(
              error instanceof Error
                ? error.message
                : "The AWS scan request failed.",
            );

      setOutcome({
        kind: "error",
        message: describeApiError(api, "the AWS scan").message,
      });
    } finally {
      setRunning(false);
    }
  }

  return (
    <section
      className="panel aws-scan-panel"
      aria-label="Real AWS assessment"
    >
      <div className="panel-header">
        <div>
          <p className="eyebrow">REAL AWS ASSESSMENT</p>
          <h3 className="panel-title">Scan a live AWS account</h3>
        </div>
        <span className="badge badge-success no-dot">
          <Icon name="shield" size={11} />
          READ-ONLY
        </span>
      </div>

      <div className="panel-body aws-scan-body">
        <ul className="aws-scan-notes">
          <li>
            Uses the AWS credentials configured on the CloudGuard
            server (profile, environment, or IAM role). Credentials
            are never shown in this UI, sent from the browser, or
            stored in scan history.
          </li>
          <li>
            Only read-only <code>Describe</code>, <code>List</code>
            {" "}and <code>Get</code> API calls are made. No AWS
            resources are created, changed, or deleted.
          </li>
          <li>
            The account is identified from AWS STS
            {" "}(<code>GetCallerIdentity</code>). If that check
            fails the scan stops and nothing is recorded as a
            result.
          </li>
        </ul>

        <label className="aws-scan-field">
          <span className="aws-scan-label">
            Regions <span className="aws-scan-hint">(optional)</span>
          </span>
          <input
            type="text"
            className="input"
            placeholder="us-east-1, eu-west-1"
            value={regionText}
            onChange={(event) => setRegionText(event.target.value)}
            aria-invalid={invalid.length > 0}
            aria-describedby="aws-region-help"
            autoComplete="off"
            spellCheck={false}
          />
          <span
            id="aws-region-help"
            className={
              invalid.length > 0
                ? "aws-scan-hint aws-scan-error"
                : "aws-scan-hint"
            }
          >
            {invalid.length > 0
              ? `Not a valid AWS region: ${invalid.join(", ")}`
              : "Leave blank to use the server's configured regions."}
          </span>
        </label>

        <label className="aws-scan-confirm">
          <input
            type="checkbox"
            checked={confirmed}
            onChange={(event) => setConfirmed(event.target.checked)}
          />
          <span>
            I understand this runs read-only API calls against the
            real AWS account configured on the server.
          </span>
        </label>

        <div className="aws-scan-actions">
          <Button
            variant="primary"
            loading={running}
            disabled={!canRun}
            onClick={() => {
              void run();
            }}
          >
            {!running && <Icon name="play" size={14} />}
            {running ? "Scanning AWS…" : "Run read-only AWS scan"}
          </Button>
        </div>

        <AwsOutcome outcome={outcome} />
      </div>
    </section>
  );
}


function AwsOutcome({ outcome }: { outcome: Outcome }) {
  if (outcome.kind === "none") return null;

  if (outcome.kind === "error") {
    return (
      <div className="aws-scan-result is-failed" role="alert">
        <strong>AWS scan could not be started.</strong>
        <p>{outcome.message}</p>
      </div>
    );
  }

  const { record } = outcome;

  if (record.status === "failed") {
    return (
      <div className="aws-scan-result is-failed" role="alert">
        <strong>AWS scan failed.</strong>
        <p>
          {record.error_message
            ?? "The scan did not complete."}
        </p>
        <p className="aws-scan-hint">
          No findings were recorded for this scan, so nothing
          here should be read as "no risk found".
        </p>
      </div>
    );
  }

  const partial = record.status === "partial";

  return (
    <div
      className={
        partial
          ? "aws-scan-result is-partial"
          : "aws-scan-result is-ok"
      }
      role="status"
    >
      <strong>
        {partial
          ? "AWS scan completed with limited coverage."
          : "AWS scan completed."}
      </strong>
      <p>
        Account{" "}
        <code>{record.account_identifier ?? "unknown"}</code> ·{" "}
        {record.asset_count} assets · {record.finding_count} findings ·{" "}
        {record.attack_path_count} attack paths
      </p>
      {partial && record.failed_collectors.length > 0 && (
        <p className="aws-scan-hint">
          Not assessed (collector failed):{" "}
          {record.failed_collectors.join(", ")}. Results below
          cover only what could be read.
        </p>
      )}
    </div>
  );
}


export default AwsScanPanel;
