/**
 * Standardized loading / empty / error state blocks.
 *
 * Every page renders these instead of inventing its own
 * page-state markup, so failures look and read the same
 * everywhere and never mislabel a 404 as an API outage.
 */

import Icon, { type IconName } from "./Icon";

import {
  CloudGuardAPIError,
  describeApiError,
} from "../services/api";


export function LoadingState({
  label = "Loading…",
  compact = false,
}: {
  label?: string;
  compact?: boolean;
}) {
  return (
    <div
      className={
        `state-block state-loading${
          compact ? " compact" : ""
        }`
      }
      role="status"
      aria-live="polite"
    >
      <span className="state-spinner" />
      <p>{label}</p>
    </div>
  );
}


export function EmptyState({
  icon = "info",
  title,
  body,
  action,
}: {
  icon?: IconName;
  title: string;
  body?: string;
  action?: React.ReactNode;
}) {
  return (
    <div className="state-block state-empty">
      <span className="state-icon">
        <Icon name={icon} size={22} />
      </span>
      <h3>{title}</h3>
      {body ? <p>{body}</p> : null}
      {action}
    </div>
  );
}


export function ErrorState({
  error,
  resourceLabel = "data",
  onRetry,
  retrying = false,
}: {
  error: CloudGuardAPIError;
  /** e.g. "findings", "scan history" */
  resourceLabel?: string;
  onRetry?: () => void;
  retrying?: boolean;
}) {
  const copy = describeApiError(
    error,
    resourceLabel,
  );

  return (
    <div
      className="state-block state-error"
      role="alert"
    >
      <span className="state-icon danger">
        <Icon name="alert" size={22} />
      </span>

      <h3>{copy.title}</h3>
      <p>{copy.message}</p>

      {error.status && error.kind !== "network" ? (
        <p className="state-meta">
          HTTP status: {error.status}
        </p>
      ) : null}

      {error.requestId ? (
        <p className="state-meta">
          Request ID:{" "}
          <code className="mono">
            {error.requestId}
          </code>
        </p>
      ) : null}

      {onRetry ? (
        <button
          type="button"
          className="btn btn-secondary"
          onClick={onRetry}
          disabled={retrying}
        >
          <Icon name="refresh" size={14} />
          {retrying ? "Retrying…" : "Retry"}
        </button>
      ) : null}
    </div>
  );
}


/**
 * Inline notice for partial/degraded data (e.g. one
 * collector failed but the rest loaded).
 */
export function PartialNotice({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <div
      className="state-block state-partial"
      role="note"
    >
      <Icon name="info" size={15} />
      <div>{children}</div>
    </div>
  );
}


/* ---------- Skeletons ---------- */

export function SkeletonLine({
  width = "100%",
  height = 12,
}: {
  width?: string | number;
  height?: number;
}) {
  return (
    <span
      className="skeleton"
      style={{
        width,
        height,
        display: "block",
      }}
    />
  );
}


export function SkeletonCard({
  lines = 3,
}: {
  lines?: number;
}) {
  return (
    <div className="skeleton-card" aria-hidden="true">
      {Array.from({ length: lines }, (_, i) => (
        <SkeletonLine
          key={i}
          width={i === 0 ? "45%" : "100%"}
        />
      ))}
    </div>
  );
}
