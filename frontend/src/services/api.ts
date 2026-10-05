import type {
  AttackPath,
  CloudAsset,
  CollectorResult,
  ComparisonResult,
  ComplianceReport,
  Finding,
  IdentityRisk,
  NetworkRisk,
  Overview,
  Relationship,
  Remediation,
  RemediationVerification,
  ScanCreateRequest,
  ScanRecord,
  SecurityReport,
  SimulationResult,
} from "../types/cloudguard";


const API_BASE_URL = "";

const DEFAULT_TIMEOUT_MS = 10_000;


export type ApiErrorKind =
  | "network"      // API unreachable (connection refused, DNS, offline)
  | "timeout"      // request aborted by the client timeout
  | "not_found"    // 404: the requested resource does not exist
  | "rate_limited" // 429: too many requests
  | "server"       // 5xx: backend failed to serve the request
  | "client"       // other 4xx: the request itself was rejected
  | "parse"        // response was not the JSON we asked for
  | "unknown";

export class CloudGuardAPIError extends Error {
  status: number | null;
  requestId: string | null;
  kind: ApiErrorKind;

  constructor(
    message: string,
    status: number | null = null,
    requestId: string | null = null,
    kind: ApiErrorKind | null = null,
  ) {
    super(message);

    this.name = "CloudGuardAPIError";
    this.status = status;
    this.requestId = requestId;
    this.kind = kind ?? classifyStatus(status);
  }
}


function classifyStatus(
  status: number | null,
): ApiErrorKind {
  if (status === null) return "unknown";
  if (status === 0) return "network";
  if (status === 404) return "not_found";
  if (status === 429) return "rate_limited";
  if (status >= 500) return "server";
  if (status >= 400) return "client";
  return "unknown";
}


/**
 * Statuses that may succeed on a bounded automatic
 * retry: transient network drops, rate limiting,
 * overloaded backend, scan-still-starting (409) and
 * the startup race where a scan record briefly
 * appears before its snapshot is readable (404).
 */
export function isTransientStatus(
  status: number | null,
): boolean {
  return (
    status === 0
    || status === 404
    || status === 408
    || status === 409
    || status === 425
    || status === 429
    || (status !== null && status >= 500)
  );
}


/**
 * User-facing copy for an API failure. Never claims
 * the whole API is down when a single resource 404s.
 */
export function describeApiError(
  error: CloudGuardAPIError,
  resourceLabel: string,
): { title: string; message: string } {
  switch (error.kind) {
    case "network":
      return {
        title: "CloudGuard API unreachable",
        message:
          "No response from the CloudGuard API. "
          + "Check that the API service is running, "
          + "then retry.",
      };
    case "timeout":
      return {
        title: "Request timed out",
        message:
          `Loading ${resourceLabel} took too long. `
          + "The API may still be processing — retry "
          + "in a few seconds.",
      };
    case "not_found":
      return {
        title: "Data not found",
        message:
          `The requested ${resourceLabel} was not `
          + "found. The scan may have been removed or "
          + "may not have finished writing its results.",
      };
    case "rate_limited":
      return {
        title: "Too many requests",
        message:
          "CloudGuard is rate limiting requests. "
          + "Wait a moment, then retry.",
      };
    case "server":
      return {
        title: "CloudGuard API error",
        message:
          `The API failed while loading ${resourceLabel} `
          + `(HTTP ${error.status}). See the API log for `
          + "details.",
      };
    case "client":
      return {
        title: "Request rejected",
        message:
          `The API rejected the request for `
          + `${resourceLabel} (HTTP ${error.status}).`,
      };
    case "parse":
      return {
        title: "Unexpected response",
        message:
          `The API returned a response CloudGuard could `
          + `not read while loading ${resourceLabel}.`,
      };
    default:
      return {
        title: "Something went wrong",
        message:
          `Loading ${resourceLabel} failed. Please retry.`,
      };
  }
}


function getErrorMessage(
  error: unknown,
): string {
  if (error instanceof Error) {
    return error.message;
  }

  return "Unknown API error";
}


async function request<T>(
  endpoint: string,
  timeoutMs: number = DEFAULT_TIMEOUT_MS,
  method: "GET" | "POST" = "GET",
  body?: unknown,
): Promise<T> {
  const controller = new AbortController();

  const timeoutId = window.setTimeout(
    () => controller.abort(),
    timeoutMs,
  );

  try {
    let response: Response;

    try {
      response = await fetch(
        `${API_BASE_URL}${endpoint}`,
        {
          method,
          headers: {
            Accept: "application/json",
            ...(body !== undefined
              ? {
                  "Content-Type":
                    "application/json",
                }
              : {}),
          },
          ...(body !== undefined
            ? {
                body: JSON.stringify(body),
              }
            : {}),
          signal: controller.signal,
        },
      );
    } catch (error) {
      if (
        error instanceof DOMException
        && error.name === "AbortError"
      ) {
        throw new CloudGuardAPIError(
          "CloudGuard API request timed out.",
          0,
          null,
          "timeout",
        );
      }

      throw new CloudGuardAPIError(
        "Unable to connect to the CloudGuard API.",
        0,
        null,
        "network",
      );
    }

    const requestId = response.headers.get(
      "x-request-id",
    );

    if (!response.ok) {
      let message = (
        `CloudGuard API request failed `
        + `with status ${response.status}.`
      );

      try {
        const body = await response.json();

        if (
          body
          && typeof body === "object"
          && "error" in body
        ) {
          const errorBody = body.error;

          if (
            errorBody
            && typeof errorBody === "object"
            && "message" in errorBody
            && typeof errorBody.message === "string"
          ) {
            message = errorBody.message;
          }
        }

        if (
          body
          && typeof body === "object"
          && "detail" in body
          && typeof body.detail === "string"
        ) {
          message = body.detail;
        }
      } catch {
        // The API may return a non-JSON error
        // response. Keep the safe fallback message.
      }

      throw new CloudGuardAPIError(
        message,
        response.status,
        requestId,
      );
    }

    const contentType = response.headers.get(
      "content-type",
    );

    if (
      !contentType
      || !contentType.includes(
        "application/json",
      )
    ) {
      throw new CloudGuardAPIError(
        "CloudGuard API returned an unexpected response format.",
        response.status,
        requestId,
        "parse",
      );
    }

    try {
      return await response.json() as T;
    } catch {
      throw new CloudGuardAPIError(
        "CloudGuard API returned invalid JSON.",
        response.status,
        requestId,
        "parse",
      );
    }
  } catch (error) {
    if (error instanceof CloudGuardAPIError) {
      throw error;
    }

    throw new CloudGuardAPIError(
      getErrorMessage(error),
    );
  } finally {
    window.clearTimeout(timeoutId);
  }
}


export function getOverview(): Promise<Overview> {
  return request<Overview>(
    "/api/overview",
  );
}


export function getAssets(): Promise<CloudAsset[]> {
  return request<CloudAsset[]>(
    "/api/assets",
  );
}


export function getRelationships(): Promise<
  Relationship[]
> {
  return request<Relationship[]>(
    "/api/relationships",
  );
}


export function getFindings(): Promise<Finding[]> {
  return request<Finding[]>(
    "/api/findings",
  );
}


export function getAttackPaths(): Promise<
  AttackPath[]
> {
  return request<AttackPath[]>(
    "/api/attack-paths",
  );
}


export function getIdentityRisks(): Promise<
  IdentityRisk[]
> {
  return request<IdentityRisk[]>(
    "/api/identity-risks",
  );
}


export function getNetworkRisks(): Promise<
  NetworkRisk[]
> {
  return request<NetworkRisk[]>(
    "/api/network-risks",
  );
}


export function getCompliance(): Promise<
  ComplianceReport
> {
  return request<ComplianceReport>(
    "/api/compliance",
  );
}


export function getSecurityReport(): Promise<
  SecurityReport
> {
  return request<SecurityReport>(
    "/api/report",
  );
}


export function getRemediations(): Promise<
  Remediation[]
> {
  return request<Remediation[]>(
    "/api/remediations",
  );
}


export function getPrioritizedRemediations(): Promise<
  Remediation[]
> {
  return request<Remediation[]>(
    "/api/remediations/prioritized",
  );
}


export function simulateRemediation(
  remediationId: string,
): Promise<SimulationResult> {
  return request<SimulationResult>(
    "/api/remediations/"
      + `${encodeURIComponent(remediationId)}`
      + "/simulate",
    DEFAULT_TIMEOUT_MS,
    "POST",
  );
}


// ------------------------------------------
// Scan endpoints
// ------------------------------------------


export function createScan(
  payload: ScanCreateRequest,
): Promise<ScanRecord> {
  return request<ScanRecord>(
    "/api/scans",
    120_000,
    "POST",
    payload,
  );
}


export function listScans(): Promise<
  ScanRecord[]
> {
  return request<ScanRecord[]>("/api/scans");
}


export function getScan(
  scanId: string,
): Promise<ScanRecord> {
  return request<ScanRecord>(
    `/api/scans/${encodeURIComponent(scanId)}`,
  );
}


function scanUrl(
  scanId: string,
  suffix: string,
): string {
  return (
    "/api/scans/"
    + encodeURIComponent(scanId)
    + suffix
  );
}


export function getScanOverview(
  scanId: string,
): Promise<Overview> {
  return request<Overview>(
    scanUrl(scanId, "/overview"),
  );
}


export function getScanAssets(
  scanId: string,
): Promise<CloudAsset[]> {
  return request<CloudAsset[]>(
    scanUrl(scanId, "/assets"),
  );
}


export function getScanRelationships(
  scanId: string,
): Promise<Relationship[]> {
  return request<Relationship[]>(
    scanUrl(scanId, "/relationships"),
  );
}


export function getScanFindings(
  scanId: string,
): Promise<Finding[]> {
  return request<Finding[]>(
    scanUrl(scanId, "/findings"),
  );
}


export function getScanAttackPaths(
  scanId: string,
): Promise<AttackPath[]> {
  return request<AttackPath[]>(
    scanUrl(scanId, "/attack-paths"),
  );
}


export function getScanRemediations(
  scanId: string,
): Promise<Remediation[]> {
  return request<Remediation[]>(
    scanUrl(scanId, "/remediations"),
  );
}


export function getScanPrioritizedRemediations(
  scanId: string,
): Promise<Remediation[]> {
  return request<Remediation[]>(
    scanUrl(
      scanId,
      "/remediations/prioritized",
    ),
  );
}


export function simulateScanRemediation(
  scanId: string,
  remediationId: string,
): Promise<SimulationResult> {
  return request<SimulationResult>(
    scanUrl(
      scanId,
      "/remediations/"
        + encodeURIComponent(remediationId)
        + "/simulate",
    ),
    DEFAULT_TIMEOUT_MS,
    "POST",
  );
}


export function getScanIdentityRisks(
  scanId: string,
): Promise<IdentityRisk[]> {
  return request<IdentityRisk[]>(
    scanUrl(scanId, "/identity-risks"),
  );
}


export function getScanNetworkRisks(
  scanId: string,
): Promise<NetworkRisk[]> {
  return request<NetworkRisk[]>(
    scanUrl(scanId, "/network-risks"),
  );
}


export function getScanCompliance(
  scanId: string,
): Promise<ComplianceReport> {
  return request<ComplianceReport>(
    scanUrl(scanId, "/compliance"),
  );
}


export function getScanCollectorResults(
  scanId: string,
): Promise<CollectorResult[]> {
  return request<CollectorResult[]>(
    scanUrl(scanId, "/collector-results"),
  );
}


export function compareScans(
  scanA: string,
  scanB: string,
): Promise<ComparisonResult> {
  return request<ComparisonResult>(
    "/api/scans/compare/"
      + encodeURIComponent(scanA)
      + "/"
      + encodeURIComponent(scanB),
  );
}


export function verifyRemediation(
  scanA: string,
  remediationId: string,
  scanB: string,
): Promise<RemediationVerification> {
  return request<RemediationVerification>(
    scanUrl(
      scanA,
      "/remediations/"
        + encodeURIComponent(remediationId)
        + "/verify/"
        + encodeURIComponent(scanB),
    ),
  );
}