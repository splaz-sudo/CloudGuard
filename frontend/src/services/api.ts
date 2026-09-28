import type {
  AttackPath,
  CloudAsset,
  ComplianceReport,
  Finding,
  IdentityRisk,
  NetworkRisk,
  Overview,
  Relationship,
  SecurityReport,
} from "../types/cloudguard";


const API_BASE_URL = "";

const DEFAULT_TIMEOUT_MS = 10_000;


export class CloudGuardAPIError extends Error {
  status: number | null;
  requestId: string | null;

  constructor(
    message: string,
    status: number | null = null,
    requestId: string | null = null,
  ) {
    super(message);

    this.name = "CloudGuardAPIError";
    this.status = status;
    this.requestId = requestId;
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
          method: "GET",
          headers: {
            Accept: "application/json",
          },
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
        );
      }

      throw new CloudGuardAPIError(
        "Unable to connect to the CloudGuard API.",
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
      );
    }

    try {
      return await response.json() as T;
    } catch {
      throw new CloudGuardAPIError(
        "CloudGuard API returned invalid JSON.",
        response.status,
        requestId,
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