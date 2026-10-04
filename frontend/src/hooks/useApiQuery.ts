import {
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";

import {
  CloudGuardAPIError,
} from "../services/api";


type ApiQueryState<T> = {
  data: T | null;
  loading: boolean;
  error: CloudGuardAPIError | null;
  retry: () => void;
};


/**
 * Shared data-fetching hook for CloudGuard
 * pages: one loading/error/retry pattern
 * instead of a fetch-in-effect copy per page.
 * The backend remains the source of truth.
 */
export function useApiQuery<T>(
  fetcher: () => Promise<T>,
  dependencies: readonly unknown[],
): ApiQueryState<T> {
  const [data, setData] =
    useState<T | null>(null);

  const [loading, setLoading] =
    useState(true);

  const [error, setError] =
    useState<CloudGuardAPIError | null>(null);

  const [attempt, setAttempt] =
    useState(0);

  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;

    return () => {
      mounted.current = false;
    };
  }, []);

  // eslint-disable-next-line react-hooks/exhaustive-deps
  const load = useCallback(fetcher, [
    ...dependencies,
    attempt,
  ]);

  useEffect(() => {
    let cancelled = false;

    setLoading(true);
    setError(null);

    load()
      .then((result) => {
        if (
          !cancelled
          && mounted.current
        ) {
          setData(result);
          setLoading(false);
        }
      })
      .catch(
        (requestError: unknown) => {
          if (
            cancelled
            || !mounted.current
          ) {
            return;
          }

          if (
            requestError
            instanceof CloudGuardAPIError
          ) {
            setError(requestError);
          } else {
            setError(
              new CloudGuardAPIError(
                "Unable to load data "
                + "from the CloudGuard API.",
              ),
            );
          }

          setLoading(false);
        },
      );

    return () => {
      cancelled = true;
    };
  }, [load]);

  const retry = useCallback(() => {
    setAttempt(
      (current) => current + 1,
    );
  }, []);

  return {
    data,
    loading,
    error,
    retry,
  };
}
