import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import {
  CloudGuardAPIError,
  isTransientStatus,
} from "../services/api";

/**
 * Hook state for API queries.
 */
export interface ApiQueryState<T> {
  data: T | null;
  loading: boolean;
  error: CloudGuardAPIError | null;
  retry: () => void;
  refetch: () => void;
}

/**
 * Lightweight API query hook.
 * Provides consistent loading/error/retry patterns across all pages.
 * Backend remains the source of truth - React only handles presentation.
 */
export function useApiQuery<T>(
  fetcher: () => Promise<T>,
  deps: readonly unknown[] = [],
  options: {
    immediate?: boolean;
    retryCount?: number;
    retryDelay?: number;
  } = {},
): ApiQueryState<T> {
  const { immediate = true, retryCount = 3, retryDelay = 1000 } = options;

  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<CloudGuardAPIError | null>(null);

  const attemptRef = useRef(0);
  const requestRef = useRef(0);
  const mountedRef = useRef(true);
  const fetcherRef = useRef(fetcher);

  // Keep fetcher reference updated
  useEffect(() => {
    fetcherRef.current = fetcher;
  }, [fetcher]);

  const executeFetch = useCallback(async (isRetry = false) => {
    if (!mountedRef.current) return;

    const requestId = ++requestRef.current;

    if (!isRetry) {
      // Start every new request from a clean slate: clearing both error and
      // data guarantees the UI can never render a stale payload beneath a
      // newer request's error (or vice versa).
      setLoading(true);
      setError(null);
      setData(null);
    }

    try {
      const result = await fetcherRef.current();
      if (!mountedRef.current || requestRef.current !== requestId) return;
      setData(result);
      setLoading(false);
      setError(null);
      if (isRetry) {
        attemptRef.current = 0;
      }
    } catch (err) {
      if (!mountedRef.current || requestRef.current !== requestId) return;

      if (err instanceof CloudGuardAPIError) {
        setError(err);

        // Retry logic for transient errors (network drops,
        // rate limiting, overloaded backend, and the startup
        // race where a scan briefly 404s before its snapshot
        // is readable). Bounded by retryCount with backoff.
        if (
          isRetry === false &&
          attemptRef.current < retryCount &&
          isTransientStatus(err.status)
        ) {
          attemptRef.current += 1;
          const scheduledFor = attemptRef.current;
          setTimeout(() => {
            // Only run the retry if no newer request has started since.
            if (mountedRef.current && requestRef.current === requestId) {
              executeFetch(true);
            }
          }, retryDelay * scheduledFor);
          return;
        }
      } else {
        setError(new CloudGuardAPIError("Unknown error occurred"));
      }

      setLoading(false);
    }
  }, [retryCount, retryDelay]);

  const refetch = useCallback(() => {
    attemptRef.current = 0;
    executeFetch(false);
  }, []);

  const retry = useCallback(() => {
    attemptRef.current = 0;
    executeFetch(false);
  }, []);

  useEffect(() => {
    if (immediate) {
      executeFetch(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, attemptRef.current]);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  return {
    data,
    loading,
    error,
    retry,
    refetch,
  };
}

/**
 * Hook for mutations (POST/PUT/DELETE) with consistent loading/error handling.
 */
export interface MutationState<TData, TVariables> {
  mutate: (variables: TVariables) => Promise<TData | null>;
  loading: boolean;
  error: CloudGuardAPIError | null;
  data: TData | null;
}

export function useMutation<TData, TVariables>(
  mutationFn: (variables: TVariables) => Promise<TData>,
): MutationState<TData, TVariables> {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<CloudGuardAPIError | null>(null);
  const [data, setData] = useState<TData | null>(null);

  const mutate = useCallback(
    async (variables: TVariables) => {
      setLoading(true);
      setError(null);

      try {
        const result = await mutationFn(variables);
        setData(result);
        setLoading(false);
        return result;
      } catch (err) {
        setLoading(false);
        if (err instanceof CloudGuardAPIError) {
          setError(err);
        } else {
          setError(new CloudGuardAPIError("Mutation failed"));
        }
        return null;
      }
    }, [mutationFn]);

  return { mutate, loading, error, data };
}

/**
 * Hook for scan-scoped data fetching.
 * Automatically uses the currently selected scan from context.
 */
export function useScanQuery<T>(
  fetcher: (scanId: string) => Promise<T>,
  scanId: string | null,
  options: {
    immediate?: boolean;
    retryCount?: number;
    retryDelay?: number;
    enabled?: boolean;
  } = {},
): ApiQueryState<T> {
  const { immediate = true, retryCount = 3, retryDelay = 1000, enabled = true } = options;

  return useApiQuery(
    () => {
      if (!scanId) {
        throw new CloudGuardAPIError("No scan selected");
      }
      return fetcher(scanId);
    },
    [scanId, enabled],
    { immediate: immediate && enabled, retryCount, retryDelay },
  );
}

/**
 * Debounced search hook for inventory search.
 */
export function useDebouncedSearch<T>(
  items: T[],
  searchFn: (item: T, query: string) => boolean,
  delay: number = 300,
): [string, T[]] {
  const [query] = useState("");
  const [debouncedQuery, setDebouncedQuery] = useState("");

  useEffect(() => {
    const timer = setTimeout(() => setDebouncedQuery(query), delay);
    return () => clearTimeout(timer);
  }, [query, delay]);

  const filtered = useMemo(
    () => (debouncedQuery ? items.filter((item) => searchFn(item, debouncedQuery)) : items),
    [items, debouncedQuery, searchFn],
  );

  return [query, filtered];
}

/**
 * Hook for paginated data.
 */
export interface PaginatedResult<T> {
  data: T[];
  loading: boolean;
  error: CloudGuardAPIError | null;
  page: number;
  pageSize: number;
  total: number;
  totalPages: number;
  goToPage: (page: number) => void;
  nextPage: () => void;
  prevPage: () => void;
  refetch: () => void;
}

export function usePaginatedQuery<T>(
  fetcher: (page: number, pageSize: number) => Promise<{ items: T[]; total: number }>,
  initialPageSize: number = 20,
): PaginatedResult<T> {
  const [page, setPage] = useState(1);
  const [pageSize] = useState(initialPageSize);
  const [total, setTotal] = useState(0);
  const [data, setData] = useState<T[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<CloudGuardAPIError | null>(null);

  const fetchPage = useCallback(
    async (pageNum: number) => {
      setLoading(true);
      setError(null);

      try {
        const result = await fetcher(pageNum, pageSize);
        setData(result.items);
        setTotal(result.total);
        setPage(pageNum);
        setLoading(false);
      } catch (err) {
        setLoading(false);
        if (err instanceof CloudGuardAPIError) {
          setError(err);
        } else {
          setError(new CloudGuardAPIError("Failed to fetch data"));
        }
      }
    }, [fetcher, pageSize]);

  const goToPage = useCallback(
    (pageNum: number) => {
      if (pageNum >= 1 && pageNum <= Math.ceil(total / pageSize)) {
        fetchPage(pageNum);
      }
    }, [fetchPage, total, pageSize]);

  const nextPage = useCallback(() => {
    goToPage(page + 1);
  }, [goToPage, page]);

  const prevPage = useCallback(() => {
    goToPage(page - 1);
  }, [goToPage, page]);

  const totalPages = Math.ceil(total / pageSize);

  useEffect(() => {
    fetchPage(page);
  }, [fetchPage, page]);

  return {
    data,
    loading,
    error,
    page,
    pageSize,
    total,
    totalPages,
    goToPage,
    nextPage,
    prevPage,
    refetch: () => fetchPage(page),
  };
}

/**
 * Hook for infinite scrolling.
 */
export interface InfiniteScrollResult<T> {
  data: T[];
  loading: boolean;
  error: CloudGuardAPIError | null;
  hasMore: boolean;
  loadMore: () => void;
  refetch: () => void;
}

export function useInfiniteQuery<T>(
  fetcher: (cursor: string | null) => Promise<{ items: T[]; nextCursor: string | null }>,
): InfiniteScrollResult<T> {
  const [data, setData] = useState<T[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<CloudGuardAPIError | null>(null);
  const [cursor, setCursor] = useState<string | null>(null);
  const [hasMore, setHasMore] = useState(true);

  const loadMore = useCallback(async () => {
    if (loading || !hasMore) return;

    setLoading(true);
    setError(null);

    try {
      const result = await fetcher(cursor);
      setData((prev) => [...prev, ...result.items]);
      setCursor(result.nextCursor);
      setHasMore(!!result.nextCursor);
      setLoading(false);
    } catch (err) {
      setLoading(false);
      if (err instanceof CloudGuardAPIError) {
        setError(err);
      } else {
        setError(new CloudGuardAPIError("Failed to load more data"));
      }
    }
  }, [fetcher, cursor]);

  const refetch = useCallback(async () => {
    setData([]);
    setCursor(null);
    setHasMore(true);
    await loadMore();
  }, [loadMore]);

  return { data, loading, error, hasMore, loadMore, refetch };
}

/**
 * Hook for managing scan selection state.
 */
export interface ScanSelectionState {
  selectedScanId: string | null;
  setSelectedScan: (scanId: string | null) => void;
  clearSelection: () => void;
}

export function useScanSelection(
  _scans: { scan_id: string }[],
): ScanSelectionState {
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);

  const setSelectedScan = useCallback(
    (scanId: string | null) => {
      setSelectedScanId(scanId);
    },
    [],
  );

  const clearSelection = useCallback(() => {
    setSelectedScanId(null);
  }, []);

  return {
    selectedScanId,
    setSelectedScan,
    clearSelection,
  };
}