import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

import {
  CloudGuardAPIError,
  createScan,
  listScans,
} from "../services/api";

import type {
  ScanRecord,
  ScanSource,
} from "../types/cloudguard";


type ScanContextValue = {
  scans: ScanRecord[];
  selectedScan: ScanRecord | null;
  loading: boolean;
  error: CloudGuardAPIError | null;
  refreshScans: () => Promise<void>;
  selectScan: (scanId: string) => void;
  startLocalLabScan: (
    environment?: string,
  ) => Promise<ScanRecord | null>;
  // Helper functions for UI display
  getSourceLabel: (source: ScanSource) => string;
  getStatusLabel: (status: string) => { label: string; variant: "success" | "warning" | "error" | "info" };
  getDataFreshness: (scan: ScanRecord) => string;
  isSimulation: (scan: ScanRecord | null) => boolean;
  isHistorical: (scan: ScanRecord | null, allScans: ScanRecord[]) => boolean;
};


const ScanContext = createContext<
  ScanContextValue | undefined
>(undefined);


export function ScanProvider({
  children,
}: {
  children: ReactNode;
}) {
  const [scans, setScans] =
    useState<ScanRecord[]>([]);

  const [selectedScanId, setSelectedScanId] =
    useState<string | null>(null);

  const [loading, setLoading] =
    useState(true);

  const [error, setError] =
    useState<CloudGuardAPIError | null>(null);


  const refreshScans =
    useCallback(async () => {
      try {
        let records = await listScans();

        if (records.length === 0) {
          await createScan({
            source: "local_lab",
          });

          records = await listScans();
        }

        setScans(records);

        setSelectedScanId((current) => {
          if (
            current
            && records.some(
              (record) =>
                record.scan_id === current,
            )
          ) {
            return current;
          }

          const firstCompleted =
            records.find(
              (record) =>
                record.status
                  === "completed"
                || record.status
                  === "partial",
            );

          return (
            firstCompleted?.scan_id
            ?? records[0]?.scan_id
            ?? null
          );
        });

        setError(null);
      } catch (requestError) {
        if (
          requestError
          instanceof CloudGuardAPIError
        ) {
          setError(requestError);
        }
      } finally {
        setLoading(false);
      }
    }, []);


  useEffect(() => {
    void refreshScans();
  }, [refreshScans]);


  const selectScan = useCallback(
    (scanId: string) => {
      setSelectedScanId(scanId);
    },
    [],
  );


  const startLocalLabScan = useCallback(
    async (
      environment?: string,
    ): Promise<ScanRecord | null> => {
      try {
        const record = await createScan({
          source: "local_lab",
          environment: environment ?? "",
        });

        await refreshScans();

        setSelectedScanId(
          record.scan_id,
        );

        return record;
      } catch (requestError) {
        if (
          requestError
          instanceof CloudGuardAPIError
        ) {
          setError(requestError);
        }

        return null;
      }
    },
    [refreshScans],
  );


  const selectedScan = useMemo(
    () =>
      scans.find(
        (record) =>
          record.scan_id
          === selectedScanId,
      ) ?? null,
    [scans, selectedScanId],
  );


  // Helper functions for clear UI labeling
  const getSourceLabel = (source: ScanSource): string => {
    switch (source) {
      case "local_lab":
        return "LOCAL LAB";
      case "aws":
        return "AWS SCAN";
      default:
        return "UNKNOWN";
    }
  };

  const getStatusLabel = (status: string): { label: string; variant: "success" | "warning" | "error" | "info" } => {
    switch (status) {
      case "completed":
        return { label: "COMPLETED", variant: "success" };
      case "partial":
        return { label: "PARTIAL", variant: "warning" };
      case "failed":
        return { label: "FAILED", variant: "error" };
      case "running":
        return { label: "RUNNING", variant: "info" };
      case "pending":
        return { label: "PENDING", variant: "info" };
      default:
        return { label: status.toUpperCase(), variant: "info" };
    }
  };

  const getDataFreshness = (scan: ScanRecord): string => {
    if (scan.source === "local_lab") {
      return "SIMULATED DATA";
    }
    return "SCAN RESULT";
  };

  const isSimulation = (scan: ScanRecord | null): boolean => {
    return scan?.source === "local_lab";
  };

  const isHistorical = (scan: ScanRecord | null, allScans: ScanRecord[]): boolean => {
    if (!scan) return false;
    const sorted = [...allScans].sort(
      (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
    );
    return sorted[0]?.scan_id !== scan.scan_id;
  };

  const value = useMemo(
    () => ({
      scans,
      selectedScan,
      loading,
      error,
      refreshScans,
      selectScan,
      startLocalLabScan,
      // Helper functions for UI
      getSourceLabel,
      getStatusLabel,
      getDataFreshness,
      isSimulation,
      isHistorical,
    }),
    [
      scans,
      selectedScan,
      loading,
      error,
      refreshScans,
      selectScan,
      startLocalLabScan,
    ],
  );

  return (
    <ScanContext.Provider value={value}>
      {children}
    </ScanContext.Provider>
  );
}


export function useScanContext(): ScanContextValue {
  const context = useContext(ScanContext);

  if (context === undefined) {
    throw new Error(
      "useScanContext must be used "
      + "within a ScanProvider.",
    );
  }

  return context;
}
