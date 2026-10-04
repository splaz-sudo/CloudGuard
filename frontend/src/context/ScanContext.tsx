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


  const value = useMemo(
    () => ({
      scans,
      selectedScan,
      loading,
      error,
      refreshScans,
      selectScan,
      startLocalLabScan,
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
