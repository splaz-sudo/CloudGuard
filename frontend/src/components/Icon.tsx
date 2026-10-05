/**
 * CloudGuard inline SVG icon set.
 *
 * Lightweight stroke icons (24x24 viewBox) drawn with
 * `currentColor` so they inherit text color. No emoji,
 * no icon-font, no external dependency.
 */

export type IconName =
  | "alert"
  | "check"
  | "chevron-down"
  | "chevron-right"
  | "copy"
  | "coverage"
  | "download"
  | "eye"
  | "findings"
  | "globe"
  | "identity"
  | "info"
  | "inventory"
  | "lock"
  | "network"
  | "overview"
  | "paths"
  | "play"
  | "refresh"
  | "remediate"
  | "reports"
  | "scans"
  | "search"
  | "shield"
  | "sliders"
  | "swap"
  | "warning"
  | "x";


const PATHS: Record<IconName, string> = {
  "alert":
    "M12 9v4m0 4h.01M10.3 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.7 3.86a2 2 0 0 0-3.4 0Z",
  "check": "M20 6 9 17l-5-5",
  "chevron-down": "m6 9 6 6 6-6",
  "chevron-right": "m9 18 6-6-6-6",
  "copy":
    "M20 9h-9a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h9a2 2 0 0 0 2-2v-9a2 2 0 0 0-2-2ZM5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1",
  "coverage":
    "M3 3h7v7H3zM14 3h7v7h-7zM14 14h7v7h-7zM3 14h7v7H3z",
  "download": "M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3",
  "eye":
    "M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7Zm10 3a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z",
  "findings":
    "M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20Zm0-6v-4m0-4h.01",
  "globe":
    "M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20Zm-10-7h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10Z",
  "identity":
    "M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2m18-10a6 6 0 1 1-12 0 6 6 0 0 1 12 0Z",
  "info":
    "M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20Zm0-10v6m0-12h.01",
  "inventory":
    "M21 8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16V8ZM3.3 7 12 12l8.7-5M12 22V12",
  "lock":
    "M19 11H5a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7a2 2 0 0 0-2-2ZM7 11V7a5 5 0 0 1 10 0v4",
  "network":
    "M4 21v-6m0-4V3m8 18v-9m0-4V3m8 18v-5m0-4V3M1 14h6M9 8h6m2 8h6",
  "overview":
    "M3 13h8V3H3v10Zm0 8h8v-6H3v6Zm10 0h8V11h-8v10Zm0-18v6h8V3h-8Z",
  "paths":
    "M6 3v12m0 0a3 3 0 1 0 3 3m-3-3a3 3 0 0 1 3 3m0 0h9M18 9a3 3 0 1 0 0-6 3 3 0 0 0 0 6Zm0 0v3a3 3 0 0 1-3 3h-1.5",
  "play": "m6 4 14 8-14 8V4Z",
  "refresh":
    "M23 4v6h-6M1 20v-6h6m-3.5 5A9 9 0 0 1 19.4 9.4L23 12M1 12l3.6 2.6A9 9 0 0 0 20.5 19",
  "remediate":
    "M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76Z",
  "reports":
    "M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8l-6-6Zm0 0v6h6M16 13H8m8 4H8m2-8H8",
  "scans":
    "M22 12h-4l-3 9L9 3l-3 9H2",
  "search":
    "M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16Zm10 2-4.35-4.35",
  "shield":
    "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z",
  "sliders":
    "M4 21v-7m0-4V3m8 18v-9m0-4V3m8 18v-5m0-4V3M1 14h6M9 8h6m2 8h6",
  "swap":
    "M17 1l4 4-4 4M3 11V9a4 4 0 0 1 4-4h14M7 23l-4-4 4-4m14-2v2a4 4 0 0 1-4 4H3",
  "warning":
    "M12 9v4m0 4h.01M10.3 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.7 3.86a2 2 0 0 0-3.4 0Z",
  "x": "M18 6 6 18M6 6l12 12",
};


function Icon({
  name,
  size = 16,
  className = "",
  strokeWidth = 1.8,
}: {
  name: IconName;
  size?: number;
  className?: string;
  strokeWidth?: number;
}) {
  return (
    <svg
      className={`icon ${className}`.trim()}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={strokeWidth}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      <path d={PATHS[name]} />
    </svg>
  );
}


export default Icon;
