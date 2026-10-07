import { useState, type CSSProperties, type ReactNode, useEffect } from "react";
import { type IconName } from "../Icon";
import Icon from "../Icon";

export interface InspectorPanelProps {
  children: ReactNode;
  title?: string;
  subtitle?: string;
  icon?: IconName;
  open: boolean;
  onClose: () => void;
  position?: "right" | "left" | "bottom";
  width?: number | string;
  maxHeight?: number | string;
  showBackdrop?: boolean;
  className?: string;
  "aria-label"?: string;
}

export function InspectorPanel({
  children,
  title,
  subtitle,
  icon,
  open,
  onClose,
  position = "right",
  width = 380,
  maxHeight = "100%",
  showBackdrop = true,
  className = "",
  "aria-label": ariaLabel,
}: InspectorPanelProps) {
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
    return () => setMounted(false);
  }, []);

  if (!mounted && !open) return null;

  const panelStyle: CSSProperties = {
    width: typeof width === "number" ? `${width}px` : width,
    maxHeight: typeof maxHeight === "number" ? `${maxHeight}px` : maxHeight,
    transform: open ? "translateX(0)" : position === "right" ? "translateX(100%)" : "translateX(-100%)",
    transition: "transform var(--dur-panel-slide) var(--ease-out)",
  };

  const backdropStyle: CSSProperties = {
    opacity: open ? 1 : 0,
    pointerEvents: open ? "auto" : "none",
    transition: "opacity var(--dur-base) var(--ease-out)",
  };

  return (
    <>
      {showBackdrop && (
        <div
          className="inspector-backdrop"
          style={backdropStyle}
          onClick={onClose}
          aria-hidden="true"
        />
      )}

      <aside
        className={`inspector-panel inspector-panel--${position} ${open ? "open" : ""} ${className}`}
        style={panelStyle}
        role="dialog"
        aria-label={ariaLabel ?? title ?? "Inspector"}
        aria-modal="true"
      >
        <div className="inspector-header">
          <div className="inspector-title-group">
            {icon && <Icon name={icon} size={16} className="inspector-icon" />}
            <div>
              {title && <h3 className="inspector-title">{title}</h3>}
              {subtitle && <p className="inspector-subtitle">{subtitle}</p>}
            </div>
          </div>
          <button
            type="button"
            className="inspector-close"
            onClick={onClose}
            aria-label="Close inspector"
          >
            <Icon name="x" size={16} />
          </button>
        </div>

        <div className="inspector-body">
          {children}
        </div>
      </aside>
    </>
  );
}

export interface ExpandableSectionProps {
  title: string;
  children: ReactNode;
  icon?: IconName;
  defaultOpen?: boolean;
  className?: string;
  showChevron?: boolean;
}

export function ExpandableSection({
  title,
  children,
  icon,
  defaultOpen = false,
  className = "",
  showChevron = true,
}: ExpandableSectionProps) {
  const [open, setOpen] = useState(defaultOpen);

  return (
    <details className={`expandable-section ${open ? "open" : ""} ${className}`} open={defaultOpen}>
      <summary className="expandable-summary" onClick={(e) => { e.preventDefault(); setOpen(!open); }}>
        {icon && <Icon name={icon} size={13} />}
        <span className="expandable-title">{title}</span>
        {showChevron && <Icon name="chevron-right" size={12} className="expandable-chev" />}
      </summary>
      <div className="expandable-content">
        {children}
      </div>
    </details>
  );
}

export function CollapsibleRows({
  items,
  preview = 4,
  renderItem,
  expandLabel = "Show all",
  empty = "No items",
  className = "",
}: {
  items: string[];
  preview?: number;
  renderItem: (item: string, index: number) => ReactNode;
  expandLabel?: string;
  empty?: string;
  className?: string;
}) {
  const [expanded, setExpanded] = useState(false);

  if (items.length === 0) {
    return <p className={`collapsible-empty ${className}`}>{empty}</p>;
  }

  const visible = expanded ? items : items.slice(0, preview);
  const hidden = expanded ? [] : items.slice(preview);

  return (
    <div className={`collapsible-rows ${className}`}>
      <div className="collapsible-preview">
        {visible.map((item, index) => renderItem(item, index))}
      </div>

      {hidden.length > 0 && (
        <button
          type="button"
          className="collapsible-toggle"
          onClick={() => setExpanded(!expanded)}
        >
          <Icon name="chevron-right" size={12} className={expanded ? "rotated" : ""} />
          {expandLabel} ({hidden.length} more)
        </button>
      )}
    </div>
  );
}

export function ChipRow({
  items,
  maxVisible = 6,
  renderItem,
  overflowLabel = "+{count} more",
  className = "",
}: {
  items: string[];
  maxVisible?: number;
  renderItem: (item: string, index: number) => ReactNode;
  overflowLabel?: string;
  className?: string;
}) {
  if (items.length === 0) return null;

  const visible = items.slice(0, maxVisible);
  const hiddenCount = items.length - maxVisible;

  return (
    <div className={`chip-row ${className}`}>
      {visible.map((item, index) => renderItem(item, index))}
      {hiddenCount > 0 && (
        <span className="chip overflow">
          {overflowLabel.replace("{count}", String(hiddenCount))}
        </span>
      )}
    </div>
  );
}