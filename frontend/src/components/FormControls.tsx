import {
  forwardRef,
  useState,
  useEffect,
  useRef,
    type SelectHTMLAttributes,
  type InputHTMLAttributes,
  type LabelHTMLAttributes,
  type ReactNode,
} from "react";

/** Select component with consistent CloudGuard styling */
export interface SelectProps
  extends Omit<SelectHTMLAttributes<HTMLSelectElement>, "onChange"> {
  label: string;
  error?: string;
  fullWidth?: boolean;
  className?: string;
  options: { value: string; label: string }[];
  placeholder?: string;
  onChange?: (value: string) => void;
}

/** Search input with consistent styling */
export interface SearchInputProps extends Omit<InputHTMLAttributes<HTMLInputElement>, "onChange"> {
  placeholder?: string;
  onChange?: (value: string) => void;
  value: string;
}

/** Label component */
export interface LabelProps extends LabelHTMLAttributes<HTMLLabelElement> {
  required?: boolean;
}

/** Form field wrapper */
export interface FormFieldProps {
  label: string;
  error?: string;
  hint?: string;
  fullWidth?: boolean;
  className?: string;
  children?: ReactNode;
}

/** Badge component */
export interface BadgeProps {
  children: ReactNode;
  variant?: "default" | "success" | "warning" | "danger" | "info" | "primary";
  size?: "sm" | "md" | "lg";
  className?: string;
}

/** Button component */
export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "secondary" | "danger" | "ghost";
  size?: "sm" | "md" | "lg";
  loading?: boolean;
}

/** Multi-select component */
export interface MultiSelectProps {
  label: string;
  options: { value: string; label: string }[];
  value: string[];
  onChange: (value: string[]) => void;
  placeholder?: string;
  className?: string;
  error?: string;
}

/* Select component */
export const Select = forwardRef<HTMLSelectElement, SelectProps>(
  (
    {
      label,
      error,
      fullWidth = false,
      className = "",
      options,
      placeholder,
      children,
      onChange,
      ...props
    },
    ref,
  ) => (
    <div className={`form-field ${fullWidth ? "form-field-full" : ""}`}>
      <label className="form-label">{label}</label>
      <div className="select-wrapper">
        <select
          ref={ref}
          className={`form-select ${error ? "has-error" : ""} ${className}`}
          onChange={
            onChange ? (event) => onChange(event.target.value) : undefined
          }
          {...props}
        >
          {placeholder && (
            <option value="" disabled>
              {placeholder}
            </option>
          )}
          {options.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
          {children}
        </select>
        {error && <span className="field-error">{error}</span>}
      </div>
    </div>
  ),
);

Select.displayName = "Select";

/* SearchInput component */
export const SearchInput = forwardRef<HTMLInputElement, SearchInputProps>(
  ({ placeholder = "Search...", onChange, value, className = "", ...props }, ref) => (
    <input
      ref={ref}
      type="search"
      className={`search-input ${className}`}
      placeholder={placeholder}
      value={value}
      onChange={(e) => onChange?.(e.target.value)}
      {...props}
    />
  ),
);

SearchInput.displayName = "SearchInput";

/* Label component */
export const Label = forwardRef<HTMLLabelElement, LabelProps>(
  ({ required = false, children, className = "", ...props }, ref) => (
    <label ref={ref} className={`form-label ${className}`} {...props}>
      {children}
      {required && <span className="required-indicator" aria-hidden="true">*</span>}
    </label>
  ),
);

Label.displayName = "Label";

/* FormField component */
export const FormField = ({
  label,
  error,
  hint,
  fullWidth = false,
  className = "",
  children,
}: FormFieldProps) => (
  <div className={`form-field ${fullWidth ? "form-field-full" : ""} ${className}`}>
    <label className="form-label">{label}</label>
    {children}
    {error && <span className="field-error">{error}</span>}
    {hint && <span className="field-hint">{hint}</span>}
  </div>
);

/* Badge component */
export const Badge = ({
  children,
  variant = "default",
  size = "md",
  className = "",
}: BadgeProps) => (
  <span className={`badge badge-${variant} badge-${size} ${className}`}>{children}</span>
);

/* Button component */
export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  (
    {
      variant = "primary",
      size = "md",
      loading = false,
      disabled,
      children,
      className = "",
      ...props
    },
    ref,
  ) => (
    <button
      ref={ref}
      className={`btn btn-${variant} btn-${size} ${className}`}
      disabled={disabled || loading}
      {...props}
    >
      {loading && <span className="btn-spinner" aria-hidden="true" />}
      {children}
    </button>
  ),
);

Button.displayName = "Button";

/* MultiSelect component */
export const MultiSelect = ({
  label,
  options,
  value,
  onChange,
  placeholder = "Select...",
  className = "",
  error,
}: MultiSelectProps) => {
  const [isOpen, setIsOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const dropdownRef = useRef<HTMLDivElement>(null);

  const handleSelect = (optionValue: string) => {
    const newValue = value.includes(optionValue)
      ? value.filter((v) => v !== optionValue)
      : [...value, optionValue];
    onChange(newValue);
  };

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setIsOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  const selectedLabels = options
    .filter((opt) => value.includes(opt.value))
    .map((opt) => opt.label)
    .join(", ");

  const query = searchQuery.trim().toLowerCase();
  const visibleOptions = query
    ? options.filter((opt) => opt.label.toLowerCase().includes(query))
    : options;

  return (
    <div className={`form-field-multiselect ${className}`}>
      <label className="form-label">{label}</label>
      <div className="multiselect-wrapper">
        <button
          type="button"
          className={`multiselect-trigger ${error ? "has-error" : ""}`}
          onClick={() => setIsOpen(!isOpen)}
          aria-expanded={isOpen}
          aria-haspopup="listbox"
        >
          <span className="multiselect-value">
            {value.length > 0 ? selectedLabels : placeholder}
          </span>
          <span className="multiselect-arrow" aria-hidden="true">▼</span>
        </button>
        {isOpen && (
          <div
            ref={dropdownRef}
            className="multiselect-dropdown"
            role="listbox"
          >
            <input
              type="text"
              className="multiselect-search"
              placeholder="Filter options..."
              onChange={(e) => setSearchQuery(e.target.value)}
              onClick={(e) => e.stopPropagation()}
              autoFocus
            />
            <div className="multiselect-options" role="listbox">
              {visibleOptions.length === 0 && (
                <span className="multiselect-empty">No options match</span>
              )}
              {visibleOptions.map((option) => (
                <button
                  key={option.value}
                  type="button"
                  role="option"
                  aria-selected={value.includes(option.value)}
                  className={`multiselect-option ${value.includes(option.value) ? "selected" : ""}`}
                  onClick={() => handleSelect(option.value)}
                >
                  <span className="option-check" aria-hidden="true">
                    {value.includes(option.value) ? "✓" : ""}
                  </span>
                  <span className="option-label">{option.label}</span>
                </button>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

