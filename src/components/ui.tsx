import clsx from "clsx";
import type { ReactNode } from "react";
import { SEVERITY_STYLE } from "../lib/format";
import type { Severity } from "../lib/types";

export function Panel({ title, action, children, className }: {
  title?: string;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={clsx("rounded-xl border border-border bg-panel", className)}>
      {title && (
        <header className="flex items-center justify-between border-b border-border px-5 py-3">
          <h2 className="text-sm font-semibold text-text">{title}</h2>
          {action}
        </header>
      )}
      <div className="p-5">{children}</div>
    </section>
  );
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  const style = SEVERITY_STYLE[severity];
  return (
    <span className={clsx("inline-flex min-w-16 justify-center rounded-md px-2 py-0.5 text-xs font-semibold ring-1 ring-inset", style.badge)}>
      {style.label}
    </span>
  );
}

export function Button({ variant = "secondary", className, ...props }: React.ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "primary" | "secondary" | "danger" | "ghost";
}) {
  return (
    <button
      {...props}
      className={clsx(
        "inline-flex items-center justify-center gap-2 rounded-lg px-3.5 py-2 text-sm font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-40",
        variant === "primary" && "bg-accent text-white hover:bg-accent/85",
        variant === "secondary" && "border border-border bg-raised text-text hover:bg-border/60",
        variant === "danger" && "border border-critical/40 bg-critical/10 text-critical hover:bg-critical/20",
        variant === "ghost" && "text-muted hover:bg-raised hover:text-text",
        className,
      )}
    />
  );
}

export function Stat({ label, value, tone }: { label: string; value: ReactNode; tone?: string }) {
  return (
    <div className="rounded-lg border border-border bg-raised/60 px-4 py-3">
      <div className="text-xs text-muted">{label}</div>
      <div className={clsx("mt-1 truncate text-sm font-medium", tone ?? "text-text")}>{value}</div>
    </div>
  );
}

export function ProgressBar({ fraction, tone = "bg-accent" }: { fraction: number; tone?: string }) {
  return (
    <div className="h-1.5 w-full overflow-hidden rounded-full bg-raised">
      <div className={clsx("h-full rounded-full transition-[width] duration-300", tone)} style={{ width: `${Math.round(fraction * 100)}%` }} />
    </div>
  );
}

export function PageHeader({ title, subtitle, action }: { title: string; subtitle?: string; action?: ReactNode }) {
  return (
    <div className="mb-6 flex items-end justify-between gap-4">
      <div>
        <h1 className="text-xl font-semibold text-text">{title}</h1>
        {subtitle && <p className="mt-1 text-sm text-muted">{subtitle}</p>}
      </div>
      {action}
    </div>
  );
}
