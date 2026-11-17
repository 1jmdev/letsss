import clsx from "clsx";
import { FileText, LayoutDashboard, Radar, ShieldAlert, ShieldCheck } from "lucide-react";
import { useStore, type View } from "../lib/store";

const NAVIGATION: { view: View; label: string; icon: typeof Radar }[] = [
  { view: "overview", label: "Overview", icon: LayoutDashboard },
  { view: "scan", label: "Scan", icon: Radar },
  { view: "findings", label: "Findings", icon: ShieldAlert },
  { view: "report", label: "Report", icon: FileText },
];

export function Sidebar() {
  const { view, setView, status, report, live } = useStore();
  const count = report ? report.findings.filter((finding) => finding.severity !== "informational").length : live.length;

  return (
    <aside className="flex w-56 shrink-0 flex-col border-r border-border bg-panel">
      <div className="flex items-center gap-2.5 px-5 py-5">
        <div className="grid size-8 place-items-center rounded-lg bg-accent/15 text-accent">
          <ShieldCheck size={18} />
        </div>
        <div>
          <div className="text-sm font-semibold">letsSS</div>
          <div className="text-xs text-muted">Screenshare tool</div>
        </div>
      </div>
      <nav className="flex flex-col gap-1 px-3">
        {NAVIGATION.map(({ view: target, label, icon: Icon }) => (
          <button
            key={target}
            onClick={() => setView(target)}
            className={clsx(
              "flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors",
              view === target ? "bg-accent/15 text-text" : "text-muted hover:bg-raised hover:text-text",
            )}
          >
            <Icon size={16} className={view === target ? "text-accent" : undefined} />
            <span className="flex-1 text-left">{label}</span>
            {target === "scan" && status === "running" && <span className="size-2 animate-pulse rounded-full bg-accent" />}
            {target === "findings" && count > 0 && (
              <span className="rounded-full bg-raised px-2 text-xs text-muted">{count}</span>
            )}
          </button>
        ))}
      </nav>
      <div className="mt-auto px-5 py-4 text-xs text-muted">v0.1.0</div>
    </aside>
  );
}
