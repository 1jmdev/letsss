import { CheckCircle2, Loader2, Square } from "lucide-react";
import { Button, PageHeader, Panel, ProgressBar, SeverityBadge } from "../components/ui";
import { MODULES } from "../lib/format";
import { useStore } from "../lib/store";

export function Scan() {
  const { status, options, progress, live, error, cancel, setView } = useStore();
  const modules = MODULES.filter((module) => options.modules.includes(module.id));
  const overall = modules.length
    ? modules.reduce((sum, module) => sum + (progress[module.id]?.fraction ?? 0), 0) / modules.length
    : 0;

  if (status === "idle") {
    return (
      <>
        <PageHeader title="Scan" />
        <Panel>
          <p className="text-sm text-muted">No scan has been started yet.</p>
          <Button variant="primary" className="mt-4" onClick={() => setView("overview")}>
            Configure scan
          </Button>
        </Panel>
      </>
    );
  }

  return (
    <>
      <PageHeader
        title="Scan"
        subtitle={status === "running" ? "Inspecting this machine…" : status === "failed" ? "The scan failed." : "Scan complete."}
        action={
          status === "running" ? (
            <Button variant="danger" onClick={cancel}>
              <Square size={14} /> Cancel
            </Button>
          ) : (
            <Button variant="primary" onClick={() => setView("findings")} disabled={status === "failed"}>
              View findings
            </Button>
          )
        }
      />

      {error && (
        <div className="mb-6 rounded-xl border border-critical/30 bg-critical/10 px-4 py-3 text-sm text-critical">{error}</div>
      )}

      <Panel className="mb-6">
        <div className="mb-2 flex items-center justify-between text-sm">
          <span className="font-medium">Overall progress</span>
          <span className="tabular-nums text-muted">{Math.round(overall * 100)}%</span>
        </div>
        <ProgressBar fraction={status === "complete" ? 1 : overall} />
      </Panel>

      <div className="grid gap-6 lg:grid-cols-2">
        <Panel title="Modules">
          <ul className="flex flex-col gap-4">
            {modules.map((module) => {
              const state = progress[module.id];
              const done = status !== "running" || (state?.fraction ?? 0) >= 1;
              return (
                <li key={module.id}>
                  <div className="mb-1.5 flex items-center gap-2 text-sm">
                    {done ? (
                      <CheckCircle2 size={15} className="text-clean" />
                    ) : (
                      <Loader2 size={15} className="animate-spin text-accent" />
                    )}
                    <span className="flex-1">{module.label}</span>
                    <span className="tabular-nums text-xs text-muted">{Math.round((done ? 1 : state?.fraction ?? 0) * 100)}%</span>
                  </div>
                  <ProgressBar fraction={done ? 1 : state?.fraction ?? 0} tone={done ? "bg-clean" : "bg-accent"} />
                  {!done && state?.detail && <p className="mt-1 truncate text-xs text-muted">{state.detail}</p>}
                </li>
              );
            })}
          </ul>
        </Panel>

        <Panel title={`Live findings (${live.length})`}>
          {live.length === 0 ? (
            <p className="text-sm text-muted">Findings appear here as modules complete.</p>
          ) : (
            <ul className="flex max-h-[28rem] flex-col gap-2 overflow-y-auto pr-1">
              {live.map((finding, index) => (
                <li key={index} className="flex items-start gap-3 rounded-lg bg-raised px-3 py-2">
                  <SeverityBadge severity={finding.severity} />
                  <span className="flex-1 text-sm">
                    {finding.title}
                    {finding.client && <span className="ml-2 text-xs font-semibold text-accent">{finding.client}</span>}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>
    </>
  );
}
