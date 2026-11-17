import clsx from "clsx";
import { ChevronRight, Search } from "lucide-react";
import { useMemo, useState } from "react";
import { Button, PageHeader, Panel, SeverityBadge } from "../components/ui";
import { describeEvidence, formatTime, MODULES, SEVERITIES, SEVERITY_STYLE, VERDICT_STYLE } from "../lib/format";
import { useStore } from "../lib/store";
import type { Finding, Module, Severity } from "../lib/types";

export function Findings() {
  const { report, setView } = useStore();
  const [severities, setSeverities] = useState<Severity[]>(["critical", "high", "medium"]);
  const [module, setModule] = useState<Module | "all">("all");
  const [query, setQuery] = useState("");

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return (report?.findings ?? []).filter(
      (finding) =>
        severities.includes(finding.severity) &&
        (module === "all" || finding.module === module) &&
        (!needle || `${finding.title} ${finding.client ?? ""} ${finding.target ?? ""}`.toLowerCase().includes(needle)),
    );
  }, [report, severities, module, query]);

  const groups = useMemo(
    () => [
      ...filtered
        .reduce((groups, finding, index) => {
          const key = finding.target ?? `#${index}`;
          return groups.set(key, [...(groups.get(key) ?? []), finding]);
        }, new Map<string, Finding[]>())
        .values(),
    ],
    [filtered],
  );

  if (!report) {
    return (
      <>
        <PageHeader title="Findings" />
        <Panel>
          <p className="text-sm text-muted">Run a scan to see findings.</p>
          <Button variant="primary" className="mt-4" onClick={() => setView("overview")}>
            Configure scan
          </Button>
        </Panel>
      </>
    );
  }

  const verdict = VERDICT_STYLE[report.verdict];
  const count = (severity: Severity) => report.findings.filter((finding) => finding.severity === severity).length;
  const toggle = (severity: Severity) =>
    setSeverities((current) =>
      current.includes(severity) ? current.filter((entry) => entry !== severity) : [...current, severity],
    );

  return (
    <>
      <PageHeader title="Findings" subtitle={`Scan finished ${formatTime(report.finished)}`} />

      <div className={clsx("mb-6 rounded-xl border bg-gradient-to-r to-transparent px-6 py-5", verdict.tone)}>
        <div className="text-xs font-semibold uppercase tracking-wider opacity-80">Verdict</div>
        <div className="mt-1 text-2xl font-bold">{verdict.label}</div>
        <div className="mt-1 text-sm text-text/80">
          {verdict.summary}
          {report.cancelled && " The scan was cancelled, so results are incomplete."}
        </div>
      </div>

      <div className="mb-4 flex flex-wrap items-center gap-2">
        {SEVERITIES.map((severity) => (
          <button
            key={severity}
            onClick={() => toggle(severity)}
            className={clsx(
              "flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-medium transition-colors",
              severities.includes(severity) ? "border-border bg-raised text-text" : "border-transparent text-muted/60",
            )}
          >
            <span className={clsx("size-2 rounded-full", SEVERITY_STYLE[severity].dot)} />
            {SEVERITY_STYLE[severity].label}
            <span className="text-muted">{count(severity)}</span>
          </button>
        ))}
        <div className="ml-auto flex items-center gap-2">
          <select
            value={module}
            onChange={(event) => setModule(event.target.value as Module | "all")}
            className="rounded-lg border border-border bg-raised px-3 py-1.5 text-sm outline-none focus:border-accent"
          >
            <option value="all">All modules</option>
            {MODULES.map((entry) => (
              <option key={entry.id} value={entry.id}>
                {entry.label}
              </option>
            ))}
          </select>
          <div className="flex items-center gap-2 rounded-lg border border-border bg-raised px-3 py-1.5 focus-within:border-accent">
            <Search size={14} className="text-muted" />
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search findings"
              className="w-44 bg-transparent text-sm outline-none placeholder:text-muted"
            />
          </div>
        </div>
      </div>

      {filtered.length === 0 ? (
        <Panel>
          <p className="text-sm text-muted">No findings match the current filters.</p>
        </Panel>
      ) : (
        <div className="flex flex-col gap-4">
          {groups.map((group, index) => (
            <div key={group[0].target ?? index} className="flex flex-col gap-2">
              {group[0].target && (
                <div className="select-text px-1 text-xs">
                  <span className="font-semibold text-text">{group[0].target.split(/[\\/]/).pop()}</span>
                  <span className="ml-2 break-all text-muted">{group[0].target}</span>
                </div>
              )}
              {group.map((finding) => (
                <FindingRow key={finding.title} finding={finding} />
              ))}
            </div>
          ))}
        </div>
      )}
    </>
  );
}

function FindingRow({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(false);
  const module = MODULES.find((entry) => entry.id === finding.module);

  return (
    <div className="overflow-hidden rounded-xl border border-border bg-panel">
      <button
        onClick={() => setOpen(!open)}
        className="flex w-full items-center gap-3 px-4 py-3 text-left transition-colors hover:bg-raised/60"
      >
        <ChevronRight size={16} className={clsx("shrink-0 text-muted transition-transform", open && "rotate-90")} />
        <SeverityBadge severity={finding.severity} />
        <span className="flex-1 text-sm">{finding.title}</span>
        {finding.client && (
          <span className="rounded-md bg-accent/15 px-2 py-0.5 text-xs font-semibold text-accent">{finding.client}</span>
        )}
        <span className="hidden w-36 text-right text-xs text-muted md:block">{module?.label}</span>
      </button>
      {open && (
        <div className="border-t border-border bg-surface/60 px-4 py-3">
          {finding.timestamp && <p className="mb-2 text-xs text-muted">Recorded {formatTime(finding.timestamp)}</p>}
          {finding.evidence.length === 0 ? (
            <p className="text-xs text-muted">No additional evidence.</p>
          ) : (
            <ul className="flex select-text flex-col gap-1.5">
              {finding.evidence.map((evidence, index) => {
                const { primary, secondary } = describeEvidence(evidence);
                return (
                  <li key={index} className="rounded-lg bg-raised px-3 py-2 font-mono text-xs">
                    <div className="break-all text-text">{primary}</div>
                    {secondary && <div className="mt-1 whitespace-pre-wrap break-all text-muted">{secondary}</div>}
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}
