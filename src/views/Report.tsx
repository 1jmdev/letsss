import { Download, RotateCcw } from "lucide-react";
import { useState } from "react";
import { Button, PageHeader, Panel, ProgressBar, Stat } from "../components/ui";
import { formatTime, moduleLabel, SEVERITIES, SEVERITY_STYLE, VERDICT_STYLE } from "../lib/format";
import { useStore } from "../lib/store";

export function ReportView() {
  const { report, exportReport, setView } = useStore();
  const [exported, setExported] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  if (!report) {
    return (
      <>
        <PageHeader title="Report" />
        <Panel>
          <p className="text-sm text-muted">A report becomes available once a scan completes.</p>
        </Panel>
      </>
    );
  }

  const clients = [...new Set(report.findings.flatMap((finding) => (finding.client ? [finding.client] : [])))];
  const total = report.findings.length || 1;
  const save = async () => {
    try {
      setError(null);
      setExported(await exportReport());
    } catch (reason) {
      setError(String(reason));
    }
  };

  return (
    <>
      <PageHeader
        title="Report"
        subtitle="Summary of the completed inspection."
        action={
          <div className="flex gap-2">
            <Button onClick={() => setView("overview")}>
              <RotateCcw size={15} /> New scan
            </Button>
            <Button variant="primary" onClick={save}>
              <Download size={15} /> Export JSON
            </Button>
          </div>
        }
      />

      {exported && (
        <div className="mb-6 rounded-xl border border-clean/30 bg-clean/10 px-4 py-3 text-sm text-clean">Saved to {exported}</div>
      )}
      {error && <div className="mb-6 rounded-xl border border-critical/30 bg-critical/10 px-4 py-3 text-sm text-critical">{error}</div>}

      <div className="mb-6 grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Stat label="Verdict" value={VERDICT_STYLE[report.verdict].label} tone={VERDICT_STYLE[report.verdict].tone.split(" ").pop()} />
        <Stat label="Findings" value={report.findings.length} />
        <Stat label="Duration" value={`${Math.max(report.finished - report.started, 0)} s`} />
        <Stat label="Started" value={formatTime(report.started)} />
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Panel title="Severity breakdown">
          <ul className="flex flex-col gap-3">
            {SEVERITIES.map((severity) => {
              const count = report.findings.filter((finding) => finding.severity === severity).length;
              return (
                <li key={severity}>
                  <div className="mb-1 flex justify-between text-sm">
                    <span className={SEVERITY_STYLE[severity].text}>{SEVERITY_STYLE[severity].label}</span>
                    <span className="tabular-nums text-muted">{count}</span>
                  </div>
                  <ProgressBar fraction={count / total} tone={SEVERITY_STYLE[severity].dot} />
                </li>
              );
            })}
          </ul>
        </Panel>

        <Panel title="Identified clients">
          {clients.length === 0 ? (
            <p className="text-sm text-muted">No specific cheat client was identified.</p>
          ) : (
            <div className="flex flex-wrap gap-2">
              {clients.map((client) => (
                <span key={client} className="rounded-lg bg-critical/15 px-3 py-1.5 text-sm font-medium text-critical">
                  {client}
                </span>
              ))}
            </div>
          )}
          <h3 className="mb-2 mt-6 text-xs font-semibold uppercase tracking-wider text-muted">Modules run</h3>
          <div className="flex flex-wrap gap-2">
            {report.modules.map((module) => (
              <span key={module} className="rounded-md bg-raised px-2.5 py-1 text-xs text-muted">
                {moduleLabel(module)}
              </span>
            ))}
          </div>
        </Panel>
      </div>

      <Panel title="Host" className="mt-6">
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
          <Stat label="Host" value={report.host.host} />
          <Stat label="System" value={report.host.os} />
          <Stat label="Administrator" value={report.host.elevated ? "Yes" : "No"} />
          <Stat label="Last boot" value={formatTime(report.host.boot_time)} />
        </div>
      </Panel>
    </>
  );
}
