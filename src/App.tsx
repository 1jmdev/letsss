import { useEffect } from "react";
import { Sidebar } from "./components/Sidebar";
import { useStore } from "./lib/store";
import { Findings } from "./views/Findings";
import { Overview } from "./views/Overview";
import { ReportView } from "./views/Report";
import { Scan } from "./views/Scan";

const VIEWS = { overview: Overview, scan: Scan, findings: Findings, report: ReportView };

export default function App() {
  const view = useStore((state) => state.view);
  const loadHost = useStore((state) => state.loadHost);
  const Active = VIEWS[view];

  useEffect(() => {
    loadHost();
  }, [loadHost]);

  return (
    <div className="flex h-screen">
      <Sidebar />
      <main className="flex-1 overflow-y-auto">
        <div className="mx-auto max-w-5xl p-8">
          <Active />
        </div>
      </main>
    </div>
  );
}
