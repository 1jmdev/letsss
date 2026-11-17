import { useState } from "react";
import { Cpu, FileText, LayoutDashboard, Package, ShieldAlert } from "lucide-react";

const views = [
  { name: "Overview", icon: LayoutDashboard },
  { name: "Findings", icon: ShieldAlert },
  { name: "Processes", icon: Cpu },
  { name: "Mods", icon: Package },
  { name: "Report", icon: FileText },
];

export default function App() {
  const [active, setActive] = useState(views[0].name);

  return (
    <div className="flex h-screen">
      <aside className="flex w-52 flex-col gap-1 border-r border-border bg-panel p-3">
        <div className="px-2 py-3 text-sm font-semibold tracking-wide">letsSS</div>
        {views.map(({ name, icon: Icon }) => (
          <button
            key={name}
            onClick={() => setActive(name)}
            className={`flex items-center gap-2.5 rounded-md px-2.5 py-2 text-sm transition-colors ${
              active === name
                ? "bg-accent/15 text-zinc-100"
                : "text-muted hover:bg-white/5 hover:text-zinc-200"
            }`}
          >
            <Icon size={16} />
            {name}
          </button>
        ))}
      </aside>
      <main className="flex-1 overflow-auto p-6">
        <h1 className="text-lg font-medium">{active}</h1>
      </main>
    </div>
  );
}
