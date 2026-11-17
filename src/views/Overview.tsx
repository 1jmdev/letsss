import clsx from "clsx";
import { AlertTriangle, FilePlus, FolderOpen, FolderPlus, Play, X } from "lucide-react";
import { Button, PageHeader, Panel, Stat } from "../components/ui";
import { formatTime, MODULES } from "../lib/format";
import { useStore } from "../lib/store";

export function Overview() {
  const {
    host,
    options,
    status,
    toggleModule,
    setAllModules,
    setOnline,
    scanAllInstallations,
    chooseGameDirectory,
    addPaths,
    removePath,
    start,
  } = useStore();
  const specific = options.game_directory !== null;
  const running = status === "running";

  return (
    <>
      <PageHeader
        title="Overview"
        subtitle="Configure the inspection and start the scan."
        action={
          <Button variant="primary" onClick={start} disabled={running || options.modules.length === 0}>
            <Play size={16} />
            {running ? "Scan running" : "Start scan"}
          </Button>
        }
      />

      {host && !host.elevated && (
        <div className="mb-6 flex items-start gap-3 rounded-xl border border-medium/30 bg-medium/10 px-4 py-3 text-sm text-medium">
          <AlertTriangle size={18} className="mt-0.5 shrink-0" />
          <span>
            letsSS is not running as administrator. Memory, Prefetch, USN journal and event log checks need elevated
            rights to see everything.
          </span>
        </div>
      )}

      <div className="mb-6 grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Stat label="Host" value={host?.host ?? "…"} />
        <Stat label="System" value={host?.os ?? "…"} />
        <Stat
          label="Administrator"
          value={host ? (host.elevated ? "Yes" : "No") : "…"}
          tone={host ? (host.elevated ? "text-clean" : "text-medium") : undefined}
        />
        <Stat
          label="Minecraft processes"
          value={host?.game_processes ?? "…"}
          tone={host && host.game_processes === 0 ? "text-muted" : "text-text"}
        />
      </div>

      <Panel title="Minecraft installations" className="mb-6">
        <div className="grid gap-3 md:grid-cols-2">
          <button
            onClick={scanAllInstallations}
            className={clsx(
              "rounded-lg border px-4 py-3 text-left transition-colors",
              !specific ? "border-accent/50 bg-accent/10" : "border-border bg-raised/40 hover:bg-raised",
            )}
          >
            <span className="block text-sm font-medium">Every installation</span>
            <span className="block text-xs text-muted">Default launcher, Prism, MultiMC, Modrinth, CurseForge, Lunar and running games</span>
          </button>
          <button
            onClick={chooseGameDirectory}
            className={clsx(
              "rounded-lg border px-4 py-3 text-left transition-colors",
              specific ? "border-accent/50 bg-accent/10" : "border-border bg-raised/40 hover:bg-raised",
            )}
          >
            <span className="flex items-center gap-2 text-sm font-medium">
              <FolderOpen size={15} /> Current session only
            </span>
            <span className="block truncate text-xs text-muted">
              {options.game_directory ?? "Choose the .minecraft folder the player is using"}
            </span>
          </button>
        </div>
      </Panel>

      <Panel
        title="Modules"
        className="mb-6"
        action={
          <div className="flex gap-1">
            <Button variant="ghost" onClick={() => setAllModules(true)}>All</Button>
            <Button variant="ghost" onClick={() => setAllModules(false)}>None</Button>
          </div>
        }
      >
        <div className="grid gap-3 md:grid-cols-2">
          {MODULES.map((module) => {
            const enabled = options.modules.includes(module.id);
            return (
              <button
                key={module.id}
                onClick={() => toggleModule(module.id)}
                className={clsx(
                  "flex items-start gap-3 rounded-lg border px-4 py-3 text-left transition-colors",
                  enabled ? "border-accent/50 bg-accent/10" : "border-border bg-raised/40 hover:bg-raised",
                )}
              >
                <span
                  className={clsx(
                    "mt-0.5 grid size-4 shrink-0 place-items-center rounded border",
                    enabled ? "border-accent bg-accent" : "border-muted/60",
                  )}
                >
                  {enabled && <span className="size-1.5 rounded-sm bg-white" />}
                </span>
                <span>
                  <span className="block text-sm font-medium text-text">{module.label}</span>
                  <span className="block text-xs text-muted">{module.description}</span>
                </span>
              </button>
            );
          })}
        </div>
      </Panel>

      <div className="grid gap-6 md:grid-cols-[2fr_1fr]">
        <Panel
          title="Additional paths"
          action={
            <div className="flex gap-2">
              <Button onClick={() => addPaths(false)}>
                <FilePlus size={15} /> Files
              </Button>
              <Button onClick={() => addPaths(true)}>
                <FolderPlus size={15} /> Folder
              </Button>
            </div>
          }
        >
          {options.paths.length === 0 ? (
            <p className="text-sm text-muted">
              Optional. Add suspicious files, folders, or a .txt path list such as an Everything export.
            </p>
          ) : (
            <ul className="flex flex-col gap-2">
              {options.paths.map((path) => (
                <li key={path} className="flex items-center gap-2 rounded-lg bg-raised px-3 py-2 font-mono text-xs">
                  <span className="flex-1 truncate">{path}</span>
                  <button onClick={() => removePath(path)} className="text-muted hover:text-critical">
                    <X size={14} />
                  </button>
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <Panel title="Settings">
          <label className="flex cursor-pointer items-start gap-3">
            <input
              type="checkbox"
              checked={options.online}
              onChange={(event) => setOnline(event.target.checked)}
              className="mt-1 accent-accent"
            />
            <span>
              <span className="block text-sm font-medium">Modrinth verification</span>
              <span className="block text-xs text-muted">Sends mod SHA-1 hashes to Modrinth to identify published builds.</span>
            </span>
          </label>
          {host && <p className="mt-5 text-xs text-muted">Last boot {formatTime(host.boot_time)}</p>}
        </Panel>
      </div>
    </>
  );
}
