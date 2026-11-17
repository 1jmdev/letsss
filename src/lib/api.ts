import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { open, save } from "@tauri-apps/plugin-dialog";
import type {
  CompletionEvent,
  FindingEvent,
  HostSummary,
  Options,
  ProgressEvent,
  Report,
} from "./types";

export const systemInformation = () => invoke<HostSummary>("system_information");

export const startInspection = (options: Options) =>
  invoke<number>("start_inspection", { options });

export const cancelInspection = (session: number) =>
  invoke<boolean>("cancel_inspection", { session });

export const sessionReport = (session: number) =>
  invoke<Report | null>("session_report", { session });

export const exportReport = (session: number, path: string) =>
  invoke<void>("export_report", { session, path });

export function subscribe(handlers: {
  progress: (event: ProgressEvent) => void;
  finding: (event: FindingEvent) => void;
  complete: (event: CompletionEvent) => void;
}): Promise<UnlistenFn> {
  return Promise.all([
    listen<ProgressEvent>("inspection://progress", (event) => handlers.progress(event.payload)),
    listen<FindingEvent>("inspection://finding", (event) => handlers.finding(event.payload)),
    listen<CompletionEvent>("inspection://complete", (event) => handlers.complete(event.payload)),
  ]).then((unlisteners) => () => unlisteners.forEach((unlisten) => unlisten()));
}

export async function choosePaths(directory: boolean): Promise<string[]> {
  const selection = await open({ multiple: true, directory });
  if (!selection) return [];
  return Array.isArray(selection) ? selection : [selection];
}

export async function chooseDirectory(): Promise<string | null> {
  const selection = await open({ directory: true, multiple: false });
  return typeof selection === "string" ? selection : null;
}

export const chooseReportDestination = () =>
  save({
    defaultPath: `letsss-report-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-")}.json`,
    filters: [{ name: "JSON report", extensions: ["json"] }],
  });
