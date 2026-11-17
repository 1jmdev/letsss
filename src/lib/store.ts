import { create } from "zustand";
import * as api from "./api";
import { MODULES } from "./format";
import type { Finding, HostSummary, Module, Options, Report } from "./types";

export type View = "overview" | "scan" | "findings" | "report";
type Status = "idle" | "running" | "complete" | "failed";

interface ModuleProgress {
  fraction: number;
  detail: string;
}

interface State {
  view: View;
  host: HostSummary | null;
  options: Options;
  session: number | null;
  status: Status;
  progress: Partial<Record<Module, ModuleProgress>>;
  live: Finding[];
  report: Report | null;
  error: string | null;
  setView: (view: View) => void;
  loadHost: () => Promise<void>;
  toggleModule: (module: Module) => void;
  setAllModules: (enabled: boolean) => void;
  setOnline: (online: boolean) => void;
  addPaths: (directory: boolean) => Promise<void>;
  removePath: (path: string) => void;
  start: () => Promise<void>;
  cancel: () => Promise<void>;
  exportReport: () => Promise<string | null>;
}

export const useStore = create<State>((set, get) => ({
  view: "overview",
  host: null,
  options: { modules: MODULES.map((module) => module.id), paths: [], online: true },
  session: null,
  status: "idle",
  progress: {},
  live: [],
  report: null,
  error: null,

  setView: (view) => set({ view }),

  loadHost: async () => {
    try {
      set({ host: await api.systemInformation() });
    } catch (error) {
      set({ error: String(error) });
    }
  },

  toggleModule: (module) =>
    set(({ options }) => ({
      options: {
        ...options,
        modules: options.modules.includes(module)
          ? options.modules.filter((entry) => entry !== module)
          : [...options.modules, module],
      },
    })),

  setAllModules: (enabled) =>
    set(({ options }) => ({
      options: { ...options, modules: enabled ? MODULES.map((module) => module.id) : [] },
    })),

  setOnline: (online) => set(({ options }) => ({ options: { ...options, online } })),

  addPaths: async (directory) => {
    const chosen = await api.choosePaths(directory);
    set(({ options }) => ({
      options: { ...options, paths: [...new Set([...options.paths, ...chosen])] },
    }));
  },

  removePath: (path) =>
    set(({ options }) => ({
      options: { ...options, paths: options.paths.filter((entry) => entry !== path) },
    })),

  start: async () => {
    const { options } = get();
    set({ status: "running", progress: {}, live: [], report: null, error: null, view: "scan" });
    try {
      set({ session: await api.startInspection(options) });
    } catch (error) {
      set({ status: "failed", error: String(error) });
    }
  },

  cancel: async () => {
    const { session } = get();
    if (session !== null) await api.cancelInspection(session);
  },

  exportReport: async () => {
    const { session } = get();
    const destination = await api.chooseReportDestination();
    if (session === null || !destination) return null;
    await api.exportReport(session, destination);
    return destination;
  },
}));

const accepts = (session: number) => {
  const state = useStore.getState();
  return state.status === "running" && (state.session === null || state.session === session);
};

api.subscribe({
  progress: ({ session, module, fraction, detail }) => {
    if (!accepts(session)) return;
    useStore.setState(({ progress }) => ({ progress: { ...progress, [module]: { fraction, detail } } }));
  },
  finding: ({ session, ...finding }) => {
    if (!accepts(session)) return;
    useStore.setState(({ live }) => ({ live: [finding, ...live] }));
  },
  complete: ({ session, report, error }) => {
    if (!accepts(session)) return;
    useStore.setState({
      status: report ? "complete" : "failed",
      report,
      error,
      host: report?.host ?? useStore.getState().host,
      view: report ? "findings" : "scan",
    });
  },
});
