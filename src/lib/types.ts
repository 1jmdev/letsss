export type Module =
  | "memory"
  | "launch_arguments"
  | "processes"
  | "mods"
  | "files"
  | "artifacts"
  | "network"
  | "bypass";

export type Severity = "informational" | "low" | "medium" | "high" | "critical";

export type Verdict = "clean" | "suspicious" | "detected";

export type Evidence =
  | { kind: "file"; path: string; detail: string | null }
  | { kind: "memory"; pid: number; address: number; excerpt: string }
  | { kind: "process"; pid: number; name: string; detail: string | null }
  | { kind: "registry"; key: string; value: string | null }
  | { kind: "event"; log: string; id: number; record: string }
  | { kind: "text"; detail: string };

export interface Finding {
  module: Module;
  severity: Severity;
  title: string;
  client: string | null;
  evidence: Evidence[];
  timestamp: number | null;
}

export interface HostSummary {
  os: string;
  host: string;
  boot_time: number;
  elevated: boolean;
  game_processes: number;
}

export interface Report {
  verdict: Verdict;
  host: HostSummary;
  modules: Module[];
  started: number;
  finished: number;
  cancelled: boolean;
  findings: Finding[];
}

export interface Options {
  modules: Module[];
  paths: string[];
  online: boolean;
  game_directory: string | null;
}

export interface ProgressEvent {
  session: number;
  module: Module;
  fraction: number;
  detail: string;
}

export type FindingEvent = Finding & { session: number };

export interface CompletionEvent {
  session: number;
  report: Report | null;
  error: string | null;
}
