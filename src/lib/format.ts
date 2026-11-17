import type { Evidence, Module, Severity, Verdict } from "./types";

export const MODULES: { id: Module; label: string; description: string }[] = [
  { id: "memory", label: "Process memory", description: "Signature scan of running Minecraft memory and injected modules" },
  { id: "launch_arguments", label: "Launch arguments", description: "Java agents, boot class path and injected JVM options" },
  { id: "processes", label: "Processes", description: "Macro software, autoclickers and cheat-named processes" },
  { id: "mods", label: "Mods", description: "Mod folders, version JARs, Modrinth verification and game logs" },
  { id: "files", label: "Executable files", description: "Running program images and paths you add" },
  { id: "artifacts", label: "Execution artifacts", description: "Prefetch, USN journal, BAM, recycle bin and shell history" },
  { id: "network", label: "Network", description: "DNS cache and hosts file entries for cheat domains" },
  { id: "bypass", label: "Bypass detection", description: "Cleared logs, disabled services and blocked forensic tools" },
];

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "informational"];

export const SEVERITY_STYLE: Record<Severity, { label: string; text: string; badge: string; dot: string }> = {
  critical: { label: "Critical", text: "text-critical", badge: "bg-critical/15 text-critical ring-critical/30", dot: "bg-critical" },
  high: { label: "High", text: "text-high", badge: "bg-high/15 text-high ring-high/30", dot: "bg-high" },
  medium: { label: "Medium", text: "text-medium", badge: "bg-medium/15 text-medium ring-medium/30", dot: "bg-medium" },
  low: { label: "Low", text: "text-low", badge: "bg-low/15 text-low ring-low/30", dot: "bg-low" },
  informational: { label: "Info", text: "text-info", badge: "bg-info/15 text-info ring-info/30", dot: "bg-info" },
};

export const VERDICT_STYLE: Record<Verdict, { label: string; summary: string; tone: string }> = {
  clean: { label: "Clean", summary: "No evidence of cheating was found.", tone: "from-clean/20 border-clean/40 text-clean" },
  suspicious: { label: "Suspicious", summary: "Findings need manual review.", tone: "from-medium/20 border-medium/40 text-medium" },
  detected: { label: "Detected", summary: "Strong evidence of cheating or tampering.", tone: "from-critical/20 border-critical/40 text-critical" },
};

export const moduleLabel = (module: Module) => MODULES.find((entry) => entry.id === module)?.label ?? module;

export const formatTime = (seconds: number) => new Date(seconds * 1000).toLocaleString();

export function describeEvidence(evidence: Evidence): { primary: string; secondary?: string } {
  switch (evidence.kind) {
    case "file":
      return { primary: evidence.path, secondary: evidence.detail ?? undefined };
    case "memory":
      return { primary: `pid ${evidence.pid} @ 0x${evidence.address.toString(16)}`, secondary: evidence.excerpt };
    case "process":
      return { primary: `${evidence.name} (pid ${evidence.pid})`, secondary: evidence.detail ?? undefined };
    case "registry":
      return { primary: evidence.key, secondary: evidence.value ?? undefined };
    case "event":
      return { primary: `${evidence.log} · event ${evidence.id}`, secondary: evidence.record };
    case "text":
      return { primary: evidence.detail };
  }
}
