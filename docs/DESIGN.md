# letsSS — Design Specification

Minecraft screenshare (SS) inspection tool. Tauri 2 desktop application, React + Tailwind
frontend, Rust backend. Targets Windows (primary) and Linux. Read-only by default; every
modifying action requires explicit operator confirmation.

---

## 1. Reference Survey (MeowTonynoh)

| Tool | Technique | Retained in letsSS | Improvement |
|---|---|---|---|
| MeowClientFucker | Aho-Corasick over `javaw` RAM (388+ clients), generic module strings with word boundaries, DNS cache (`ipconfig /displaydns`) | Yes | Native DNS cache API (`DnsGetCacheDataTable`), UTF-16 + modified-UTF-8 matching, per-hit context excerpt, region attribution |
| MeowDoomsdayFucker / MeowNovowareFucker | Single-client private RAM signatures, 50 MB chunks, regions <100 MB; JARParser / JournalTrace downloaded at runtime | Yes, merged into one signature engine | No third-party executables: Prefetch and USN Journal parsed natively |
| MeowImportsChecker | Authenticode, ASCII/UTF-16/.NET metadata strings, PE import table, packer sections, YARA-style tags A–P, `paths.txt` bulk mode, deleted-path tracking | Yes | Parallel pipeline (rayon), ELF support on Linux, rules stored as data instead of code |
| MeowModAnalyzer | SHA1 → Modrinth / Megabase, JAR + nested JAR string scan, fullwidth Unicode, obfuscator signatures, hollow shell mods, `Zone.Identifier` source | Yes | Constant-pool parsing of `.class` files (no raw-byte regex), batched Modrinth `version_files` request, cached hashes |
| MeowResolver | 22 registry / event-log / filesystem bypass checks | Yes (detection) | Remediation is opt-in per finding, logged in the report |
| JVM-Inspector | `-javaagent`, `-Dfabric.addMods`, `-Xbootclasspath`, `-agentpath`, `jdk.attach.allowAttachSelf` | Yes | Also enumerates loaded modules/DLLs and attach-listener files |
| PrefetchParametersCheck | `PrefetchParameters` key last-write vs. boot time | Yes | Generalised: last-write vs. boot for every watched registry key |

Weaknesses addressed across all references: Windows-only, separate executables per client,
console output only, signatures embedded in code, runtime downloads of unsigned tools, no
exportable report, no severity model.

---

## 2. Architecture

```
┌──────────────────────── Tauri window (React + Tailwind) ────────────────────────┐
│ Overview │ Scan progress │ Findings │ Process detail │ Mods │ Report export     │
└───────────────▲───────────────────────────────────────────────────▲─────────────┘
                │ invoke() commands                                  │ events (progress, finding)
┌───────────────┴────────────────────── src-tauri (app shell) ──────┴─────────────┐
│ commands.rs · state.rs · elevation check                                        │
└───────────────▲─────────────────────────────────────────────────────────────────┘
                │ library API
┌───────────────┴────────────── crates/inspection (platform-neutral core) ───────┐
│ orchestrator → modules: memory · mods · launch_arguments · files · artifacts    │
│               · network · bypass · signatures · report                          │
│ platform/{windows,linux}: process memory, journals, registry, event logs        │
└─────────────────────────────────────────────────────────────────────────────────┘
```

The core crate has no Tauri dependency, so it can also ship as a CLI (`crates/inspection_cli`)
for headless use.

### 2.1 Workspace layout

```
letsSS/
├── Cargo.toml                       # [workspace] + [workspace.dependencies]
├── crates/
│   ├── inspection/
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── finding.rs           # Finding, Severity, Evidence
│   │   │   ├── orchestrator.rs      # runs modules, emits progress
│   │   │   ├── signatures/          # database load, decode, Aho-Corasick build
│   │   │   ├── memory/              # region walk, chunk reader, matcher
│   │   │   ├── mods/                # jar, class constant pool, obfuscation, hash lookup
│   │   │   ├── launch_arguments.rs  # JVM command-line analysis
│   │   │   ├── files/               # PE/ELF strings, imports, sections, bulk path list
│   │   │   ├── artifacts/           # prefetch, usn, bam, shellbags, recycle bin, shell history
│   │   │   ├── network.rs           # DNS cache, hosts file
│   │   │   ├── bypass/              # registry/policy/event-log tamper checks
│   │   │   ├── report.rs            # JSON + HTML export
│   │   │   └── platform/{mod.rs, windows/, linux/}
│   │   └── tests/
│   └── inspection_cli/
├── signatures/                      # source TOML files, compiled into binary by build.rs
├── src-tauri/                       # existing app shell
└── src/                             # existing React frontend
```

### 2.2 Dependencies

| Purpose | Crate |
|---|---|
| Multi-pattern search | `aho-corasick`, `memchr` |
| Parallelism | `rayon` |
| JAR / ZIP | `zip` |
| PE / ELF | `goblin` |
| Hashing | `sha1`, `sha2` |
| Windows APIs | `windows` (Win32_System_Diagnostics_Debug, ProcessStatus, Registry, EventLog, Ioctl, Security_WinTrust) |
| Linux APIs | `nix` (`process_vm_readv`, `/proc`) |
| Process listing | `sysinfo` |
| HTTP (Modrinth) | `reqwest` (rustls) |
| Serialization | `serde`, `serde_json`, `toml` |
| Errors | `thiserror` (core), `anyhow` (app, CLI) |
| Signature integrity | `ed25519-dalek` |

---

## 3. Inspection Modules

Each module implements one trait and returns `Vec<Finding>`; the orchestrator runs them in
parallel where they do not compete for disk.

```rust
pub trait Inspection {
    fn identifier(&self) -> &'static str;
    fn run(&self, context: &Context, progress: &Progress) -> Result<Vec<Finding>, InspectionError>;
}
```

### 3.1 Process Memory (`memory`)

1. Enumerate `java`/`javaw` processes plus known launchers (Lunar, Badlion, Feather, Prism,
   MultiMC, TLauncher) and standalone clicker candidates (any process with an autoclicker
   import profile).
2. Region walk — Windows: `VirtualQueryEx`, `MEM_COMMIT`, readable, no `PAGE_GUARD`.
   Linux: `/proc/<pid>/maps`, `r` permission, skip `[vvar]`.
3. Read in 16 MB chunks with a `max_pattern_len` overlap so matches across chunk borders are
   not lost (the reference tools miss these). Windows `ReadProcessMemory`, Linux
   `process_vm_readv`.
4. One Aho-Corasick automaton per encoding: raw bytes, UTF-16LE, Java modified UTF-8.
5. Generic module strings require word boundaries and a minimum co-occurrence count
   (e.g. three distinct combat modules) before raising above `Low` severity.
6. Evidence: address, region protection, 64-byte excerpt.
7. Also checked: loaded modules (`EnumProcessModulesEx` / `/proc/<pid>/maps` file mappings)
   for DLLs/`.so` outside the JRE and Minecraft directories; `PAGE_EXECUTE_READWRITE`
   private regions with PE headers (manual-map injection).

### 3.2 Launch Arguments (`launch_arguments`)

Command line via `NtQueryInformationProcess` / `/proc/<pid>/cmdline`. Flags:

| Argument | Severity |
|---|---|
| `-javaagent:` (non-whitelisted agent) | High |
| `-agentpath:`, `-agentlib:` (except whitelisted) | High |
| `-Xbootclasspath/p:` / `/a:` | High |
| `-Djdk.attach.allowAttachSelf=true` | High |
| `-Dfabric.addMods`, `-Dloader.addMods`, `-Dfabric.gameJarPath` | Medium |
| `-Djava.library.path`, `-Djna.boot.library.path` outside launcher dir | Medium |
| `--tweakClass`, `--launchTarget` unknown | Medium |

Additional: JVM attach listener presence (`.attach_pid<pid>` in temp / `\\.\pipe\javatool<pid>`).

### 3.3 Mods (`mods`)

Inputs: every `mods` folder found under `.minecraft`, launcher instance directories
(Prism, MultiMC, CurseForge, Modrinth App, Lunar, Feather), plus operator-supplied paths.

Pipeline per JAR:
1. SHA1 → local cache → batched `POST https://api.modrinth.com/v2/version_files`. Match
   marks `Verified` but the JAR is still structurally inspected (fake identity check).
2. Read entries in memory; recurse into `META-INF/jars/` nested JARs.
3. Parse `.class` constant pools — class names, method names, string literals — and match
   against signatures. Avoids false hits on compressed bytes.
4. Normalise fullwidth / homoglyph Unicode before matching (`Ａｕｔｏ Ｃｒｙｓｔａｌ`).
5. Obfuscation metrics: single-letter path ratio, numeric/CJK/confusion-character names,
   known obfuscator markers (Skidfuscator, Radon, Caesium, Bozar, Branchlock, Binscure,
   Paramorphism, Zelix, Stringer, JNIC, Scuti, qProtect).
6. Structure: hollow shell (≤3 classes + one nested JAR), `Runtime.exec`, `URLClassLoader`
   / `defineClass` from network bytes, HTTP POST of system properties, `fabric.mod.json` id
   impersonating a known mod (sodium, lithium, iris) with mismatched hash.
7. Origin: `Zone.Identifier` ADS (Windows), `user.xdg.origin.url` xattr (Linux).

### 3.4 Executable Files (`files`)

Inputs: Downloads, Desktop, Temp, AppData, recent-execution paths from artifacts, and bulk
path lists (Everything export, `paths.txt`). Trusted-path whitelist applies only when the file
has no cheat-signature hit.

Per file: Authenticode (`WinVerifyTrust`); ASCII + UTF-16 strings (min 4); .NET `#Strings`
and `#US` heaps; PE imports (`SendInput`, `mouse_event`, `SetWindowsHookEx`,
`WriteProcessMemory`, `CreateRemoteThread`, `NtMapViewOfSection`); packer sections
(`.vmp0`, `.themida`, `UPX0`); runtime packers (PyInstaller, Nuitka). Linux: ELF dynamic
symbols (`XTestFakeButtonEvent`, `uinput`, `ptrace`, `process_vm_writev`).

Rule tags kept compatible with MeowImportsChecker (A, sA, B, C, D, E, F, G, I, P) so
operators trained on it recognise output.

### 3.5 Execution Artifacts (`artifacts`)

| Artifact | Windows | Linux |
|---|---|---|
| Program execution | Prefetch (`.pf`, MAM decompression via `RtlDecompressBufferEx`), BAM/DAM, UserAssist, AmCache | Shell history (bash/zsh/fish), `~/.local/share/recently-used.xbel`, systemd user journal |
| File deletion / replacement | USN Journal read natively (`FSCTL_READ_USN_JOURNAL`), filter `.jar`/`.exe`/`.dll` renames and deletes since boot; Recycle Bin `$I` files | Recently modified files in `mods`, `/tmp`, `~/.cache`; Trash `info/*.trashinfo` |
| Folder access | ShellBags, `OpenSavePidlMRU`, RecentDocs | `~/.config/*/recent*` |
| JAR execution | Prefetch referencing `.jar` paths, `javaw` launched with `-jar` | Shell history `java -jar` |

All artifacts are merged into one timeline sorted by timestamp, annotated with whether the
referenced file still exists (deleted-path tracking from MeowImportsChecker).

### 3.6 Network (`network`)

DNS cache entries (`DnsGetCacheDataTable`; Linux: `resolvectl` statistics are unavailable
per-domain, so read `systemd-resolved` journal and browser history domains instead) and hosts
file entries redirecting forensic or cheat domains.

### 3.7 Bypass / Tamper Detection (`bypass`) — Windows

All 22 MeowResolver checks, plus:
- `PrefetchParameters`, `SysMain`, `EventLog`, `BAM` service keys — last-write vs. boot time.
- SysMain/EventLog/DPS/PcaSvc/DiagTrack service stopped or disabled.
- USN Journal recreated since boot (journal ID creation time > boot).
- Event log cleared (1102, 104), time changed (4616, >30 s), journal deleted (3079, 501).
- Recycle Bin emptied recently, `fsutil` / `wevtutil` / `vssadmin` in recent executions.
- Virtual machine / sandbox indicators and running screen-recording blockers.

Linux equivalents: shell history truncated or `HISTFILE` unset, journal vacuumed
(`journalctl --header` first entry vs. boot), `LD_PRELOAD` in Minecraft process environment.

Remediation (Resolver mode) lives behind an explicit per-finding action, never automatic.

---

## 4. Signature Database

Signatures are data, not code. Source files in `signatures/*.toml`, one file per category.

```toml
[[client]]
name = "Example Client"
category = "pvp"                 # pvp | crystal | utility | clicker | ghost | loader
patterns = [
  { value = "example/client/module/combat/KillAura", scope = ["memory", "mods"] },
  { value = "exampleclient.net", scope = ["dns"] },
]

[[generic]]
name = "Kill Aura"
category = "combat"
patterns = ["KillAura", "Kill Aura"]
boundary = true
weight = 3
```

- `build.rs` compiles TOML to a compact binary blob, XOR-encoded with a per-build key so
  plain strings do not appear in the executable (reference tools use obfuscation for the
  same reason).
- Optional online update: signed blob (`ed25519`) fetched from a configured URL, verified
  against an embedded public key, cached locally. Offline operation always works.
- Coverage target: top 100 PvP clients and clickers (Vape V4/Lite, Doomsday, Prestige,
  Novoware, Argon, Krypton, 198Macros, Meteor, LiquidBounce, Wurst, Sigma, Rise, Raven,
  Slinky, Itami, Dream, Entropy, Drip, Koid, Gs Clicker, OPAutoClicker, etc.), seeded from
  the lists in §1 sources and expanded by sample analysis.

---

## 5. Finding Model and Scoring

```rust
pub struct Finding {
    pub module: &'static str,
    pub severity: Severity,          // Informational | Low | Medium | High | Critical
    pub title: String,
    pub client: Option<String>,      // set when a specific client is identified
    pub evidence: Vec<Evidence>,     // path / pid+address / registry key / event record
    pub timestamp: Option<SystemTime>,
}
```

Verdict per session: `Clean`, `Suspicious` (Medium findings or ≥ N Low), `Detected`
(any client-specific hit or High/Critical). Tamper findings raise the verdict one level,
since evidence destruction itself is reportable in SS procedure.

---

## 6. Tauri Interface

Commands (`src-tauri/src/commands.rs`):

| Command | Purpose |
|---|---|
| `system_information` | OS, elevation state, boot time, detected Minecraft installations |
| `start_inspection(modules, paths)` | Starts orchestrator on a worker thread, returns session id |
| `cancel_inspection(session)` | Cooperative cancellation via `AtomicBool` |
| `session_findings(session)` | Full finding list |
| `export_report(session, format)` | JSON / HTML report written to chosen path |
| `apply_remediation(finding_id)` | Resolver action, Windows only, confirmation in UI |

Events: `inspection://progress` `{ module, fraction, detail }`, `inspection://finding`
(streamed as discovered so the operator sees hits immediately).

Elevation: Windows manifest `requireAdministrator` for the release build; Linux shows a
banner and limits memory scanning to same-user processes unless run with `CAP_SYS_PTRACE`.

---

## 7. Frontend

Stack: React 19, Tailwind CSS 4 (`@tailwindcss/vite`), `lucide-react` icons. No router —
a sidebar switches views held in component state.

| View | Content |
|---|---|
| Overview | Elevation status, detected Minecraft instances and running Java processes, module checkboxes, Start button |
| Progress | Per-module progress bars, live finding counter, Cancel |
| Findings | Verdict banner, table grouped by module, filter by severity, expandable evidence rows |
| Timeline | Merged artifact timeline, filter `.jar` / deleted only |
| Mods | Per-JAR card: Verified / Unknown / Flagged, origin, obfuscation metrics |
| Report | Export JSON / HTML, copy summary for Discord |

Visual design: dark neutral theme (zinc-950 background), single accent colour, severity
colours red/orange/yellow/blue/zinc. Window 1100×720, minimum 900×600.

---

## 8. Platform Matrix

| Capability | Windows | Linux |
|---|---|---|
| Process memory scan | Full | Full (root or ptrace scope 0) |
| Launch arguments | Full | Full |
| Mods analysis | Full | Full |
| Executable analysis | PE + .NET + Authenticode | ELF + PE (Wine prefixes) |
| Execution artifacts | Prefetch, BAM, USN, ShellBags, AmCache | Shell history, recently-used, journal |
| DNS cache | Native API | Limited |
| Bypass detection | Full (§3.7) | Reduced set |
| Remediation | Yes | No |

---

## 9. Implementation Order

1. Workspace conversion, `inspection` crate skeleton, `Finding` model, orchestrator, Tauri
   commands and events, frontend shell with Tailwind.
2. Signature database format + `build.rs` compiler.
3. Launch arguments and process memory (Windows, then Linux).
4. Mods analysis with Modrinth lookup.
5. Execution artifacts: Prefetch, BAM, USN; Linux history.
6. Bypass detection.
7. Executable file analysis and bulk path list mode.
8. Report export, signed signature updates, CLI.
