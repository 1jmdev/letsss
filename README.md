# letsSS

Free and open-source Minecraft screenshare (SS) tool. letsSS inspects a machine for cheat
clients, ghost clients, autoclickers, and anti-forensic tampering. It ships as a desktop app
and as a single command-line executable for Windows and Linux.

Everything runs locally. The only network request is an optional Modrinth lookup of mod
SHA-1 hashes, which can be disabled with `--offline`.

## Quick start

### Windows (PowerShell)

```powershell
powershell -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/1jmdev/letsss/main/scripts/run.ps1 | iex"
```

### Linux

```bash
curl -fsSL https://raw.githubusercontent.com/1jmdev/letsss/main/scripts/run.sh | bash
```

Both commands download the latest release from
[GitHub Releases](https://github.com/1jmdev/letsss/releases/latest) and start it with
administrator / root rights, which are required for memory and system artifact inspection.

The desktop app installers (`.msi` / `.exe` for Windows, `.deb` / `.AppImage` for Linux) are
on the same release page.

## What it checks

| Module | Coverage |
| --- | --- |
| Process memory | Signature scan of running Minecraft processes, manually mapped images, foreign native modules |
| Launch arguments | Java agents, boot class path changes, injected JVM options, attach handshakes |
| Processes | Macro software, autoclickers, cheat-named processes |
| Mods | Mod folders of every major launcher, version JARs, Modrinth verification, obfuscation, game logs |
| Executable files | Downloads, Desktop, Temp, and running programs: strings, imports, packers, signatures |
| Execution artifacts | Prefetch, USN journal, BAM, recycle bin, shell history |
| Network | DNS cache and hosts file entries for cheat domains |
| Bypass detection | Cleared event logs, disabled services, deleted journals, blocked forensic tools |

Signatures live in [`crates/letsss_core/signatures`](crates/letsss_core/signatures) as TOML
and can be extended without code changes.

## Command-line usage

```
letsss [OPTIONS] [PATHS]...

  -m, --modules <MODULES>  Run only these modules (memory, launch-arguments, processes,
                           mods, files, artifacts, network, bypass)
      --offline            Skip Modrinth hash verification
  -v, --verbose            Show informational findings and all evidence
      --json <FILE>        Also write the full report as JSON
      --no-pause           Do not wait for Enter before exiting
      --no-elevate         Do not request administrator rights on Windows
```

`PATHS` may be files, folders, or `.txt` path lists such as an Everything export.

## License

[MIT](LICENSE)
