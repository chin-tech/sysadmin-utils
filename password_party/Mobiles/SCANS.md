# AV scans

Start or inspect AV scans for a mobile, separately from checkout:

```powershell
.\Mobiles.ps1 -Scan -Name example
```

The controller checks AV definitions and existing scan state first. If no scan exists, it starts one only when definitions are current. Repeat the same command to see running scans or the latest completed result. Calls return after dispatch/status collection and never wait for the scan to finish. Completed attempts are reused until you request a fresh attempt:

```powershell
.\Mobiles.ps1 -Scan -Name example -Rescan
```

New scans require definitions within the configured age limit (30 UTC calendar days inclusive by default). Stale, missing/unrecognized, or future-dated definitions prevent dispatch and report `BlockedDefinitions`; existing scans and history remain visible. `-Force` bypasses only this definition gate:

```powershell
.\Mobiles.ps1 -Scan -Name example -Force
# Request a fresh attempt when completed history already exists:
.\Mobiles.ps1 -Scan -Name example -Rescan -Force
```

An active scan is always reused, including with `-Rescan` or `-Force`. Forced scans still report stale/unknown definitions and do not make those hosts ready. `-Force` alone does not replace completed history.

The scan command has only `-Rescan` and `-Force` controls. Definition age, timeout, scan paths, tool directories, and Symantec settings belong in the existing `DefaultConfig.Preflight` configuration dictionary. The dictionary name, Windows task name, locks, and endpoint directories remain unchanged so existing configuration, active jobs, and history continue working. Defaults are 30 days, 240 minutes, Windows `C:`, and Linux `/`; additional paths or an existing SEP administrator scan name can be configured there. Configuration changes apply to the next dispatched scan, not one already running.

Windows dispatch uses the shared `New-TaskXML` builder with an encoded PowerShell action, registered as SYSTEM and explicitly started without an automatic trigger. Scan options, output, and results remain in the protected state directory; no separate generated `worker.ps1` is needed. Each controller call records a `Scan` audit snapshot in the normal `.log`/`.jsonl` pair under `MobileDeployments`.

## How scan state is stored

Each scan has its own directory. The worker writes ordinary files: `status` (`Starting`, `Running`, then `finished`), `exit-code`, `started-utc`, `completed-utc`, and scanner output/log files. An `error` file is added for a Windows launcher failure. The root's `latest` and `completed` files contain paths to the current and last completed attempts. Linux also keeps the requested paths and definition version, and records excluded NFS paths in a NUL-separated file so spaces, newlines and backslashes are preserved.

The workers do not build JSON reports or assess definition age. A status reader collects files and checks whether the scheduled task/service or native scanner is still active. An unfinished inactive attempt is reported as interrupted, with a short grace period for a newly queued job. The controller first reads status, checks definitions and the requested scan policy, and requests a start only when appropriate; the endpoint rechecks activity under its dispatch lock before starting. Readiness, exit-code interpretation and Linux scope/definition matching are assessed on the controller.

A `finished` file means the process ended, not that the scan was clean: its exit code determines the report status. Workers keep the complete output files; readers bound audit excerpts. Existing `latest.json`, `completed.json`, and per-run `result.json` histories remain readable without migration. Do not edit files while a scan is active.

## Outcomes

The console report lists each target, platform, definition status, current scan state, latest managed scan result/time. States include `NotStarted`, `Starting`, `Running`, `Clean`, `ThreatsDetected`, `CompletedNeedsReview`, `Failed`, `TimedOut`, and `Interrupted`. Pending scans are labeled `Pending` in the readable audit; they are not counted as successful readiness checks. Read the audit log for AV version/definition observations, definition age/threshold, scanner output, exit code, and timestamps. A missing host is reported explicitly. `Invoke-MobileScan -MobileName example -PassThru` also returns the host records for PowerShell callers.

Definition status is `Current`, `Stale`, `FutureDate`, or `Unknown`. Recognized unambiguous dates are compared by UTC calendar date. Unknown/unsupported date formats are not guessed; the vendor value remains in the inventory details. The scan command does not download or install signatures.

Linux dispatches a root-owned transient systemd service through `dzdo`. Its worker runs `clamscan` with a timeout, configured paths, and an explicit per-scan `--log` file. `clamscan` has no universal results directory; this program creates durable managed history under `/var/log/mobiles/preflight` by default (`Preflight.LinuxScanStateDirectory`). It uses `bash`, `systemd-run`/`systemctl`, `flock`, `jq`, GNU `date`/coreutils, and procps. A dispatch lock, service state, and native `clamscan` process detection prevent duplicate scans. Services survive SSH disconnects. Abandoned/inactive workers are reported as `Interrupted` rather than being mistaken for successful completion.

Both the elevated dispatcher and detached worker use `Preflight.LinuxToolDirectories` as their explicit PATH. Defaults include `/usr/local/bin`, `/usr/local/sbin`, and the standard system directories; add your site's custom tool directories there if needed. Use only administrator-controlled directories, since these commands run as root. This avoids dependencies disappearing when dzdo or systemd supplies a different PATH from the SSH login. Missing dependency errors include the searched PATH.

ClamAV scans configured paths recursively, excluding `/proc`, `/sys`, `/dev`, and `/run`. At the start of each Linux worker, mounted `nfs` and `nfs4` directories (including bind mounts) are discovered from `/proc/self/mountinfo` and excluded automatically. Spaces, backslashes, and regex characters in mount paths are handled as literal path characters. `ExcludedNfsMounts` is recorded in running/completed state and the collected audit details. If mount information cannot be read, the scan fails without launching ClamAV. Mounts added after discovery are not covered until a fresh scan; keep mounts stable during a scan. Other filesystem types beneath a configured path may still be included. No removal/quarantine options are supplied. Exit codes map to `Clean` (0), `ThreatsDetected` (1), `Failed` (other errors), or `TimedOut`. The scan directory retains exit status, UTC times, scanned paths, definition version, and stdout/stderr; the reader includes up to 64 KiB per stream in the report; the complete native log remains on the endpoint. A historical clean result is not treated as current readiness evidence when its paths or definition version differ from the current request. Existing unmanaged ClamAV logs are not assumed to be clean scan history. See the [ClamAV manual](https://github.com/Cisco-Talos/clamav/blob/main/docs/man/clamscan.1.in).

Windows dispatches the persistent `Mobiles-PreflightAV` scheduled task as SYSTEM, with protected worker/state files under `%ProgramData%\Mobiles\Preflight` by default (`Preflight.WindowsScanStateDirectory`). The worker waits on `DoScan.exe /Sync` and records completion; the administrator's scan call returns after starting the task. The two standard DoScan installation locations are tried unless a custom executable path is supplied. The native `GlobalScanStatus` registry value is also checked, so active SEP scans started elsewhere are respected. Existing native completion/status and recent AV-log excerpts are reported when available. Latest native AV-log timestamps describe log modification, not necessarily a scan completion timestamp.

**Symantec exit zero means completion, not absence of detections.** Results remain `CompletedNeedsReview`; recent native AV-log excerpts/paths and managed worker results are included for review. The endpoint's configured policy can take its normal remediation actions. On timeout the worker stops the launcher, but the SEP service may still be scanning; native running status takes precedence on later queries. Actual SEP versions, Windows Task Scheduler integration, and RHEL/dzdo authorization require on-site validation. See [Broadcom article 151455](https://knowledge.broadcom.com/external/article?legacyId=TECH104287) and [native scan status](https://knowledge.broadcom.com/external/article/179001/check-the-current-scan-status-of-an-endp.html).

Endpoint history is retained across scan calls. Each administrator call writes a new audit snapshot; a previously returned `.log`/`.jsonl` is not updated automatically when a background worker finishes. Run `-Scan` again to collect the new result. `LastScan` and `LastScanUtc` show the latest managed completed attempt, including failed attempts, while a newer scan can be `Running`. Historical scan age is shown rather than silently triggering another full scan; request `-Rescan` when fresh evidence is needed. Old endpoint histories can be archived/pruned by an administrator when no scan is active.

A host is marked successful only with current definitions, a managed clean result matching current Linux scope/definitions, and no reported failures. Consequently SEP scans require log review, and missing scans remain unevaluated. Scan completion does not automatically authorize or gate a later checkout; it is a separate command.

## Scope

The scan command evaluates AV definitions and scan history only. It does not change networking, boot options, crypto policy, credential files, or `fstab`.
