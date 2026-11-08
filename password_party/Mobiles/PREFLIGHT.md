# Standalone preflight

Start or inspect AV scans before checkout, without creating accounts, publishing GPO changes, disjoining machines, running checkout hooks, changing boot options, or editing mounts:

```powershell
.\Mobiles.ps1 -Preflight -Name example
```

Repeat the same command to inspect running scans or the latest completed result. It returns after dispatch/status collection and does not wait for scan completion. Completed attempts are reused until you explicitly request a new scan:

```powershell
.\Mobiles.ps1 -Preflight -Name example -Rescan
```

An active scan is always reused, even with `-Rescan`. To query inventory/status/history without starting a missing scan:

```powershell
.\Mobiles.ps1 -Preflight -Name example -SkipScans
```

Override the definition-age threshold or scan timeout for a run:

```powershell
.\Mobiles.ps1 -Preflight -Name example -DefinitionMaxAgeDays 3 -ScanTimeoutMinutes 360
```

`-SkipScans` and `-Rescan` are mutually exclusive. Timeout/path overrides affect the next dispatched scan, not a scan already running.

The manifest's `DefaultConfig.Preflight` holds defaults: seven days, 240 minutes, Windows `C:`, Linux `/`, and optional Symantec scan name/executable overrides. A full `Preflight` dictionary can also be supplied through the existing configuration override. Configure additional Windows drives and Linux paths there as needed. Prefer an existing SEP administrator scan name when your site requires a specific scan policy. Paths, arguments, and outcomes are recorded in the normal `.log`/`.jsonl` audit pair under `MobileDeployments`.

## Outcomes

The console report lists each target, platform, definition status, current scan state, latest managed scan result/time. States include `NotStarted`, `Starting`, `Running`, `Clean`, `ThreatsDetected`, `CompletedNeedsReview`, `Failed`, `TimedOut`, and `Interrupted`. Pending scans are labeled `Pending` in the readable audit; they are not counted as successful readiness checks. Read the audit log for version/core-server observations, definition age/threshold, scanner output, exit code, and timestamps. A missing host is reported explicitly. `Invoke-MobilePreflight -MobileName example -PassThru` also returns the host records for PowerShell callers.

Definition status is `Current`, `Stale`, `FutureDate`, or `Unknown`. Recognized unambiguous dates are compared by UTC calendar date. Unknown/unsupported date formats are not guessed; the vendor value remains in the inventory details. Preflight does not download or install signatures.

Linux dispatches a root-owned transient systemd service through `dzdo`. Its worker runs `clamscan` with a timeout, configured paths, and an explicit per-scan `--log` file. `clamscan` has no universal results directory; this program creates durable managed history under `/var/log/mobiles/preflight` by default (`Preflight.LinuxScanStateDirectory`). It uses `bash`, `systemd-run`/`systemctl`, `flock`, `jq`, GNU `date`/coreutils, and procps. A dispatch lock, service state, and native `clamscan` process detection prevent duplicate scans. Services survive SSH disconnects. Abandoned/inactive workers are reported as `Interrupted` rather than being mistaken for successful completion.

ClamAV scans configured paths recursively, excluding `/proc`, `/sys`, `/dev`, and `/run`. Other mounted filesystems beneath a configured path may be included. No removal/quarantine options are supplied. Exit codes map to `Clean` (0), `ThreatsDetected` (1), `Failed` (other errors), or `TimedOut`. The worker persists exit status, UTC times, scanned paths, definition version, and up to 64 KiB of stdout/stderr per stream; the complete native log remains on the endpoint. A historical clean result is not treated as current readiness evidence when its paths or definition version differ from the current request. Existing unmanaged ClamAV logs are not assumed to be clean scan history. See the [ClamAV manual](https://github.com/Cisco-Talos/clamav/blob/main/docs/man/clamscan.1.in).

Windows dispatches the persistent `Mobiles-PreflightAV` scheduled task as SYSTEM, with protected worker/state files under `%ProgramData%\Mobiles\Preflight` by default (`Preflight.WindowsScanStateDirectory`). The worker waits on `DoScan.exe /Sync` and records completion; the administrator's preflight call returns after starting the task. The two standard DoScan installation locations are tried unless a custom executable path is supplied. The native `GlobalScanStatus` registry value is also checked, so active SEP scans started elsewhere are respected. Existing native completion/status and recent AV-log excerpts are reported when available. Latest native AV-log timestamps describe log modification, not necessarily a scan completion timestamp.

**Symantec exit zero means completion, not absence of detections.** Results remain `CompletedNeedsReview`; recent native AV-log excerpts/paths and managed worker results are included for review. The endpoint's configured policy can take its normal remediation actions. On timeout the worker stops the launcher, but the SEP service may still be scanning; native running status takes precedence on later queries. Actual SEP versions, Windows Task Scheduler integration, and RHEL/dzdo authorization require on-site validation. See [Broadcom article 151455](https://knowledge.broadcom.com/external/article?legacyId=TECH104287) and [native scan status](https://knowledge.broadcom.com/external/article/179001/check-the-current-scan-status-of-an-endp.html).

Endpoint history is retained across preflight calls. Each administrator call writes a new audit snapshot; a previously returned `.log`/`.jsonl` is not updated automatically when a background worker finishes. Run preflight again to collect the new result. `LastScan` and `LastScanUtc` show the latest managed completed attempt, including failed attempts, while a newer scan can be `Running`. Historical scan age is shown rather than silently triggering another full scan; request `-Rescan` when fresh evidence is needed. Old endpoint histories can be archived/pruned by an administrator when no scan is active.

A host is marked successful only with current definitions, a managed clean result matching current Linux scope/definitions, and no reported failures. Consequently SEP scans require log review, and missing scans remain unevaluated. Preflight completion does not automatically authorize or gate a later checkout; it is a separate command.

## Scope

Preflight evaluates AV definitions and scan history only. It does not query SMB/FIPS state, infer sharing intent, or require mount verification for a successful AV assessment. The `-Smb` preflight option has been removed.

SMB authentication, mounts, and any related FIPS compatibility checks belong to a separate verification stage for mobiles that use shares, after all machines have left the domain and disconnected from the domain network. That stage is not implemented by this command. Preflight does not edit boot options, crypto policy, credential files, or `fstab`.

Run `pwsh -NoProfile -File ./tests/Verify-Preflight.ps1` for fake-scanner and transport-fixture checks. These do not execute real malware scans or modify FIPS/boot settings.
