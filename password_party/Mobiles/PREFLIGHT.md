# Standalone preflight

Run inventory and AV scans before checkout, without creating accounts, publishing GPO changes, disjoining machines, running checkout hooks, changing boot options, or editing mounts:

```powershell
.\Mobiles.ps1 -Preflight -Name example
```

For inventory without scans:

```powershell
.\Mobiles.ps1 -Preflight -Name example -SkipScans
```

Override the definition-age threshold or scan timeout for a run:

```powershell
.\Mobiles.ps1 -Preflight -Name example -DefinitionMaxAgeDays 3 -ScanTimeoutMinutes 360
```

The manifest's `DefaultConfig.Preflight` holds defaults: seven days, 240 minutes, Windows `C:`, Linux `/`, and optional Symantec scan name/executable overrides. A full `Preflight` dictionary can also be supplied through the existing configuration override. Configure additional Windows drives and Linux paths there as needed. Prefer an existing SEP administrator scan name when your site requires a specific scan policy. Paths, arguments, and outcomes are recorded in the normal `.log`/`.jsonl` audit pair under `MobileDeployments`.

## Outcomes

The console report lists each target, platform, definition status, scan outcome, and SMB readiness. Read the audit log for version/core-server observations, definition age/threshold, scanner output, exit code, and timestamps. A missing host is reported explicitly. `Invoke-MobilePreflight -MobileName example -PassThru` also returns the host records for PowerShell callers.

Definition status is `Current`, `Stale`, `FutureDate`, or `Unknown`. Recognized unambiguous dates are compared by UTC calendar date. Unknown/unsupported date formats are not guessed; the vendor value remains in the inventory details. Preflight does not download or install signatures.

Linux uses `clamscan`, invoked via `dzdo`, with `timeout`, `jq`, and GNU `date`/coreutils available. It scans configured paths recursively and excludes `/proc`, `/sys`, `/dev`, and `/run`. Other mounted filesystems beneath a configured path may be included. It does not pass removal or quarantine options. Exit codes map to `Clean` (0), `ThreatsDetected` (1), `Failed` (other errors), or `TimedOut`. Scan stdout/stderr in the audit is limited to 64 KiB per stream. A clean outcome applies to the configured scope and ClamAV's scanning limits, not necessarily every byte on the machine. See the [ClamAV manual](https://github.com/Cisco-Talos/clamav/blob/main/docs/man/clamscan.1.in).

Windows uses Symantec Endpoint Protection's `DoScan.exe /Sync`, with configured scan directories or an existing `/ScanName`. The two standard installation locations are tried unless a custom executable path is supplied. **Exit zero means completion, not absence of detections.** This is reported as `CompletedNeedsReview`; recent endpoint AV-log locations are included for review. The endpoint's configured SEP policy can take its normal remediation actions; this command does not change that policy. On timeout the launcher is stopped, but the SEP service may still be scanning. Actual SEP versions and remote execution require validation on site. See [Broadcom article 151455](https://knowledge.broadcom.com/external/article?legacyId=TECH104287).

A host is marked successful only with current definitions, a verified clean scan result, no reported failures, and no outstanding SMB check. Consequently SEP scans require log review, skipped scans remain unevaluated, and SMB-enabled Linux hosts still need a real mount test. Preflight completion does not automatically authorize or gate a later checkout; it is a separate command.

## Workgroup SMB and FIPS

SMB intent is inferred when a mobile has Windows and Linux hosts and its Windows post-deployment selection includes `NetworkSharing`. Use `-Smb` to request this check explicitly or `-Smb:$false` to omit it for a run.

Linux reports its current `/proc/sys/crypto/fips_enabled` state and, on RHEL 8, the current crypto policy. An active FIPS kernel or FIPS crypto policy produces `BlockedByFips`; an unknown runtime state is reported as unknown. A non-FIPS runtime produces `RequiresMountTest`, not an assertion that credentials or SMB connectivity work.

Preflight deliberately does not set `fips=0`, reboot hosts, change crypto policy, create credential files, or edit `fstab`. A boot argument change only applies after reboot, and RHEL 8's FIPS/crypto-policy/initramfs state is broader than that one argument. Red Hat warns that turning off established FIPS mode can leave an inconsistent system; see [RHEL 8 guidance](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/security_hardening/switching-rhel-to-fips-mode_security-hardening).

Workgroup mounts are intended to use the Windows-local SMB account through a root-owned credential file. Concrete host/share/IP/mount mappings are still needed before implementing that provisioning and its check-in cleanup/restoration behavior. The standalone preflight command does not modify the existing SMB provisioning implementation.

Run `pwsh -NoProfile -File ./tests/Verify-Preflight.ps1` for fake-scanner and transport-fixture checks. These do not execute real malware scans or modify FIPS/boot settings.
