This patch applies configuration once, fixes mobile definition round trips, and gates domain departure on provisioning and observed local account state.

Configuration precedence is module defaults, `cfg.psd1` beside `Mobiles.ps1`, then explicit `-ConfigOverride` values. `Set-MobileConfig` is the only function accepting a configuration hashtable. Paths derived from an overridden parent are recomputed unless explicitly supplied. Unknown keys, empty override values, and malformed GPO IDs are rejected before the module configuration changes. Existing callers using per-function `-Config` must switch to `Set-MobileConfig`.

CLI completion shows the command modes, `-Name`, and the default overview's `-Full` initially. Choose a mode first to discover its options: `-Scan` exposes only `-Rescan` and `-Force`, `-RegisterDeployment` exposes departure controls, and `-UnRegisterDeployment` exposes `-Archive`. Dynamic parameter definitions live in `Mobiles.ps1` and discovery does not load the deployment module or configuration. `-ConfigOverride` and PowerShell common parameters remain callable explicitly but are hidden from completion. `-Debug` replaces the removed `-enableDebug` switch. GPO requires exactly one of `-Add` or `-Remove`; `-Force` applies to GPO only with `-Remove`.

`cfg.example.psd1` shows the supported data-file format. PowerShell data files require literal values: the existing local `cfg.psd1` expression `"C:\Users\${env:USERNAME}"` cannot be imported. Replace that value with the actual Windows path, or omit `NfsHome` to derive it from `nfsHomeRoot` and the current username. Local configuration and credentials are not included in this patch.

The writer honors its destination, escapes CSV fields, and rejects path-like mobile names. The reader accepts both `fullname` and the legacy `name` column. Empty default-user directories no longer produce a phantom `.local` account.

Domain departure remains opt-in. For example:

```powershell
.\Mobiles.ps1 -RegisterDeployment -Name example -Disjoin
```

Windows verifies each expected local account is enabled and has its required group memberships. Any recorded deployment failure skips departure for that host. Linux creates accounts before verifying their presence in `/etc/passwd`, checks required wheel membership, and skips departure when preceding steps recorded failures. Linux account selection now uses the existing role priority.

Linux departure accepts `-LinuxDisjoinKeytab` to reuse a prepared credential. If omitted, it collects a Kerberos principal and current account key version, prompts for the domain password with `Read-Host -AsSecureString`, and generates the keytab through WinRM on the domain controller. The controller is discovered automatically in the current AD domain. Optional `-DomainPrincipal` and `-DomainKeyVersion` supply non-secret inputs; omitted values are prompted. Generation runs before remote deployment starts. The keytab principal must have permission to perform domain departure. No live Kerberos/domain integration was verified here.

These checks establish account existence and membership, not successful password authentication or interactive logon. Live Windows encryption/remoting and proprietary software collection still require representative machines. Setup is now an explicit administrator operation through `Initialize-Mobiles.ps1`; routine registration checks existing local prerequisites without repairing them, and telemetry never invokes setup. See `SETUP.md`. Sharing narrower asset paths and unifying logon role derivation remain follow-up work.

Run the focused offline regression checks with:

```powershell
pwsh -NoProfile -File ./tests/Verify-MobileChanges.ps1
```

The checks use the actual selected implementations with simulated external dependencies. They cover configuration derivation and invalid overrides, quoted-name round trips and legacy definitions, Windows missing/disabled accounts and missing memberships, generated Bash syntax, and the Linux failure gate. They do not execute remote deployments or replace the older Pester suite.

Centrify review: Delinea documents keytab-based departure via `kinit -kt <keytab> <principal>` followed by `adleave`. The current departure fragment still omits the principal and uses whichever `kinit` is on PATH; this can request a host principal instead of the user in the keytab. The privileged ticket-cache context also needs validation. See `KEYTAB.md` for vendor sources, version limits, and an authentication-only check. The Linux departure fragment was reviewed, not changed, in this pass. Password-based departure should use the interactive prompt through a protected input channel, subject to confirming the agent version's prompt behavior; do not put passwords in command arguments or generated scripts.

Windows telemetry now reads Symantec `LatestVirusDefsDate` and `LatestVirusDefsRevision` from `CurrentVersion\Public-Opstate`, trying the native location first and then `WOW6432Node`. It preserves the vendor date value without guessing its format. Details include the selected source, both registry read outcomes, and errors; absent keys are distinguished from access failures. See [Broadcom article 181033](https://knowledge.broadcom.com/external/article/181033/finding-the-current-info-including-defin.html).

Ivanti telemetry reads the `CoreServer` value under `HKLM\SOFTWARE\WOW6432Node\Intel\LANDesk\LDWM`, with a native-path fallback. The overview adds an `IVANTI CORE` column. This reports the configured core, not a verified connection or the last contacted server. Registry observations survive service-query failures. See [Ivanti client connectivity settings](https://help.ivanti.com/ld/help/en_US/LDMS/10.0/Windows/agent-h-client-connectivity.htm).

Run `pwsh -NoProfile -File ./tests/Verify-WindowsCollectors.ps1` for the registry fixture checks. These exercise the generated collector functions and syntax with simulated registry/service dependencies; real Windows registry layouts and installed agent behavior remain unverified. The unused legacy information collector is retained unchanged.

The keytab generator supplies the password to the native password prompt rather than putting it in process arguments. It sets `/answer -`, supplies no account mapping options, times out after 30 seconds, and keeps native output out of error messages. Native redirected-password input and compatibility with the account's Kerberos salt remain unverified; a successful fixture check does not demonstrate a usable keytab. Run `pwsh -NoProfile -File ./tests/Verify-KeytabPrompt.ps1` to verify prompt/generator wiring without domain access.

Module organization: related functions now live in collapsible `#region` sections. Shared utilities and account helpers appear near the top, followed by configuration, credentials/keytabs, GPO permissions and read-only environment checks, mobile definitions, Windows/Linux provisioning and cleanup, Windows/Linux collectors, collection orchestration (including legacy collectors), reporting, and deployment commands.

Removed unused internal helpers: `ConvertFrom-Base64`, `Repair-GpoPermissions`, `New-CustomGPO`, `New-DeployerCertificate`, `New-WindowsPostTask-SupportAcl`, and `Get-EncryptedCredRSA`. Also removed the unused `WindowsPayload` class and obsolete default-config alias. The logon-script comment now references the current certificate helper; the obsolete certificate test block was removed from the legacy Pester suite in favor of the existing focused certificate checks. Collector implementations, including the legacy collector and Bash sample, remain available together.

Validation: all four focused offline verification scripts pass. The module imports through its manifest, every declared public function remains exported, and retained function bodies match their previous implementations after trailing-whitespace normalization and removal of the obsolete commented support-ACL call. The legacy Pester suite still targets older interfaces elsewhere and was not run.

Literal PowerShell payload fragments now use `{ ... }` scriptblocks with `.ToString()` at the script-text boundary, so editors and PowerShell's parser can inspect their syntax. Bash here-strings and interpolated `@"` templates remain strings. Twenty generated payload variants were compared before/after and retain identical code tokens. The Windows collector checks also parse optional post-deployment combinations offline.

Deployment task selection now lives in `MobileManager.psd1` under `PrivateData.PSData.DefaultConfig.DeploymentTasks`:

```powershell
DeploymentTasks = @{
    Windows = @{
        Provisioning = @('Users', 'PasswordExpiry', 'Groups', 'BitLocker')
        Scheduled = @('LogArchiver', 'PostDeploy')
        PostDeployment = @('UserRights')
    }
    Linux = @{
        Provisioning = @('CreateDirectory', 'Luks', 'AddUsers')
    }
}
```

Remove a name to omit that step, or set an entire list to `@()`. Keep the platform and phase dictionaries present. Reload the module after editing the manifest (`Mobiles.ps1` already imports with `-Force`). Defaults retain the existing deployment steps. Supported task names map to existing implementations; introducing a new task requires updating the module's catalog and implementation as well as the manifest.

Selections execute in the module's canonical order, preserving account creation before privilege assignment and Linux directory creation before user creation. Unknown platforms/phases/task names and duplicate names are rejected. A `DeploymentTasks` override replaces the entire plan, so supply all its platform/phase dictionaries. Explicit `Get-PostDeployScript` switches can override its configured selection for direct callers; Linux `-SkipLuks` still suppresses the selected encryption step. Linux log rotation is managed by fleet logrotate configuration, independently of mobile check-in/check-out.

`Scheduled.PostDeploy` controls registration of the existing `Mobile-DisjoinTask` boot task; `PostDeployment` controls its generated contents. An empty post-deployment list omits that scheduled task. Windows provisioning selection travels in the remote payload. Linux-only deployments no longer construct Windows task XML. Cleanup removes all known managed scheduled tasks regardless of the current selection, allowing a mobile deployed under an earlier plan to be cleaned up.

Local account verification and domain departure gating remain mandatory when `-Disjoin` is requested, even if account creation or group assignment is disabled. Such a deployment needs the expected accounts and memberships to exist already. Domain departure remains opt-in and is not a configurable optional task. Offline checks cover selection ordering, invalid plans, disabled provisioning and scheduled/post-deployment tasks, and verification with provisioning disabled. Live platform integration remains unverified.

Procedure extension hooks now come from the root `Scripts/Check-out` and `Scripts/Check-in` folders. The former runs after registration provisioning and before departure; the latter runs before unregister cleanup. Self-contained `.ps1` and `.sh` snapshots run on matching target platforms in filename order. Failures feed the existing host result ledger and prevent departure/cleanup as appropriate. See `Scripts/README.md` for execution context, environment variables, time limits, and examples of reading audit files.

Both procedures create a unique append-only JSON-lines run journal in `MobileDeployments` before side effects begin and print its path at completion. It includes selected tasks/targets, hook names and hashes, returned host actions and failures, and an overall completion event. It avoids logging credential payloads and script contents; hook stdout/stderr are captured and truncated to 64 KiB per stream. Windows observations are saved before Linux work, so a later transport error does not discard earlier results. Existing scheduled jobs' later execution remains separate from the procedure's registration audit.

`tests/Verify-ProcedureHooks.ps1` executes harmless local PowerShell/Bash hook fixtures and mocks domain/remoting operations. It checks source snapshots, deterministic order, environment context, invalid PowerShell syntax, nonzero exits/errors, clean result JSON, both platform departure/cleanup failure gates, separate check-in/out logs, and failed completion after a transport exception. Live Windows remoting and Centrify/dzdo authorization still need environment validation.

Audit readability: every run now writes a readable `.log` beside its existing `.jsonl` journal. The readable file expands target names, selected tasks, host/action statuses, nested details, hook output, and failure messages without PowerShell object placeholders. Completion prints the readable path; `-Verbose` also shows the JSONL path. The exported `Show-MobileRunLog -Path ...` renders existing JSONL files, so old runs do not need to be repeated. Tests cover both in-memory event objects and deserialized historical JSONL records, nested action details, empty platform lists, and failure messages.

AV scans: `Mobiles.ps1 -Scan -Name <mobile>` checks AV definitions and runs ClamAV/SEP scans separately from checkout. The manifest contains a `Preflight` dictionary for definition-age limits, scan timeout/scope, and optional SEP executable/scan-name overrides. Every planned host receives a report/audit record, including unreachable or malformed responses. SEP completion is explicitly `CompletedNeedsReview`, since DoScan exit zero does not establish no detections. The scan command evaluates AV readiness only; see `SCANS.md` for scope and status meanings.

AV scans dispatch to independent endpoint workers rather than waiting over WinRM/SSH. Windows uses a protected SYSTEM scheduled task plus SEP's native scan-status registry; Linux uses a root-owned transient systemd service, explicit ClamAV log, and dispatch lock. Repeated calls reuse running/latest attempts, `-Rescan` requests a new attempt only when idle. Managed exit codes, timestamps, scan scope, and output survive controller disconnects. Reports show latest completed managed results alongside active state; abandoned workers become `Interrupted`. Readable audit summaries distinguish `Pending` and `NeedsReview` from failed scans. SEP results retain the required AV-log review. Updated offline tests execute detached fake scanner workers and exercise duplicate suppression, stored results, forced rescans, dispatch decisions, pending/interrupted states, and scope mismatches; native Windows scheduling/ACL and real RHEL/Centrify behavior still require environment validation.

The scan interface uses configuration for age limits, timeout, and scope. `-Rescan` requests a fresh attempt; `-Force` bypasses the definition gate without marking stale hosts ready. Normal repeated calls reuse active/completed attempts. The former `-Preflight`, `-SkipScans`, `-ForceScan`/`-force-scan`, and per-call policy overrides have been removed. `Invoke-MobileScan` exposes the same controls plus `-PassThru` for structured records. Existing `Preflight` configuration and endpoint identifiers remain stable to preserve running scans and history; new audit snapshots use procedure `Scan`.

Administrator setup is separate from `Mobiles.ps1` and from normal module imports. `Initialize-Mobiles.ps1` loads `Setup/MobileEnvironment.ps1` privately after applying configuration. `-Initialize` and the exported `Initialize-Environment` command have been removed. Registration audits its read-only prerequisite checks and stops before remote work if required local assets are missing.

Setup publication is now idempotent for unchanged healthy state. Managed GPO files and shortcut attributes are compared before writes; existing IDs, unrelated XML, AD metadata, ACLs, and OU settings are preserved. User revisions advance only on changes or explicit `Initialize-Mobiles.ps1 -ForceGpoRefresh`; the computer revision is preserved. Forced refresh backs up managed state and reconciles version mismatches or rebuilds malformed files. SSH ACLs are likewise compared before invoking icacls. See `SETUP.md` for recovery boundaries and `tests/Verify-GpoSetup.ps1` for offline publication/version fixtures.
