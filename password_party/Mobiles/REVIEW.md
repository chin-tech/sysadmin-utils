This patch applies configuration once, fixes mobile definition round trips, and gates domain departure on provisioning and observed local account state.

Configuration precedence is module defaults, `cfg.psd1` beside `Mobiles.ps1`, then explicit `-ConfigOverride` values. `Set-MobileConfig` is the only function accepting a configuration hashtable. Paths derived from an overridden parent are recomputed unless explicitly supplied. Unknown keys, empty override values, and malformed GPO IDs are rejected before the module configuration changes. Existing callers using per-function `-Config` must switch to `Set-MobileConfig`.

`cfg.example.psd1` shows the supported data-file format. PowerShell data files require literal values: the existing local `cfg.psd1` expression `"C:\Users\${env:USERNAME}"` cannot be imported. Replace that value with the actual Windows path, or omit `NfsHome` to derive it from `nfsHomeRoot` and the current username. Local configuration and credentials are not included in this patch.

The writer honors its destination, escapes CSV fields, and rejects path-like mobile names. The reader accepts both `fullname` and the legacy `name` column. Empty default-user directories no longer produce a phantom `.local` account.

Domain departure remains opt-in. For example:

```powershell
.\Mobiles.ps1 -RegisterDeployment -Name example -Disjoin
```

Windows verifies each expected local account is enabled and has its required group memberships. Any recorded deployment failure skips departure for that host. Linux creates accounts before verifying their presence in `/etc/passwd`, checks required wheel membership, and skips departure when preceding steps recorded failures. Linux account selection now uses the existing role priority.

Linux departure accepts `-LinuxDisjoinKeytab` to reuse a prepared credential. If omitted, it collects a Kerberos principal and current account key version, prompts for the domain password with `Read-Host -AsSecureString`, and generates the keytab through WinRM on the domain controller. Optional `-DomainController`, `-DomainPrincipal`, and `-DomainKeyVersion` supply the non-secret inputs; otherwise the controller is discovered and the remaining inputs are prompted. Generation runs before remote deployment starts. The keytab principal must have permission to perform domain departure. No live Kerberos/domain integration was verified here.

These checks establish account existence and membership, not successful password authentication or interactive logon. Live Windows encryption/remoting and proprietary software collection still require representative machines. Initialization still provisions the environment during registration; separating that behavior, sharing narrower asset paths, and unifying logon role derivation are follow-up work.

Run the focused offline regression checks with:

```powershell
pwsh -NoProfile -File ./tests/Verify-MobileChanges.ps1
```

The checks use the actual selected implementations with simulated external dependencies. They cover configuration derivation and invalid overrides, quoted-name round trips and legacy definitions, Windows missing/disabled accounts and missing memberships, generated Bash syntax, and the Linux failure gate. They do not execute remote deployments or replace the older Pester suite.

Centrify follow-up: removed the undocumented `adleave -y` argument. Delinea documents Kerberos-based departure, but the current generic `kinit`/cache handling is still unverified with Centrify. Before live use, align the Kerberos utility, principal, and privileged ticket-cache context with the installed agent. Password-based departure should use the interactive prompt through a protected input channel, subject to confirming the agent version's prompt behavior; do not put passwords in command arguments or generated scripts.

Windows telemetry now reads Symantec `LatestVirusDefsDate` and `LatestVirusDefsRevision` from `CurrentVersion\Public-Opstate`, trying the native location first and then `WOW6432Node`. It preserves the vendor date value without guessing its format. Details include the selected source, both registry read outcomes, and errors; absent keys are distinguished from access failures. See [Broadcom article 181033](https://knowledge.broadcom.com/external/article/181033/finding-the-current-info-including-defin.html).

Ivanti telemetry reads the `CoreServer` value under `HKLM\SOFTWARE\WOW6432Node\Intel\LANDesk\LDWM`, with a native-path fallback. The overview adds an `IVANTI CORE` column. This reports the configured core, not a verified connection or the last contacted server. Registry observations survive service-query failures. See [Ivanti client connectivity settings](https://help.ivanti.com/ld/help/en_US/LDMS/10.0/Windows/agent-h-client-connectivity.htm).

Run `pwsh -NoProfile -File ./tests/Verify-WindowsCollectors.ps1` for the registry fixture checks. These exercise the generated collector functions and syntax with simulated registry/service dependencies; real Windows registry layouts and installed agent behavior remain unverified. The unused legacy information collector is retained unchanged.

The keytab generator supplies the password to the native password prompt rather than putting it in process arguments. It sets `/answer -`, supplies no account mapping options, times out after 30 seconds, and keeps native output out of error messages. Native redirected-password input and compatibility with the account's Kerberos salt remain unverified; a successful fixture check does not demonstrate a usable keytab. Run `pwsh -NoProfile -File ./tests/Verify-KeytabPrompt.ps1` to verify prompt/generator wiring without domain access.

Module organization: related functions now live in collapsible `#region` sections. Shared utilities and account helpers appear near the top, followed by configuration, credentials/keytabs, GPO and initialization, mobile definitions, Windows/Linux provisioning and cleanup, Windows/Linux collectors, collection orchestration (including legacy collectors), reporting, and deployment commands.

Removed unused internal helpers: `ConvertFrom-Base64`, `Repair-GpoPermissions`, `New-CustomGPO`, `New-DeployerCertificate`, `New-WindowsPostTask-SupportAcl`, and `Get-EncryptedCredRSA`. Also removed the unused `WindowsPayload` class and obsolete default-config alias. The logon-script comment now references the current certificate helper; the obsolete certificate test block was removed from the legacy Pester suite in favor of the existing focused certificate checks. Collector implementations, including the legacy collector and Bash sample, remain available together.

Validation: all four focused offline verification scripts pass. The module imports through its manifest, every declared public function remains exported, and retained function bodies match their previous implementations after trailing-whitespace normalization and removal of the obsolete commented support-ACL call. The legacy Pester suite still targets older interfaces elsewhere and was not run.

Literal PowerShell payload fragments now use `{ ... }` scriptblocks with `.ToString()` at the script-text boundary, so editors and PowerShell's parser can inspect their syntax. Bash here-strings and interpolated `@"` templates remain strings. Twenty generated payload variants were compared before/after and retain identical code tokens. The Windows collector checks also parse optional post-deployment combinations offline.
