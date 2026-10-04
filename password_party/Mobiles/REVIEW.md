This patch applies configuration once, fixes mobile definition round trips, and gates domain departure on provisioning and observed local account state.

Configuration precedence is module defaults, `cfg.psd1` beside `Mobiles.ps1`, then explicit `-ConfigOverride` values. `Set-MobileConfig` is the only function accepting a configuration hashtable. Paths derived from an overridden parent are recomputed unless explicitly supplied. Unknown keys, empty override values, and malformed GPO IDs are rejected before the module configuration changes. Existing callers using per-function `-Config` must switch to `Set-MobileConfig`.

`cfg.example.psd1` shows the supported data-file format. PowerShell data files require literal values: the existing local `cfg.psd1` expression `"C:\Users\${env:USERNAME}"` cannot be imported. Replace that value with the actual Windows path, or omit `NfsHome` to derive it from `nfsHomeRoot` and the current username. Local configuration and credentials are not included in this patch.

The writer honors its destination, escapes CSV fields, and rejects path-like mobile names. The reader accepts both `fullname` and the legacy `name` column. Empty default-user directories no longer produce a phantom `.local` account.

Domain departure remains opt-in. For example:

```powershell
.\Mobiles.ps1 -RegisterDeployment -Name example -Disjoin
```

Windows verifies each expected local account is enabled and has its required group memberships. Any recorded deployment failure skips departure for that host. Linux creates accounts before verifying their presence in `/etc/passwd`, checks required wheel membership, and skips departure when preceding steps recorded failures. Linux account selection now uses the existing role priority.

Linux departure also requires `-LinuxDisjoinKeytab`, a prepared base64 keytab credential. This replaces the undefined password variable and incomplete keytab-generation call in the original registration path. The keytab principal must have permission to perform domain departure. No live Kerberos/domain integration was verified here.

These checks establish account existence and membership, not successful password authentication or interactive logon. Live Windows encryption/remoting and proprietary software collection still require representative machines. Initialization still provisions the environment during registration; separating that behavior, sharing narrower asset paths, and unifying logon role derivation are follow-up work.

Run the focused offline regression checks with:

```powershell
pwsh -NoProfile -File ./tests/Verify-MobileChanges.ps1
```

The checks use the actual selected implementations with simulated external dependencies. They cover configuration derivation and invalid overrides, quoted-name round trips and legacy definitions, Windows missing/disabled accounts and missing memberships, generated Bash syntax, and the Linux failure gate. They do not execute remote deployments or replace the older Pester suite.

Centrify follow-up: removed the undocumented `adleave -y` argument. Delinea documents Kerberos-based departure, but the current generic `kinit`/cache handling is still unverified with Centrify. Before live use, align the Kerberos utility, principal, and privileged ticket-cache context with the installed agent. Password-based departure should use the interactive prompt through a protected input channel, subject to confirming the agent version's prompt behavior; do not put passwords in command arguments or generated scripts.
