# Administrator setup

Provision the management environment explicitly from the account that will operate deployments:

```powershell
.\Initialize-Mobiles.ps1
```

This creates or repairs the configured directories, SSH key/enrollment and permissions, deployer certificate, and GPO logon scripts. It uses the module defaults and root `cfg.psd1`, with explicit `-ConfigOverride` values taking precedence. The existing setup ledger is displayed and fatal failures stop the script. An ordinary repeat with the same configuration/templates and healthy existing state leaves managed files, shortcut IDs/timestamps, versions, and matching SSH ACLs unchanged. Missing assets or changed managed content are repaired as needed.

Certificates and SSH locations are associated with the operating account/profile, so configure each operator's required environment. Running setup once under an unrelated account does not provision every operator's certificate store. Existing domain/SYSVOL permissions are still required for the GPO work.

`Mobiles.ps1` has no `-Initialize` mode. Importing `MobileManager.psd1` does not expose initialization or load its implementation. Setup-only functions live in `Setup/MobileEnvironment.ps1` and are loaded privately by the administrator entry point.

Registration performs a read-only local prerequisite check: configured directories, a deployer certificate with its private key, and an SSH private key when Linux hosts are included. Missing assets stop registration before credentials are collected or remote deployment begins, and the audit records the failure. These checks do not prove remote connectivity or validate every GPO/ACL setting; they do not repair or republish anything.

`-Info -Full` collects telemetry without running setup. Check-in and AV scans also do not initialize the management environment. Routine run logs and deployment artifacts continue to be created as part of their respective operations.

## GPO updates and forced refresh

Normal setup preserves existing GPO identity, display name, enabled/disabled flags, ACLs, computer extension registrations, unrelated user extensions, unrelated shortcut items, targeting filters, and OU link settings. It only adds a missing link to the configured OU. The two mobile shortcut IDs stay stable. Changed templates/configuration update the managed scripts/shortcut properties and advance the user version; the computer version is preserved. AD and SYSVOL publication use the same writable DC, while client-facing paths remain domain-based.

To deliberately republish the managed GPO content and repair mismatched or malformed state:

```powershell
.\Initialize-Mobiles.ps1 -ForceGpoRefresh
```

This flag republishes `CreateLocalAccounts.ps1`, `Run.ps1`, and the two mobile shortcuts, and advances the user revision even when the content already matches. It does not delete/recreate the GPO, rotate keys/certificates, reset security filtering or flags, enable intentionally disabled OU links, or issue `gpupdate` on endpoints. Existing valid shortcut IDs and unrelated preferences remain intact.

Before forced publication, setup saves existing managed files, `gpt.ini`, any pending-publication marker, and the AD version/extension list under `AdminRoot/GpoBackups/<GPO GUID>/<timestamp-id>/`; the setup ledger reports the backup location. Malformed shortcut XML or `gpt.ini` can then be rebuilt. Unrelated settings inside a malformed file cannot be reliably recovered automatically; the original is retained in that backup. Multiple shortcuts targeting the same managed path remain an explicit error because choosing between their potentially different targeting rules requires administrator review.

Normal setup stops on AD/SYSVOL version mismatches or malformed state instead of silently resetting it. Check replication first; use forced refresh when the state actually needs repair. Forced reconciliation advances from the highest observed user revision and preserves the highest observed computer revision. This reconciles counters on the selected DC; it does not validate or restore unrelated computer-policy content.

A `Mobiles.publish-pending` marker is written before policy files are updated and removed after AD publication succeeds. If publication is interrupted, the next normal run stops with instructions to use `-ForceGpoRefresh`, so partially published content cannot be mistaken for a successful no-op. Publication across files and AD is not transactional; do not edit the same GPO concurrently through another setup process or GPMC, and allow normal AD/SYSVOL replication after changes.

The upper 16-bit user revision advances while the lower computer revision is retained; rollover skips zero, following [Microsoft's GPO version update rules](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpol/70fd86b1-926a-4dcf-9ce7-6f9d2149c20d). Valid `gpt.ini` sections/keys and existing ANSI bytes outside the version value are preserved.
