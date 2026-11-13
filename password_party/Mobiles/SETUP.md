# Administrator setup

Provision the management environment explicitly from the account that will operate deployments:

```powershell
.\Initialize-Mobiles.ps1
```

This creates or repairs the configured directories, SSH key/enrollment and permissions, deployer certificate, and GPO logon scripts. It uses the module defaults and root `cfg.psd1`, with explicit `-ConfigOverride` values taking precedence. The existing setup ledger is displayed and fatal failures stop the script. Run it again deliberately for repairs or to republish setup after configuration/template changes.

Certificates and SSH locations are associated with the operating account/profile, so configure each operator's required environment. Running setup once under an unrelated account does not provision every operator's certificate store. Existing domain/SYSVOL permissions are still required for the GPO work.

`Mobiles.ps1` has no `-Initialize` mode. Importing `MobileManager.psd1` does not expose initialization or load its implementation. Setup-only functions live in `Setup/MobileEnvironment.ps1` and are loaded privately by the administrator entry point.

Registration performs a read-only local prerequisite check: configured directories, a deployer certificate with its private key, and an SSH private key when Linux hosts are included. Missing assets stop registration before credentials are collected or remote deployment begins, and the audit records the failure. These checks do not prove remote connectivity or validate every GPO/ACL setting; they do not repair or republish anything.

`-Info -Full` collects telemetry without running setup. Check-in and AV scans also do not initialize the management environment. Routine run logs and deployment artifacts continue to be created as part of their respective operations.
