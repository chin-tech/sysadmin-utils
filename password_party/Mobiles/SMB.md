# SMB checkout and check-in

Enable `NetworkSharing` in `DeploymentTasks.Windows.PostDeployment`. All Windows hosts share their fixed drives. `-SmbHosts` selects which Windows hosts Linux mounts; blank/invalid input opens the mobile-scoped terminal picker.

```powershell
.\Mobiles.ps1 -RegisterDeployment -Name tmobile -SmbHosts WIN-A,WIN-B -Disjoin
```

Each host's active `10.x` interface is selected automatically when unique, or through the interface picker when ambiguous. Duplicate addresses or incompatible subnets stop preparation. Sources use captured Windows IPs; local paths use `/share/<hostname>/<drive>`. Domain departure still uses the existing keytab/credential arguments and account checks.

## Native Linux configuration

Checkout writes persistent settings, then ordinary boot facilities apply them. It installs **no Linux SMB worker script or custom service**:

- NetworkManager: save the current connection's autoconnect, IPv4 method and configured addresses, then set the captured address/prefix as static. Other profile settings remain unchanged. No `connection up/down`, device reapply, or NetworkManager restart runs during checkout/check-in.
- Boot: when FIPS is currently enforced, create a separate mobile kernel entry with `fips=0`. Keep normal entries and save the normal default. The dedicated images require free `/boot` space. RHEL 8 crypto policy is not changed; actual FIPS/SMB compatibility is verified after reboot.
- Mounts: write a marked `/etc/fstab` block with numeric IP sources, `sec=ntlmssp`, SMB 3.0, `_netdev,nofail,x-systemd.automount`, and root-only credential files. Native automounts mount on access; an unavailable storage host does not become a required boot mount.
- Access: after ordinary Linux account provisioning, add local mobile users to `SMBLinuxGroup`, recording only memberships added by the deployment. Failure blocks domain departure.

Disconnect from the domain network and reboot onto the isolated network. A normal status query observes state without starting mounts:

```powershell
.\Mobiles.ps1 -SmbStatus -Name tmobile
```

To explicitly start the native fstab mount units and run temporary write/delete probes:

```powershell
.\Mobiles.ps1 -SmbStatus -Name tmobile -VerifyMounts
```

Verification checks the reboot, kernel FIPS enforcement, captured address and expected CIFS sources. Mount/probe attempts are bounded by timeouts. It reports unavailable shares as `NeedsReview`; `nofail` remains in fstab. Status queries append observations to the normal `.log`/`.jsonl` audit pair.

The Linux implementation is split into `Get-LinuxSmbNetworkScript`, `Get-LinuxSmbBootScript`, `Get-LinuxSmbMountScript`, `Get-LinuxSmbGroupScript`, and `Get-LinuxSmbStatusScript` in `Private/LinuxSmb.ps1`. These are ordinary SSH command fragments. Routine JSON access lives in the session helpers (`state_get`, `state_set`, `state_add`, `state_list`, and `option_get`). For example, `state_set OriginalKernel "$normal_kernel"` saves a string, and `state_add CreatedMountPoints "$directory"` records a directory once in creation order. `mount_entries` reads each mount into `host`, `target`, `source`, and `authority` fields in one pass. Keep JSON as data; do not source it as shell code. The existing JSON schema and legacy restoration path remain compatible. Only data and credentials are persisted, not generated executable content. Windows line endings are normalized on the outbound command stream; JSON carries data only.

## SMB account and permissions

```powershell
SMBUser = 'mobile-smb-access'
SMBLinuxGroup = 'users'
```

The configured username reaches Windows account creation, permissions and Linux credentials. Password input uses `Read-Host -AsSecureString`, or `-SmbCredential` with the configured username. An existing account is **reused without resetting its password**; supply its current password, consistently across the storage hosts. A missing account is created. An existing disabled account is temporarily enabled and its original enabled state recorded. Incorrect credentials are reported by explicit mount verification.

Check-in deletes only accounts created by this deployment. Reused accounts retain their password and original enabled state. Existing share grants and this account's NTFS rules are recorded and restored; unrelated identities are preserved. External changes to the same account's NTFS rules require inspection rather than being overwritten. Only logon-right entries added by this deployment are removed. New shares grant the SMB account full access; protected child NTFS ACLs can still deny particular paths. `NetworkSharing` is independent of optional `UserRights`/`PostDeploy` tasks.

Windows installs only `boot.ps1`, a short network action for deferred DHCP/static changes. It contains no account, share, ACL or task-installation code. `Get-WindowsSmbTaskOptions` uses the existing `New-TaskXML` builder on the controller; the endpoint registers that XML as SYSTEM. Its boot trigger has no expiry, so it still works if checkout and reboot are days apart. Account/share setup and cleanup run over WinRM while the controller is connected. Check-in replaces the old full `worker.ps1` with this smaller boot action for existing deployments. Preparation reports `PreparedPendingReboot`; after boot the task records `Active`. Windows management operations (including check-in hooks, cleanup, and status) use the recorded computer names, without falling back to WinRM by IP. Name resolution and management authentication must still work after disjoin. Captured IPs are used for Linux SMB mounts. The SMB data credential does not replace management credentials, and the tool does not change TrustedHosts.

## Check-in and older deployments

```powershell
.\Mobiles.ps1 -UnRegisterDeployment -Name tmobile
```

Check-in hooks run first. Linux unmounts must succeed before any Windows shares are removed; busy mounts abort cleanup without force/lazy unmount. Remove only managed fstab entries, credentials, newly created empty directories and added group memberships. Restore saved NetworkManager values without reconnecting the live interface. Restore the normal boot selection and FIPS arguments; preserve a newer normal default and repair new normal entries that inherited `fips=0` during updates. Windows restores its saved DHCP/DNS behavior at startup, retaining originally static configurations.

Reconnect to the original network, reboot, then use `-SmbStatus` to confirm `Restored`. The Linux status check uses the boot ID, original connection UUID, IPv4 availability and original FIPS enforcement to checkpoint restoration. The controller plan is retained until verified.

Saved deployments from the old Linux service implementation can be checked in with this version. Cleanup disables/removes that service and deletes its worker without executing it, so CRLF in the old worker does not block check-in. The old active mobile connection is disabled for autoconnect; its untouched original connection is used after reboot. The disabled legacy profile is retained to avoid interrupting the current SSH session; it can be deleted manually after restoration. Fresh checkouts create no such profile or service. An old service still running with its deployment lock must be stopped before check-in.

## Finding and maintaining the implementation

The module loads three ordinary PowerShell files explicitly:

- `Private/MobileSmb.ps1`: selection, controller plans, check-out/check-in order and status.
- `Private/WindowsSmb.ps1`: Windows inventory, provisioning and the separate network-only boot action.
- `Private/LinuxSmb.ps1`: Linux networking, boot entries, mounts and access groups.

Keep the `Private` directory beside `MobileManager.psm1` when copying the program. These files are part of the program, not custom `Scripts/Check-in` or `Scripts/Check-out` hooks. Edit the script blocks in these files; generated endpoint scripts should not be hand-maintained. CLI options, result objects and normal audit display remain the same.

Controller plans live under `MobileDeployments/smb/<id>.json`. Each host's `State` contains its returned restoration details, including Windows DHCP/DNS, account ownership, shares and permission snapshots, or Linux original connection/boot settings. Preparation, cleanup and successful status queries refresh these snapshots. Failed connections retain the last collected snapshot; a disconnected controller cannot observe subsequent boot changes until the next status query. For an offline reference on the primary node:

```powershell
$plan = Get-Content '<MobileDeployments>\smb\<id>.json' -Raw | ConvertFrom-Json
$plan.Windows | Select-Object HostName, Status, State
$plan.Windows[0].State | Format-List *
$plan.Linux[0].State | Format-List *
```

Endpoint state is retained as a local recovery copy and the input to disconnected startup operations; check-in reads that current copy. The controller record lets you inspect the captured settings without logging into each host. It is a snapshot, not a live database. Linux restoration data lives under `/var/lib/mobiles/smb/<id>`; credential files are mode 0600 inside a mode-0700 directory. Windows recovery state remains under `C:\ProgramData\Mobiles\Smb\<id>`. Passwords and generated payloads are excluded from controller plans/audits. Use `Preflight.LinuxToolDirectories` for custom tool locations.

Offline validation: `pwsh -NoProfile -File ./tests/Verify-SmbDeployment.ps1`. Native RHEL 7.9/8.10 boot and Windows ACL/WinRM behavior still require site validation.

References: [NetworkManager command behavior](https://networkmanager.dev/docs/api/latest/nmcli.html), [native fstab automount/nofail behavior](https://www.freedesktop.org/software/systemd/man/latest/systemd.mount.html), [Red Hat SMB authentication](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/managing_file_systems/mounting-an-smb-share-on-red-hat-enterprise-linux_managing-file-systems).
