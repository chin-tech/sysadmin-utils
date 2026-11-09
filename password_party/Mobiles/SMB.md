# Mobile SMB checkout and check-in

`NetworkSharing` in `DeploymentTasks.Windows.PostDeployment` enables the coordinated workflow. Every Windows computer in the mobile shares its fixed local drives, including its system drive. `-SmbHosts` chooses which of those computers Linux mounts; it does not restrict Windows share creation.

```powershell
.\Mobiles.ps1 -RegisterDeployment -Name tmobile -SmbHosts WIN-A,WIN-B -Disjoin
```

The existing domain-controller/keytab arguments remain available for Linux departure. Omitting `-SmbHosts`, supplying blank input, or including an unknown name opens the terminal multi-select picker populated from that mobile's Windows list. Valid names are preselected when correcting invalid input. Cancellation/empty selection stops checkout. Unattended use requires valid explicit selections; redirected input cannot use the picker.

Each host's active `10.x` IPv4 interface is discovered. One match is selected automatically; multiple matches open an interface picker. No match stops preparation. Duplicate addresses and selected subnets that cannot directly reach one another stop preparation before endpoint changes. This assumes an isolated network without an intervening router. The selected Windows IPs are captured explicitly, so CIFS sources do not require DNS:

```fstab
//10.20.1.11/C /share/WIN-A/C cifs credentials=/var/lib/mobiles/smb/<id>/credentials-WIN-A,sec=ntlmssp,vers=3.0,_netdev,nofail,x-systemd.device-timeout=15s,file_mode=0660,dir_mode=0770,gid=users 0 0
```

The hostname names the local directory; the source uses the numeric address. Multiple storage hosts receive separate directories. The credential authority is the Windows machine's actual local computer name, including when the mobile lists an FQDN. Each mount receives a systemd mount-unit drop-in setting `TimeoutSec=30`; this avoids depending on newer fstab timeout options unavailable in upstream systemd 219. Every managed fstab line has **`nofail`** and `_netdev`. A missing share does not make it a required boot mount. The activation worker runs as a background service, so its mount/probe attempts also do not delay the multi-user boot target. It still reports unsuccessful mounts and write probes.

## Configuration and credentials

Set these in the manifest or your existing `cfg.psd1` override:

```powershell
SMBUser = 'mobile-smb-access'
SMBLinuxGroup = 'users'
```

The account name is used for account creation, share permissions, and Linux credential files. `NetworkSharing` creates the account independently of the optional `UserRights`/`PostDeploy` tasks. The command prompts once for a secure password, or accepts `-SmbCredential` with a username matching `SMBUser`. The account must be distinct from deployment user accounts. Existing accounts are reported before preparation; their passwords are never overwritten. Existing drive-letter shares must point to the expected drive root. New shares grant full access to this account; existing share permissions are preserved with an additional grant. NTFS permissions grant inheritable full control at each drive root without taking ownership or changing protected child ACLs. Protected paths can therefore remain inaccessible.

`SMBLinuxGroup` must already exist. At activation the deployment's local Linux users are added if necessary, and only those added memberships are removed on check-in. This group controls local access to the shared-account mounts. The Windows account receives network logon rights and is denied local/RDP interactive logon. A deployment-owned firewall rule permits TCP 445 from `10.0.0.0/8` on all profiles.

Windows receives the password as a SecureString credential over the existing WinRM transport. Linux receives it in the SSH payload, then stores it only in root-owned mode-0600 credential files inside a mode-0700 state directory. The controller plan and audit logs contain no password or generated worker payload. Endpoint worker/options/state files require administrator/root access. Use `Preflight.LinuxToolDirectories` for custom dependency locations, just as with preflight.

## Checkout and activation

1. Resolve selections and collect interface/drive inventory before changing endpoints.
2. Save a non-secret controller plan under `MobileDeployments/smb/<id>.json`. Prepare Windows accounts, shares, permissions, firewall rules, and startup workers. Prepare Linux credentials, empty mount directories, a cloned NetworkManager profile, and its startup service. Preparation failures stop ordinary provisioning/domain departure and retain restoration state.
3. Run ordinary checkout tasks, hooks and local-account checks. Domain departure still requires `-Disjoin` and successful prerequisites.
4. Disconnect from the domain network, connect the isolated mobile network, and reboot the hosts. Address changes are deferred until startup. Windows freezes the selected DHCP address; originally static Windows addressing is retained. Linux activates a static clone using the captured address/prefix, without modifying its original connection profile. The clone omits corporate IPv4 gateways, static routes and DNS.
5. Collect results after the hosts finish booting:

```powershell
.\Mobiles.ps1 -SmbStatus -Name tmobile
```

Preparation reports `PreparedPendingReboot`, not verified connectivity. Windows activation reports `Active` once its selected static address is installed. Linux activation verifies FIPS enforcement is off, installs the managed fstab block, mounts every selected share, and performs a temporary write/delete probe in each. A mount failure is recorded as an activation failure while `nofail` permits boot to continue. Once storage hosts are available, a Linux administrator can retry using `systemctl restart mobiles-smb-<id>.service`. Existing mounts are reused only when their sources match the plan.

On Linux hosts currently enforcing FIPS, preparation copies the normal default kernel and initramfs to uniquely named mobile images and creates a dedicated grubby entry with `fips=0`. Ordinary entries are retained. The copies let check-in remove only the mobile entry and its images, without removing the normal entry for the same kernel version. Enough `/boot` space for both images is required. Preparation requires grubby to resolve the default kernel and a single initramfs file; unsupported layouts fail explicitly. Hosts initially outside FIPS mode do not receive a mobile kernel entry. The workflow does not change the RHEL 8 system crypto policy; successful kernel verification and an actual CIFS mount are required. Validate this behavior on both site images.

## Check-in

```powershell
.\Mobiles.ps1 -UnRegisterDeployment -Name tmobile
```

For a saved SMB deployment, check-in hooks run before SMB teardown, and are not run a second time during ordinary cleanup. All Linux clients must unmount successfully before any Windows shares are removed. Busy mounts stop cleanup; the workflow does not force/lazily detach them. Managed fstab blocks, credential files and mount timeout drop-ins are removed. Added Linux group memberships, Windows account/share/NTFS grants, local logon-right entries and firewall rules are removed while preserving pre-existing shares and unrelated settings. Newly created empty mount directories are removed during the restoration boot.

Networking restoration is deferred to startup so management sessions remain available for ordinary cleanup. Check-in stages the saved original NetworkManager connection by UUID and restores DHCP/DNS only on Windows interfaces that originally used DHCP. Originally static Windows configurations stay static. Linux selects the normal kernel, removes the mobile entry/images, and verifies the original FIPS enforcement after reboot. A newer normal default is preserved; if the saved default has been removed, the first installed normal entry in grubby boot order is used. When originally enforcing FIPS, the selected normal entry and newly installed normal entries receive `fips=1`, including when they inherited mobile arguments during an update. Other pre-existing normal entries are retained.

Check-in reports `RestorePendingReboot`. Reconnect to the original network for DHCP, reboot the hosts, then run `-SmbStatus` to verify `Restored` and complete the controller lifecycle. Status first tries the saved hostname, then the captured IP, so a renewed DHCP address can be reached through restored DNS. Retain the controller plan until restoration is verified. The endpoint copies of state/history remain available for inspection.

## Endpoint results and management access

Windows stores `state.json` and `history.jsonl` under `C:\ProgramData\Mobiles\Smb\<id>`; its startup task is `Mobiles-Smb-<id>`. Linux stores state, history and options under `/var/lib/mobiles/smb/<id>`; its unit is `mobiles-smb-<id>.service`, with output in the system journal. Each `-SmbStatus` query collects current endpoint results into the regular `.log`/`.jsonl` audit pair. Earlier audit snapshots do not change when workers finish.

Check-in uses saved numeric addresses for management too. Existing WinRM authentication/trust or HTTPS certificate configuration must permit management by IP after domain departure, and SSH must remain authorized for the management account. The tool does not alter the controller's TrustedHosts or substitute the SMB data credential for management credentials. Status can show `Unreachable` separately from an endpoint's saved activation result. Native Windows SMB/ACL/WinRM behavior, RHEL 7.9/8.10 grubby/network behavior, FIPS interaction and site policies require on-site validation; offline tests mock native mutations.

Run `pwsh -NoProfile -File ./tests/Verify-SmbDeployment.ps1` for the offline fixtures.

References: [Red Hat SMB mounts and credential files](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/managing_file_systems/mounting-an-smb-share-on-red-hat-enterprise-linux_managing-file-systems), [grubby options](https://github.com/rhboot/grubby/blob/main/grubby.8), [NetworkManager profiles](https://networkmanager.dev/docs/api/latest/nmcli.html), [systemd mount behavior](https://www.freedesktop.org/software/systemd/man/latest/systemd.mount.html), [Windows address creation](https://learn.microsoft.com/en-us/powershell/module/nettcpip/new-netipaddress).
