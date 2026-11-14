# Optional offline SMB

```powershell
# cfg.psd1 (default shown)
@{ SmbUserName = 'mobile-smb-access' }

# Select one storage host from this mobile's Windows computers.
./Mobiles.ps1 -RegisterDeployment -Name tmobile -SmbHost WIN01 -Disjoin
```

Omit `-SmbHost`, or pass an empty/whitespace value, to skip SMB preparation. The selected name must match a Windows member of the mobile; typos fail before deployment work. There is one new CLI option and no additional service or scheduled task. SMB requires the existing `PostDeploy` scheduled selection.

## Execution

1. The controller queries each Windows computer by **name over WinRM**, capturing its single primary `10.x` address, prefix, gateway, DNS, interface index and fixed drive letters. Machines with ambiguous/missing `10.x` addresses fail rather than selecting an arbitrary NIC. The inventory is saved in the normal deployment audit on the controller.
2. The controller generates one random password per mobile and stores it CMS-encrypted under `MobileDump/<mobile>.smb.cms`, using the existing deployer certificate. Repeated deployment reuses it. Every Windows member gets the configured local SMB account during ordinary provisioning; an existing account has its password refreshed and is enabled. Keep this name dedicated to SMB. Passwords are absent from audit events and scheduled-task XML.
3. The existing `Mobile-DisjoinTask` boot task receives the captured network data through `Get-TaskData` / `New-TaskXML`. It shares each fixed Windows drive as `C`, `D`, etc., grants the SMB account share access and inheritable NTFS Modify access, allows TCP 445 from `10.0.0.0/8` on all profiles, and makes the captured IPv4 configuration persistent/static. Conflicting existing share paths fail. Existing NTFS permissions and unrelated firewall rules remain in place; explicit deny permissions can still prevent access.
4. Linux saves its single current `10.x` address, prefix, gateway and DNS into the active NetworkManager connection profile using `nmcli`. It does **not** reactivate the connection during SSH; the saved configuration takes effect on reconnect/reboot. This is the Linux equivalent of preparing the next boot, without a new worker or systemd service.
5. Linux writes root-only mode `0600` credentials to `/etc/security/mobiles-smb.conf` and adds mounts for the selected Windows host's fixed drives. Entries use `//<captured-IP>/C /share/<hostname>/C cifs defaults,_netdev,nofail,sec=ntlmssp,credentials=... 0 0`. Repeated runs replace only those mountpoint entries; unrelated fstab entries remain. `cifs-utils` must already be installed.
6. If the Linux kernel currently enforces FIPS, SMB preparation creates a separate **Mobile SMB (fips=0)** boot entry from the current default and selects it. RHEL 8 BLS gets a separate entry file; RHEL 7 GRUB uses `grubby --copy-default`. The normal entry, global crypto policy, initramfs and default kernel argument configuration remain intact. The original boot title is retained in `/etc/security/mobiles-smb-boot-original` and reported to the controller audit. Check-in restores that title if the mobile entry is still default, preserves a newer independently selected default, and removes the mobile entry/marker. If the required original entry has been removed, restoration fails visibly for manual repair.

Reboot/disconnect remains an operator action. Preparation is reported as **Prepared**, not as successful live mounting. If Windows shares were unavailable when Linux booted, retry the relevant mounts locally after Windows is ready; `nofail` allows Linux boot to continue.

Windows boot results remain in `C:\Post-Deployment.xml`, as with the existing post task. The controller journal records task registration and Linux preparation; it cannot assert that a later offline boot task completed. Windows deployment failures stop Linux SMB deployment from proceeding.

## Returning to the domain

DHCP restoration is deliberately separate from remote check-in, so a network change cannot cut the transport mid-procedure. No automatic DHCP reset is installed. A later local pre-check-in command can restore DHCP before hosts need domain connectivity. The Windows boot task must be disabled/removed before such a reset, or its next boot will reapply the stored static address. Check-in already removes the managed Windows tasks.

For this pass, check-in restores the Linux boot selection only. SMB accounts, share/NTFS grants, the firewall rule, fstab entries, credentials and static network profiles are retained; they are not silently rolled back. This avoids introducing another state/rollback framework while the local return workflow is being decided. The controller's inventory/audit and encrypted credential are the primary references.

Current DHCP leases become static addresses; this does not reserve them on the DHCP server. Coordinate reservations or network isolation to avoid a later lease collision. Changing `SmbUserName` does not delete the former dedicated account. Reuse the existing encrypted credential file unless intentionally rotating it across all members.

## Boot limitation and validation

`fips=0` is a kernel enforcement override for the mobile boot. It is **not** a complete or supported reversal of an installed FIPS configuration, and other crypto policies may still prevent NTLM. Red Hat documents that distinction in its [RHEL 8 FIPS guidance](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/security_hardening/switching-rhel-to-fips-mode_security-hardening). This implementation does not change global crypto policy to make a failed mount work.

Offline checks execute generated scripts with harmless command substitutes, including both GRUB/BLS paths, credential reuse, existing accounts/shares, static address parameters, fstab repeat runs, private credential permissions and result logging. Real RHEL 7.9/8.10 boot, NetworkManager, NTLM mount, Windows ACL/firewall and domain rejoin testing is still required before deployment use. A BLS template with unresolved `$kernelopts` is rejected rather than guessed.

Implementation references: [Microsoft netsh IPv4 commands](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface), [Red Hat NetworkManager configuration](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/configuring_basic_system_settings/assembly_configuring-and-managing-network-access_configuring-basic-system-settings), and the [grubby manual](https://github.com/rhboot/grubby/blob/main/grubby.8).
