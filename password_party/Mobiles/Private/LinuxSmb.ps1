# Linux SMB uses normal NetworkManager, GRUB and fstab settings. These fragments run over SSH.

function Get-MobileSmbToolPath {
    $directories = if ($script:Config.Preflight.LinuxToolDirectories) { $script:Config.Preflight.LinuxToolDirectories } else { @('/usr/local/sbin','/usr/local/bin','/usr/sbin','/usr/bin','/sbin','/bin') }
    foreach ($directory in $directories) {
        if ([string]::IsNullOrWhiteSpace($directory) -or -not $directory.StartsWith('/') -or $directory -match '[:\r\n]') { throw 'Invalid Linux tool directory.' }
    }
    $directories -join ':'
}

function Get-LinuxMobileSmbInventory {
    $body = @'
ip -o -4 address show up scope global |
    awk '$4 ~ /^10\./ {print $2, $4}' |
    jq -Rn '
        [inputs | split(" ") | {
            InterfaceName: .[0],
            IPAddress: (.[1] | split("/")[0]),
            PrefixLength: (.[1] | split("/")[1] | tonumber)
        }] | {Interfaces: .}
    '
'@
    'export PATH=' + (ConvertTo-BashArgument (Get-MobileSmbToolPath)) + "`n" + $body
}


function Get-LinuxSmbSessionScript {
    return @'
set -euo pipefail
export LC_ALL=C
umask 077
state="$root/state.json"
if [[ -L /var/lib/mobiles || -L /var/lib/mobiles/smb || -L "$root" ]]; then echo 'Redirected SMB state directory' >&2; exit 2; fi
if [[ -e "$root" && ! -O "$root" ]]; then echo 'SMB state is not owned by the privileged account' >&2; exit 2; fi
mkdir -p "$root"; chmod 700 "$root"
exec 9>/run/lock/mobiles-smb.lock
flock -n 9 || { echo 'Another SMB operation is running; stop the old mobiles-smb service if necessary' >&2; exit 2; }
# JSON stays data, never shell code. Workflow fragments below use these simple operations.
json_get() {
    local file="$1" key="$2" child="${3:-}"
    jq -r --arg key "$key" --arg child "$child" '
        (if $child == "" then .[$key] else .[$key][$child] end)
        | if . == null then "" else . end
    ' "$file"
}
state_get() { json_get "$state" "$@"; }
option_get() { json_get "$root/options.json" "$@"; }
state_list() { jq -r --arg key "$1" '.[$key][]?' "$state"; }
save_state() {
    jq "$@" "$state" > "$state.tmp"
    mv -f "$state.tmp" "$state"
}
state_set() {
    save_state --arg key "$1" --arg value "$2" '.[$key] = $value'
}
state_add() {
    # Append once, preserving order (directory cleanup relies on creation order).
    save_state --arg key "$1" --arg value "$2" '
        .[$key] = ((.[$key] // []) | if index($value) == null then . + [$value] else . end)
    '
}
mount_entries() {
    # One decoded record per mount; fields cannot contain tabs/newlines in the controller plan.
    jq -r '.Mounts[] | [.HostName, .MountPoint, .Source, (.CredentialDomain // .HostName)] | @tsv' "$root/options.json"
}
finish() {
    state_set Status "$1"
    state_set UpdatedUtc "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    jq -c . "$state" >> "$root/history.jsonl"
    cat "$state"
}
'@
}

function Get-LinuxSmbNetworkScript {
    param([switch]$Restore)
    if ($Restore) { return @'
original_uuid="$(state_get OriginalConnection)"
if jq -e '.OriginalNetwork != null' "$state" >/dev/null; then
    settings=()
    while IFS=$'\t' read -r key value; do
        settings+=("$key" "$value")
    done < <(jq -r '.OriginalNetwork | to_entries[] | [.key, .value] | @tsv' "$state")
    nmcli connection modify uuid "$original_uuid" "${settings[@]}"
else
    # Earlier deployments used an untouched original profile and a mobile clone.
    mobile_name="$(state_get MobileConnection)"
    if [[ -n "$mobile_name" ]] && nmcli connection show id "$mobile_name" >/dev/null 2>&1; then
        nmcli connection modify id "$mobile_name" connection.autoconnect no
        save_state '.LegacyProfileRetained=true'
    fi
fi
'@ }
    return @'
iface="$(option_get Interface InterfaceName)"
address="$(option_get Interface IPAddress)/$(option_get Interface PrefixLength)"
original_uuid="$(nmcli -t -f UUID,DEVICE connection show --active | awk -F: -v dev="$iface" '$2==dev {print $1}')"
[[ "$original_uuid" =~ ^[a-fA-F0-9-]{36}$ ]] || { echo 'One active NetworkManager connection is required' >&2; exit 2; }
ip -o -4 address show dev "$iface" | awk -v address="$address" '$4==address {found=1} END {exit !found}'
state_set OriginalConnection "$original_uuid"
state_set InterfaceName "$iface"
save_state '.OriginalNetwork = {}'
for key in connection.autoconnect ipv4.method ipv4.addresses; do
    value="$(nmcli -t --escape no -f "$key" connection show uuid "$original_uuid")"
    value="${value#*:}"
    save_state --arg key "$key" --arg value "$value" '.OriginalNetwork[$key] = $value'
done
# Modify the saved profile only. Do not call connection up/down or device reapply.
nmcli connection modify uuid "$original_uuid" ipv4.method manual ipv4.addresses "$address" connection.autoconnect yes
'@
}

function Get-LinuxSmbBootScript {
    param([switch]$Restore)
    if ($Restore) { return @'
mobile_kernel="$(state_get MobileKernel)"
if [[ -n "$mobile_kernel" ]]; then
    normal_kernel="$(grubby --default-kernel)"
    if [[ "$normal_kernel" == "$mobile_kernel" ]]; then
        normal_kernel="$(state_get OriginalKernel)"
        if [[ ! -f "$normal_kernel" ]] || ! grubby --info="$normal_kernel" >/dev/null 2>&1; then
            normal_kernel="$(grubby --info=ALL | sed -n 's/^kernel="\(.*\)"$/\1/p' | grep -v '/vmlinuz-mobiles-' | while IFS= read -r path; do [[ ! -f "$path" ]] || { printf '%s\n' "$path"; break; }; done)"
        fi
        [[ -n "$normal_kernel" && -f "$normal_kernel" ]] || { echo 'No normal kernel available' >&2; exit 2; }
        grubby --set-default="$normal_kernel"
    fi
    if [[ "$(state_get OriginalFips)" == 1 ]]; then
        grubby --update-kernel="$normal_kernel" --remove-args=fips --args=fips=1
        while IFS= read -r path; do
            [[ "$path" != *'/vmlinuz-mobiles-'* && -f "$path" ]] || continue
            if ! grep -Fxq "kernel=\"$path\"" "$root/kernel-entries.before"; then grubby --update-kernel="$path" --remove-args=fips --args=fips=1; fi
        done < <(grubby --info=ALL | sed -n 's/^kernel="\(.*\)"$/\1/p')
    fi
    if grubby --info="$mobile_kernel" >/dev/null 2>&1; then grubby --remove-kernel="$mobile_kernel"; fi
    rm -f -- "$mobile_kernel" "$(state_get MobileInitrd)"
fi
'@ }
    return @'
fips="$(cat /proc/sys/crypto/fips_enabled 2>/dev/null || echo 0)"
normal_kernel="$(grubby --default-kernel)"
state_set OriginalFips "$fips"
state_set OriginalKernel "$normal_kernel"
if [[ "$fips" == 1 ]]; then
    grubby --info=ALL > "$root/kernel-entries.before"
    initrd="$(grubby --info=DEFAULT | sed -n 's/^initrd="\(.*\)"$/\1/p')"
    [[ -f "$normal_kernel" && -f "$initrd" ]] || { echo 'Default kernel/initramfs is not a single file' >&2; exit 2; }
    mobile_kernel="/boot/vmlinuz-mobiles-$id"; mobile_initrd="/boot/initramfs-mobiles-$id.img"
    [[ ! -e "$mobile_kernel" && ! -e "$mobile_initrd" ]]
    state_set MobileKernel "$mobile_kernel"
    state_set MobileInitrd "$mobile_initrd"
    cp -p -- "$normal_kernel" "$mobile_kernel"; cp -p -- "$initrd" "$mobile_initrd"
    if command -v restorecon >/dev/null; then restorecon "$mobile_kernel" "$mobile_initrd"; fi
    grubby --add-kernel="$mobile_kernel" --initrd="$mobile_initrd" --copy-default --title="Mobile SMB $id" --remove-args=fips --args=fips=0
    info="$(grubby --info="$mobile_kernel")"
    printf '%s\n' "$info" | grep -q 'fips=0'
    if printf '%s\n' "$info" | grep -q 'fips=1'; then echo 'Mobile entry still enforces FIPS' >&2; exit 2; fi
    grubby --set-default="$mobile_kernel"
fi
'@
}

function Get-LinuxSmbMountScript {
    param([switch]$Restore)
    # Build the fstab without our managed block; preserve its inode and other entries.
    $removeBlock = @'
awk -v begin="# BEGIN MOBILES SMB $id" -v end="# END MOBILES SMB $id" '$0==begin {skip=1;next} $0==end {skip=0;next} !skip' /etc/fstab > "$root/fstab.base"
'@
    if ($Restore) { return @'
while IFS=$'\t' read -r host target source authority; do
    if [[ "$(state_get Version)" == 2 ]]; then
        # Partial preparation may have stopped before this particular mount was managed.
        if ! state_list ManagedMountPoints | grep -Fx -- "$target" >/dev/null; then
            continue
        fi
    fi
    if findmnt -rn -t cifs --mountpoint "$target" >/dev/null; then
        [[ "$(findmnt -rn -t cifs --mountpoint "$target" -o SOURCE)" == "$source" ]] || { echo "Unexpected mount at $target" >&2; exit 2; }
        umount "$target" # A busy mount aborts cleanup. No force/lazy unmount.
    fi
    automount="$(systemd-escape --path --suffix=automount "$target")"
    if systemctl is-active --quiet "$automount"; then systemctl stop "$automount"; fi
done < <(mount_entries)
'@ + "`n" + $removeBlock + "`n" + @'
cat "$root/fstab.base" > /etc/fstab
while IFS= read -r drop_in; do
    rm -f -- "$drop_in"
    rmdir -- "$(dirname "$drop_in")" 2>/dev/null || true
done < <(state_list MountDropIns)
rm -f -- "$root"/credentials-*
# Remove children before parents; nonempty or pre-existing directories are retained.
while IFS= read -r target; do
    rmdir -- "$target" 2>/dev/null || true
done < <(jq -r '.CreatedMountPoints | reverse[]' "$state")
systemctl daemon-reload
'@ }
    return $removeBlock + "`n" + @'
smb_user="$(option_get UserName)"
smb_password="$(printf '%s' "$payload" | jq -r .Password)"
group="$(option_get LinuxGroup)"
cp "$root/fstab.base" "$root/fstab.new"
printf '\n# BEGIN MOBILES SMB %s\n' "$id" >> "$root/fstab.new"
while IFS=$'\t' read -r host target source authority; do
    if [[ -L /share || -L "/share/$host" || -L "$target" ]] || findmnt -rn --mountpoint "$target" >/dev/null; then echo "Unsafe/mounted target $target" >&2; exit 2; fi
    if [[ -e "$target" && ( ! -d "$target" || -n "$(ls -A "$target")" ) ]]; then echo "Mount target is not an empty directory: $target" >&2; exit 2; fi
    if awk -v target="$target" '$1 !~ /^#/ && $2==target {found=1} END {exit !found}' "$root/fstab.base"; then echo "Existing fstab entry for $target" >&2; exit 2; fi
    state_add ManagedMountPoints "$target"
    for directory in /share "/share/$host" "$target"; do
        if [[ ! -d "$directory" ]]; then
            state_add CreatedMountPoints "$directory"
            mkdir -m 0755 "$directory"
        fi
    done
    credential="$root/credentials-$host"
    printf 'username=%s\npassword=%s\ndomain=%s\n' "$smb_user" "$smb_password" "$authority" > "$credential"
    chmod 600 "$credential"
    printf '%s %s cifs credentials=%s,sec=ntlmssp,vers=3.0,_netdev,nofail,x-systemd.automount,file_mode=0660,dir_mode=0770,gid=%s 0 0\n' "$source" "$target" "$credential" "$group" >> "$root/fstab.new"
done < <(mount_entries)
printf '# END MOBILES SMB %s\n' "$id" >> "$root/fstab.new"
cat "$root/fstab.new" > /etc/fstab
unset payload smb_password
# fstab is picked up at reboot. Do not start mounts or reload units here.
'@
}

function Get-LinuxSmbGroupScript {
    param([switch]$Restore)
    if ($Restore) { return @'
group="$(option_get LinuxGroup)"
while IFS= read -r user; do
    if awk -F: -v user="$user" '$1==user {found=1} END {exit !found}' /etc/passwd && id -nG "$user" | tr ' ' '\n' | grep -Fxq "$group"; then
        gpasswd -d "$user" "$group" >/dev/null
    fi
done < <(state_list AddedGroupMembers)
'@ }
    return @'
group="$(option_get LinuxGroup)"
while IFS= read -r user; do
    awk -F: -v user="$user" '$1==user {found=1} END {exit !found}' /etc/passwd
    if ! id -nG "$user" | tr ' ' '\n' | grep -Fxq "$group"; then
        state_add AddedGroupMembers "$user"
        usermod -aG "$group" "$user"
    fi
done < <(jq -r '.LinuxUsers[]' "$root/options.json")
cat "$state"
'@
}

function Get-LinuxSmbStatusScript {
    param([switch]$VerifyMounts)
    $verify = if ($VerifyMounts) { 'true' } else { 'false' }
    return "verify_mounts=$verify`n" + @'
boot_id="$(cat /proc/sys/kernel/random/boot_id)"
fips="$(cat /proc/sys/crypto/fips_enabled 2>/dev/null || echo 0)"
saved_status="$(state_get Status)"
results='[]'

if [[ "$saved_status" == RestorePendingReboot || "$saved_status" == Restored ]]; then
    # Check-in needs a new boot using the original connection and FIPS setting.
    iface="$(state_get InterfaceName)"
    original_uuid="$(state_get OriginalConnection)"
    active_uuid="$(nmcli -t -f UUID,DEVICE connection show --active | awk -F: -v dev="$iface" '$2==dev {print $1}')"
    status=RestorePendingReboot
    if [[ "$boot_id" != "$(state_get RestoreBootId)" &&
          "$fips" == "$(state_get OriginalFips)" &&
          "$active_uuid" == "$original_uuid" ]]; then
        if ip -o -4 address show up dev "$iface" scope global | awk 'END {exit NR==0}'; then
            status=Restored
            state_set Status Restored
        fi
    fi
else
    # Check-out needs a reboot, FIPS disabled, and the captured IP on the selected NIC.
    iface="$(option_get Interface InterfaceName)"
    expected_ip="$(option_get Interface IPAddress)"
    if [[ "$boot_id" == "$(state_get PreparedBootId)" ]]; then
        status=PreparedPendingReboot
    elif [[ "$fips" != 0 ]]; then
        status=NeedsReview
    elif ! ip -o -4 address show dev "$iface" | awk -v ip="$expected_ip" '
        { split($4, address, "/"); if (address[1] == ip) found=1 }
        END { exit !found }
    '; then
        status=NeedsReview
    else
        # Status observes mounts. Explicit verification also starts mounts and probes writes.
        ready=true
        if [[ "$verify_mounts" == true ]]; then systemctl daemon-reload; fi
        while IFS=$'\t' read -r host target source authority; do
            success=false
            if [[ "$verify_mounts" == true ]]; then
                unit="$(systemd-escape --path --suffix=mount "$target")"
                timeout 40 systemctl start "$unit" >/dev/null 2>&1 || true
            fi
            actual_source="$(findmnt -rn -t cifs --mountpoint "$target" -o SOURCE 2>/dev/null || true)"
            if [[ "$actual_source" == "$source" ]]; then
                success=true
                if [[ "$verify_mounts" == true ]]; then
                    if ! timeout 15 /bin/bash -c '
                        probe="$(mktemp "$1/.mobiles-write-test-XXXXXXXXXX")" && rm -- "$probe"
                    ' _ "$target"; then
                        success=false
                    fi
                fi
            fi
            results="$(printf '%s' "$results" | jq \
                --arg path "$target" --arg source "$source" --argjson success "$success" \
                '. + [{MountPoint:$path, Source:$source, Success:$success}]')"
            if [[ "$success" != true ]]; then ready=false; fi
        done < <(mount_entries)
        status=NeedsReview
        if [[ "$ready" == true ]]; then status=Active; fi
    fi
fi
jq --arg status "$status" --arg fips "$fips" --argjson mounts "$results" '
    .Status = $status | .CurrentFips = $fips | .Mounts = $mounts
' "$state"
'@
}

function Get-LinuxMobileSmbScript {
    param([Parameter(Mandatory)][ValidateSet('Prepare','Group','Restore','Status','Verify')][string]$Mode,
        [Parameter(Mandatory)][string]$Id, $Options, [pscredential]$Credential)
    if ($Id -notmatch '^[a-f0-9]{20}$') { throw 'Invalid SMB deployment state ID.' }
    $parts = [System.Collections.Generic.List[string]]::new()
    $parts.Add("export PATH=$(ConvertTo-BashArgument (Get-MobileSmbToolPath))`nid='$Id'`nroot='/var/lib/mobiles/smb/$Id'")
    $parts.Add((Get-LinuxSmbSessionScript))
    if ($Mode -eq 'Prepare') {
        $Options | Add-Member -NotePropertyName Password -NotePropertyValue $Credential.GetNetworkCredential().Password -Force
        try { $payload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($Options | ConvertTo-Json -Depth 12 -Compress))) }
        finally { $Options.PSObject.Properties.Remove('Password') }
        $parts.Add("payload=`$(printf '%s' '$payload' | base64 -d)")
        $parts.Add(@'
if [[ -f "$state" ]] && [[ "$(state_get Status)" != Restored ]]; then echo 'Saved SMB state exists; check it in first' >&2; exit 2; fi
for tool in jq nmcli ip mount.cifs findmnt grubby systemctl systemd-escape flock; do command -v "$tool" >/dev/null || { echo "SMB requires $tool" >&2; exit 2; }; done
printf '%s' "$payload" | jq 'del(.Password)' > "$root/options.json"
group="$(option_get LinuxGroup)"
getent group "$group" >/dev/null || { echo 'SMBLinuxGroup does not exist' >&2; exit 2; }
jq -n --arg boot "$(cat /proc/sys/kernel/random/boot_id)" \
    --arg fips "$(cat /proc/sys/crypto/fips_enabled 2>/dev/null || echo 0)" '{
        Version: 2,
        Status: "Preparing",
        PreparedBootId: $boot,
        OriginalFips: $fips,
        CreatedMountPoints: [],
        ManagedMountPoints: [],
        AddedGroupMembers: [],
        MobileKernel: null,
        MobileInitrd: null
    }' > "$state"
'@)
        $parts.Add((Get-LinuxSmbNetworkScript))
        $parts.Add((Get-LinuxSmbBootScript))
        $parts.Add((Get-LinuxSmbMountScript))
        $parts.Add("finish PreparedPendingReboot")
    } else {
        $parts.Add('if [[ ! -f "$state" ]]; then printf ''{"Status":"NotPrepared"}\n''; exit 0; fi')
        switch ($Mode) {
            Group { $parts.Add((Get-LinuxSmbGroupScript)) }
            Restore {
                $parts.Add('if [[ "$(state_get Status)" == Restored ]]; then cat "$state"; exit 0; fi')
                $parts.Add(@'
# Stop/remove the old deployment service if this host used the previous implementation.
unit="mobiles-smb-$id.service"
if [[ -f "/etc/systemd/system/$unit" ]]; then systemctl disable "$unit" >/dev/null; systemctl stop "$unit"; rm -f "/etc/systemd/system/$unit"; fi
rm -f -- "$root/worker.sh" "$root/environment.sh"
'@)
                $parts.Add((Get-LinuxSmbMountScript -Restore))
                $parts.Add((Get-LinuxSmbGroupScript -Restore))
                $parts.Add((Get-LinuxSmbNetworkScript -Restore))
                $parts.Add((Get-LinuxSmbBootScript -Restore))
                $parts.Add('state_set RestoreBootId "$(cat /proc/sys/kernel/random/boot_id)"')
                $parts.Add('finish RestorePendingReboot')
            }
            Status { $parts.Add((Get-LinuxSmbStatusScript)) }
            Verify { $parts.Add((Get-LinuxSmbStatusScript -VerifyMounts)) }
        }
    }
    $delimiter = 'MOBILE_SMB_' + [guid]::NewGuid().ToString('N')
    # Normalize the entire outbound script; executable content is never encoded inside JSON.
    ("dzdo bash <<'$delimiter'`n" + ($parts -join "`n") + "`n$delimiter`n").Replace("`r`n", "`n").Replace("`r", "`n")
}

function New-LinuxTask-SmbGroup {
    param([Parameter(Mandatory)][string]$Id)
    $scriptText = Get-LinuxMobileSmbScript -Mode Group -Id $Id
    @"
if smb_group_result=`$($scriptText
); then
    record_action 'SMB' 'Local mount access group' 'Success' "`$smb_group_result"
else
    record_failure 'Could not configure local SMB group membership'
    record_action 'SMB' 'Local mount access group' 'Failed'
fi
"@
}
