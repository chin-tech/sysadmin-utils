#!/usr/bin/env bash


usage() {
   cat <<EOF
Usage: $0 [-p password_or_file] [-d target_drives] [-s] [-h] [password_or_file] [target_drives]

Options:
  -p PASS    | Current LUKS password or path to a file containing it (default: P@ssw0rdP@ssw0rd)
  -d DRIVES  | Target drive filter (e.g., "sda,nvme0n1,md0")
  -s         | Safe mode: build a separate initramfs and create a new GRUB entry instead of overwriting existing initramfs images
  -x         | Skip entering pass,
  -t         | TPM option ( this is arguably less reliable )
  -h         Show this help message
EOF
}

luksSlot=5
separate_grub=0
currentPass=""
target_drives=""
skip=0

while getopts ":p:d:shx" opt; do
   case "$opt" in
      p) currentPass="$OPTARG" ;;
      d) target_drives="$OPTARG" ;;
      s) separate_grub=1 ;;
      x) skip=1 ;;
      h) usage; exit 0 ;;
      \?) echo "Invalid option: -$OPTARG" >&2; usage; exit 1 ;;
      :) echo "Option -$OPTARG requires an argument." >&2; usage; exit 1 ;;
   esac
done
shift $((OPTIND - 1))

currentPass="${currentPass:-${1:-P@ssw0rdP@ssw0rd}}"
if [[ -f $currentPass ]]; then
   currentPass=$(cat "$currentPass")
fi

target_drives="${target_drives:-$2}"
if [[ -n $target_drives ]]; then
   target_drives=$(echo "$target_drives" | grep -oP '(sd[a-z]+|nvme[0-9]+n[0-9]+(p[0-9]+)?|vd[a-z]+|md[0-9]+)' | paste -sd'|' -)
fi

readarray -t luks_drives < <(lsblk -prno name,fstype | awk '$2 == "crypto_LUKS" {print $1}' | grep -E "$target_drives")
outKey=/etc/security/luks.key

drive_count="${#luks_drives[@]}"
if [[ $drive_count -gt 0 ]]; then
   echo "Found $drive_count"
else
   echo "no luks partitions found!"
   exit 1
fi

dracutNeedsRebuild=0
dracut_mod=""
if [[ -n $tpm ]]; then
   echo "[INFO] Attempting TPM clevis bind"
   if [[ -c /dev/tpmrm0 ]] && [[ "2" = $(cat /sys/class/tpm/tpm0/tpm_version_major 2>/dev/null) ]]; then
      dracut_mod="clevis"
      if [[ $separate_grub -eq 0 ]] && ! grep -q 'clevis' /etc/dracut.conf.d/* 2>/dev/null; then
         echo 'add_dracutmodules+=" clevis "' >> /etc/dracut.conf.d/clevis.conf
      fi
      for d in "${luks_drives[@]}"; do
         echo -n "$currentPass" | clevis luks bind -y -d "$d" tpm2 '{"pcr_bank":"sha256","pcr_ids":"7"}'
      done
      dracutNeedsRebuild=1
   fi
else
   echo "[INFO] /sys/dmi/id hashing..."
   dracut_mod="lukskey"
   mkdir -p /etc/security
   # omit /sys/class/dmi/id/board_serial for vm

   
   cat /sys/class/dmi/id/{product_uuid,product_serial,board_serial} | sha256sum | awk '{printf "%s", $1}' > "$outKey"
   chmod 400 "$outKey"

   ## Add LuksKey
   for d in "${luks_drives[@]}"; do
      if [[ $skip -eq 1 ]]; then
         continue
      fi
      echo -n "$currentPass" | cryptsetup -q luksKillSlot "$d" $luksSlot --key-file - 2>/dev/null || true
      if ! echo -n "$currentPass" | cryptsetup -q -S $luksSlot luksAddKey "$d" "$outKey" --key-file -; then
         echo "ERROR: Failed to add LUKS key to slot 2 on $d (check current password)" >&2
         exit 1
      fi
      echo "$d - Success"
   done

   syskey_folder='/usr/lib/dracut/modules.d/99lukskey'
   mod_setup_file="$syskey_folder/module-setup.sh"
   key_sh="$syskey_folder/generate-key.sh"
   sys_service="$syskey_folder/luks-key.service"
   mkdir -p "$syskey_folder"

   cat << 'EOF' > "$mod_setup_file"
#!/bin/bash
check() { return 0; }
depends() { echo "crypt systemd"; return 0; }

installkernel() {
    hostonly="" instmods dmi-sysfs dmi_scan
}

install() {
    inst_multiple sha256sum cat awk mkdir chmod sed
    inst_simple "$moddir/generate-key.sh" /usr/sbin/generate-key.sh
    chmod 755 "${initdir}/usr/sbin/generate-key.sh"

    # Run as early dracut hooks (for RHEL 7 / non-systemd udev paths)
    inst_hook cmdline 01 "$moddir/generate-key.sh"
    inst_hook pre-udev 01 "$moddir/generate-key.sh"

    inst_simple "$moddir/luks-key.service" "$systemdsystemunitdir/luks-key.service"

    # Pull lukskey-gen.service and passive cryptsetup-pre.target into active boot targets
    local udir="${initdir}{$systemdsystemunitdir}"
    mkdir -p "$udir"/{sysinit.target.wants,cryptsetup.target.{requires,wants},cryptsetup-pre.target.requires,systemd-cryptsetup@.service.d}
    for t in "$udir"/{sysinit.target.wants,cryptsetup.target.requires,cryptsetup-pre.target.requires}; do
      ln -sf "../luks-key.service" "$t/"
   done
   for t in "$udir"/{sysinit.target.wants,cryptsetup.target.wants}; do
      ln -sf "../cryptsetup-pre.target" "$t/"
   done

    # Drop-in to guarantee systemd-cryptsetup@ instances wait for lukskey-gen.service
    mkdir -p "${initdir}${systemdsystemunitdir}/systemd-cryptsetup@.service.d"
    cat << 'DROPIN' > "${initdir}${systemdsystemunitdir}/systemd-cryptsetup@.service.d/10-lukskey.conf"
[Unit]
Requires=luks-key.service
After=luks-key.service
DROPIN

    # Ensure initramfs /etc/crypttab contains the keyfile path for all entries
    if [ -f /etc/crypttab ]; then
        while read -r _mapper _dev _luksfile _luksoptions || [ -n "$_mapper" ]; do
            [ -z "$_mapper" ] && continue
            [ "${_mapper#\#}" != "$_mapper" ] && continue
            case "$_dev" in
                UUID=*) _dev="/dev/disk/by-uuid/${_dev#UUID=}" ;;
            esac
            if [ -f "${initdir}/etc/crypttab" ]; then
                sed -i "\|^${_mapper}[[:space:]]|d" "${initdir}/etc/crypttab"
            fi
            echo "$_mapper $_dev $_luksfile $_luksoptions" >> "${initdir}/etc/crypttab"
        done < /etc/crypttab
    fi
}
EOF

   cat << 'EOF' > "$key_sh"
#!/bin/sh
outKey=/etc/security/luks.key
SYS_DIR=/sys/class/dmi/id

[ -d "$SYS_DIR" ] || modprobe dmi-sysfs 2>/dev/null || true

mkdir -p /etc/security
cat /sys/class/dmi/id/{product_uuid,product_serial,board_serial} | sha256sum | awk '{printf "%s", $1}' > "$outKey"
chmod 400 /etc/security/luks.key
EOF

   cat << 'EOF' > "$sys_service"
[Unit]
Description=Generate LUKS Key from Hardware
DefaultDependencies=no
Before=cryptsetup-pre.target cryptsetup.target systemd-udevd.service dracut-cmdline.service dracut-pre-udev.service
Wants=cryptsetup-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/generate-key.sh

[Install]
WantedBy=sysinit.target cryptsetup.target cryptsetup-pre.target
EOF
   chmod 755 "$mod_setup_file" "$key_sh" "$sys_service"

   if [[ $separate_grub -eq 0 ]]; then
      echo 'add_dracutmodules+=" lukskey "' > /etc/dracut.conf.d/syskey.conf
   fi

   ### update crypttab
   cp /etc/crypttab /root/crypttab.bak 2>/dev/null || true
   for d in "${luks_drives[@]}"; do
      uuid=$(blkid -s UUID -o value "$d")
      entry="luks-$uuid UUID=$uuid $outKey luks"
      if [ -f /etc/crypttab ] && grep -q "$uuid" /etc/crypttab; then
         sed -i "/$uuid/d" /etc/crypttab
      fi
      echo "$entry" >> /etc/crypttab
   done
   dracutNeedsRebuild=1

fi

if [[ $dracutNeedsRebuild = 1 ]]; then
   if [[ $separate_grub -eq 1 ]]; then
      default_kernel=$(grubby --default-kernel)
      default_kver=$(basename "$default_kernel" | sed 's/^vmlinuz-//')
      default_title=$(grubby --info="$default_kernel" | awk -F= '/^title=/ {gsub(/^"|"$|^\x27|\x27$/, "", $2); print $2; exit}')
      [[ -z "$default_title" ]] && default_title="RHEL ($default_kver)"

      local kname="vmlinuz-${default_kver}-lukssafe"
      unlock_kernel="/boot/${kname}"
      unlock_initrd="/boot/${kname}.img"

      echo "Creating dedicated kernel link $unlock_kernel and initramfs $unlock_initrd..."
      ln -f "$default_kernel" "$unlock_kernel" 2>/dev/null || cp -f "$default_kernel" "$unlock_kernel"
      dracut -f -a "$dracut_mod" "$unlock_initrd" "$default_kver"
      if grep -q 'fips=1' /proc/cmdline; then
         echo "[INFO] Fips detected...adding hmac"
         sha512hmac $unlokc_kernel > "/boot/.$kname.hmac"
      fi

      local grub_title="${default_title} (luks-safe)"
      grubby --remove-kernel="$unlock_kernel" 2>/dev/null || true
      grubby --add-kernel="$unlock_kernel" --initrd="$unlock_initrd" --copy-default --title="${grub_title}" --make-default

      if grep -q 'resume=' /proc/cmdline; then
         swap_uuid=$(grep -oP 'resume=\K\S+' /proc/cmdline)
         grubby --update-kernel="$unlock_kernel" --remove-args="resume=$swap_uuid rd.luks.uuid=$swap_uuid"
         grubby --update-kernel="$unlock_kernel" --args="noresume"
      fi
      echo "Added GRUB entry '${grub_title}' with initramfs $unlock_initrd"
   else
      if grep -q 'resume=' /proc/cmdline; then
         swap_uuid=$(grep -oP 'resume=\K\S+' /proc/cmdline)
         grubby --update=ALL --remove-args="resume=$swap_uuid rd.luks.uuid=$swap_uuid"
         grubby --update=ALL --args="noresume"
      fi
      dracut -f --regenerate-all
   fi
fi
