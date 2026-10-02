#!/usr/bin/env bash


currentPass=${1:-'P@ssw0rdP@ssw0rd'}
if [[ -f $currentPass ]]; then
   currentPass=$(cat $currentPass)
fi

target_drives="$2"
if [[ -n $target_drives ]]; then
   target_drives=$(echo "$target_drives" | grep -oP '(sd[a-z]+|nvme[0-9]+n[0-9]+(p[0-9]+)?|vd[a-z]+)' | paste -sd'|' -)
fi

readarray -t luks_drives < <(lsblk -prno name,fstype | awk '$2 == "crypto_LUKS" {print $1}' | grep "$target_drives" )
outKey=/etc/security/luks.key

drive_count="${#luks_drives[@]}"
if [[ $drive_count -gt 0 ]]; then
   echo "Found $drive_count"
else
   echo "no luks partitions found!"
   exit 1
fi

dracutNeedsRebuild=0
if [[ -c /dev/tpmrm0 ]] && [[ "2" =  $(cat /sys/class/tpm/tpm0/tpm_version_major) ]]; then
   if ! grep -q 'clevis' /etc/dracut.conf.d/*; then
      echo 'add_dracutmodules+=" clevis "' >> /etc/dracut.conf.d/clevis.conf 
   fi

   for d in "${luks_drives[@]}"; do
      echo -n "$currentPass" | clevis luks bind -d $d tpm2 '{"pcr_bank":"sha256","pcr_ids":"7"}'
   done
   dracutNeedsRebuild=1

else
   echo "...No TPM Found, hashing hardware"

   # omit /sys/class/dmi/board_serial for vm
   cat /sys/class/dmi/id/product_uuid /sys/class/dmi/id/product_serial | sha256sum | awk '{print $1}' > $outKey
   chmod 400 $outKey
   ## Add LuksKey
   for d in "${luks_drives[@]}"; do
      echo -n "$currentPass" | cryptsetup luksKillSlot $d 2 --key-file -
      echo -n "$currentPass" | cryptsetup -S 2 luksAddKey $d $outKey --key-file -
   done
   syskey_folder='/usr/lib/dracut/modules.d/99lukskey'
   mod_setup_file="$syskey_folder/module-setup.sh"
   key_sh="$syskey_folder/generate-key.sh"
   mkdir -p $syskey_folder
   cat << 'EOF' > $mod_setup_file
#!/bin/sh
check() { return 0 }
depends() { echo 'crypt' ; return 0 }
install() { 
   inst_multiple sha256sum chmod cat awk
   inst_hook cmdline 10 "$moddir/generate-key.sh" 
}
EOF
   cat << 'EOF' > $key_sh 
#!/bin/sh
if [ -d /sys/class/dmi/id ]; then
   mkdir -p /etc/security
   cat /sys/class/dmi/id/product_uuid /sys/class/dmi/id/product_serial | sha256sum | awk '{print $1}' > /etc/security/luks.key
   chmod 400 /etc/security/luks.key
fi
EOF
   chmod 755 $mod_setup_file
   chmod 755 $key_sh

   echo  'add_dracutmodules+=" lukskey "' > /etc/dracut.conf.d/syskey.conf

   ### update cryptab
   cp /etc/crypttab /root/crypttab.bak
   for d in "${luks_drives[@]}"; do
      uuid=$(blkid -s UUID -o value "$d")
      entry="luks-$uuid UUID=$uuid $outKey luks,key-slot=2,nofail"
      if grep $uuid /etc/crypttab; then
         sed "/$uuid/d" /etc/crypttab -i
      fi
      echo "$entry" >> /etc/crypttab
   done
   dracutNeedsRebuild=1

fi

if grep -q 'resume=' /proc/cmdline; then
   swap_uuid=$(grep -oP 'resume=\K.+?\s')
   grubby --update=ALL --remove-args="resume=$swap_uuid rd.luks.uuid=$swap_uuid"
   grubby --update=ALL --args="noresume"
fi

if [[ $dracutNeedsRebuild = 1 ]]; then
   dracut -f --regenerate-all
fi
