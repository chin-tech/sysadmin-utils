#!/usr/bin/env bash

## Get your desired usb device

lsusb

## example output
#
# Bus 001 Device 015: ID abcd:1234 LogiLink UDisk flash drive

# Apply rule to usbguard (also add HID for good measure)

sed -i -e '1aallow id "abcd:1234"' -e '2aallow with interface equals { 03:*:* }' /etc/usbguard/rules.conf

VENDOR="abcd"
PRODUCT="1234"

ROOT_USB_FILE="/root/test-usb"
BASE_SERVICE_NAME="usb-action@"
USB_SYSTEMD_FILE="$BASE_SERVICE_NAME.service"
## Udev rule

cat << EOF > /etc/udev/rules.d/99-u.rules
ACTION=="add", SUBSYSTEM=="usb", ENV{DEVTYPE}=="usb_device", ATTRS{idVendor}=="$VENDOR", ATTRS{idProduct}=="$PRODUCT", TAG+="systemd", ENV{SYSTEMD_WANTS}="$BASE_SERVICE_NAME%k.service"
EOF

cat << EOF > /etc/systemd/system/$USB_SYSTEMD_FILE
[Unit]
Description=USB Triggered Action Script
After=local-fs.target

[Service]
Type=oneshot
ExecStart=$ROOT_USB_FILE
EOF

cat << EOF > $ROOT_USB_FILE && chmod +x $ROOT_USB_FILE
#!/usr/bin/env bash

modprobe -C $(mktemp -d) -a uas usb-storage cdrom sr_mod
### or
modprobe --ignore-install uas
modprobe --ignore-install usb-storage
modprobe --ignore-install cdrom
modprobe --ignore-install sr_mod

sleep 2
mkdir -p /sa-tmp
mount /dev/sr0 /sa-tmp
find /sa-tmp -iname '*.cvd' -type f -exec cp -t /var/lib/clamav/ {} \;

## DO clamscan
umount /sa-tmp
rmdir /sa-tmp
modprobe -ra uas usb-storage cdrom sr_mod 

EOF


systemctl daemon-reload
udevadm control --reload-rules



