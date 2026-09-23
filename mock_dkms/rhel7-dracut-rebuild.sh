#!/usr/bin/env bash
#
# /etc/kernel/postinst.d/99-dracut-rebuild.sh
# Finalizer: Runs depmod and rebuilds initramfs once after all module builds complete.
#   $1 = Target Kernel Version (e.g. 3.10.0-1160.119.1.el7.x86_64)
#   $2 = Path to vmlinuz image

set -o pipefail

TARGET_KVER="$1"
LOG_FILE="/var/log/kernel-postinst-dracut.log"

exec >> "${LOG_FILE}" 2>&1

echo "======================================================================"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Starting post-build finalization for: ${TARGET_KVER}"

if [[ -z "${TARGET_KVER}" ]]; then
    echo "[!] ERROR: Missing target kernel version. Aborting."
    exit 1
fi

INITRAMFS_IMG="/boot/initramfs-${TARGET_KVER}.img"

# 1. Update module dependency maps across all compiled extra/updates modules
echo "[*] Updating module dependencies (depmod) for ${TARGET_KVER}..."
depmod -a "${TARGET_KVER}"

# 2. Rebuild initramfs once to package all newly placed modules
if command -v dracut >/dev/null 2>&1; then
    echo "[*] Building initramfs: ${INITRAMFS_IMG}..."
    dracut -f "${INITRAMFS_IMG}" "${TARGET_KVER}"
    DRACUT_EXIT=$?

    if [[ ${DRACUT_EXIT} -eq 0 ]]; then
        echo "[+] Successfully generated ${INITRAMFS_IMG}."
    else
        echo "[!] ERROR: dracut failed with exit code ${DRACUT_EXIT}."
        exit ${DRACUT_EXIT}
    fi
fi

echo "[+] Finalization complete."
exit 0