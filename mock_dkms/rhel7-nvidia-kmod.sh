#!/usr/bin/env bash
#
# /etc/kernel/postinst.d/99-nvidia-kmod.sh
# Invoked automatically by RHEL 7 kernel RPM scriptlets:
#   $1 = Kernel Version string (e.g. 3.10.0-1160.119.1.el7.x86_64)
#   $2 = Path to vmlinuz (e.g. /boot/vmlinuz-3.10.0-1160.119.1.el7.x86_64)

set -o pipefail

TARGET_KVER="$1"
VMLINUZ_PATH="$2"
LOG_FILE="/var/log/nvidia-kernel-hook.log"
INSTALLER_BIN="/opt/nvidia/nvidia-driver.run"

exec >> "${LOG_FILE}" 2>&1

echo "======================================================================"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Hook triggered for target kernel: ${TARGET_KVER}"

# Guard: Ensure we received a kernel version
if [[ -z "${TARGET_KVER}" ]]; then
    echo "[!] ERROR: No kernel version supplied to \$1. Aborting."
    exit 1
fi

# Guard: Ensure the installer bundle exists
if [[ ! -f "${INSTALLER_BIN}" ]]; then
    echo "[!] ERROR: NVIDIA installer not found at ${INSTALLER_BIN}. Skipping."
    exit 0
fi

# Guard: Ensure matching kernel-devel / build tree exists
KBUILD_DIR="/lib/modules/${TARGET_KVER}/build"
if [[ ! -d "${KBUILD_DIR}" ]]; then
    echo "[!] WARNING: Kernel header tree '${KBUILD_DIR}' does not exist."
    echo "[!] Run: yum install -y kernel-devel-${TARGET_KVER}"
    exit 0
fi

# Check if NVIDIA module already exists for this kernel
if [[ -f "/lib/modules/${TARGET_KVER}/extra/nvidia.ko" ]] || \
   [[ -f "/lib/modules/${TARGET_KVER}/kernel/drivers/video/nvidia.ko" ]]; then
    echo "[*] NVIDIA kernel module is already compiled for ${TARGET_KVER}. Nothing to do."
    exit 0
fi

echo "[*] Compiling NVIDIA kernel interface for ${TARGET_KVER}..."

# NVIDIA installer flags:
#   -s, --silent: Run without interactive ncurses UI
#   -K, --kernel-module-only: Only compile & install kernel modules (don't overwrite OpenGL/user libs)
#   -k, --kernel-name: Specify the target kernel release string
#   --no-backup: Do not create backup of existing display configs
#   --no-runpath: Prevent modifying system shared library path
"${INSTALLER_BIN}" \
    --silent \
    --kernel-module-only \
    --kernel-name="${TARGET_KVER}" \
    --no-backup \
    --no-runpath

INSTALL_EXIT=$?

if [[ ${INSTALL_EXIT} -eq 0 ]]; then
    echo "[+] Successfully compiled NVIDIA modules for ${TARGET_KVER}."
    
    # Update module dependencies map for the target kernel
    depmod -a "${TARGET_KVER}"
    
    # Rebuild initramfs for the target kernel to avoid nouveau/driver race on boot
    if command -v dracut >/dev/null 2>&1; then
        echo "[*] Updating dracut initramfs for ${TARGET_KVER}..."
        dracut -f "/boot/initramfs-${TARGET_KVER}.img" "${TARGET_KVER}"
    fi
    echo "[+] Done."
else
    echo "[!] ERROR: NVIDIA installer failed with exit code ${INSTALL_EXIT}."
    exit ${INSTALL_EXIT}
fi

exit 0