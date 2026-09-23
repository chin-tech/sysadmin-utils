#!/usr/bin/env bash
# /etc/kernel/postinst.d/10-nvidia-kmod.sh
set -o pipefail

TARGET_KVER="$1"
INSTALLER_BIN="/opt/nvidia/nvidia-driver.run"

if [[ -z "${TARGET_KVER}" ]] || [[ ! -f "${INSTALLER_BIN}" ]]; then
    exit 0
fi

# Skip if already built
if [[ -f "/lib/modules/${TARGET_KVER}/extra/nvidia.ko" ]]; then
    exit 0
fi

# Compile modules only
"${INSTALLER_BIN}" \
    --silent \
    --kernel-module-only \
    --kernel-name="${TARGET_KVER}" \
    --no-backup \
    --no-runpath