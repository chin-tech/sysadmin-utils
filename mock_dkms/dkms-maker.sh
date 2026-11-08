#!/usr/bin/env bash
set -euo pipefail

# Usage: sudo ./setup_dkms.sh <path-to-driver-folder> <module-name> <version>
DRIVER_DIR="$(realpath "$1")"
PKG_NAME="${2:-$(basename "$DRIVER_DIR")}"
PKG_VER="${3:-1.0.0}"
MAKEFILE="$DRIVER_DIR/Makefile"

if [[ ! -f "$MAKEFILE" ]]; then
    echo "Error: No Makefile found in $DRIVER_DIR" >&2
    exit 1
fi

# 1. Extract TARGET / module name from the Makefile (falls back to PKG_NAME)
TARGET_NAME=$(grep -E '^\s*TARGET\s*:?=' "$MAKEFILE" | head -n1 | cut -d '=' -f2 | tr -d '[:space:]' || true)
TARGET_NAME="${TARGET_NAME%.ko}" # strip .ko if present
TARGET_NAME="${TARGET_NAME:-$PKG_NAME}"

# 2. Generate dkms.conf inside the driver directory
cat <<EOF > "$DRIVER_DIR/dkms.conf"
PACKAGE_NAME="${PKG_NAME}"
PACKAGE_VERSION="${PKG_VER}"
CLEAN="make clean"
MAKE[0]="make KDIR=/lib/modules/\${kernelver}/build"
BUILT_MODULE_NAME[0]="${TARGET_NAME}"
DEST_MODULE_LOCATION[0]="/updates/dkms/"
AUTOINSTALL="yes"
EOF

echo "[+] Created $DRIVER_DIR/dkms.conf"

# 3. Create symlink in /usr/src/
SRC_LINK="/usr/src/${PKG_NAME}-${PKG_VER}"
if [[ -L "$SRC_LINK" || -d "$SRC_LINK" ]]; then
    sudo rm -rf "$SRC_LINK"
fi

sudo ln -s "$DRIVER_DIR" "$SRC_LINK"
echo "[+] Linked $DRIVER_DIR -> $SRC_LINK"

# 4. Register, build, and install into the current running kernel
sudo dkms remove "${PKG_NAME}/${PKG_VER}" --all 2>/dev/null || true
sudo dkms add "${PKG_NAME}/${PKG_VER}"
sudo dkms build "${PKG_NAME}/${PKG_VER}"
sudo dkms install "${PKG_NAME}/${PKG_VER}"

echo "[+] Done. Checking status:"
dkms status -m "${PKG_NAME}"
