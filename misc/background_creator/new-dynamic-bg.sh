#!/usr/bin/env bash
set -euo pipefail

# 1. Gather System Metrics
HOSTNAME=$(hostname -s)
DOMAIN=$(dnsdomainname 2>/dev/null || hostname -d 2>/dev/null || echo "local")
OS_DESC=$(source /etc/os-release && echo "$PRETTY_NAME")
KERNEL=$(uname -r)
UPTIME=$(uptime -p | sed 's/up //')
SERIAL=$(cat /sys/class/dmi/id/product_serial 2>/dev/null || echo "N/A")

## CUSTOMIZATION
## convert -list font
FONT='Noto-Sans-Black'

# Primary active IPv4 (excluding lo)
IP_ADDR=$(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | paste -sd ' | ' -)
[[ -z "$IP_ADDR" ]] && IP_ADDR="Disconnected / No IP"

# 2. Canvas & Rendering Geometry
TARGET_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/dynamic-wallpaper"
mkdir -p "$TARGET_DIR"
OUTPUT_FILE="$TARGET_DIR/wallpaper.png"

# Detect display resolution (via xrandr if in X11, fallback to 1920x1080)
RES=$(xrandr 2>/dev/null | awk '/\*/ {print $1; exit}' || echo "1920x1080")
WIDTH=${RES%x*}
HEIGHT=${RES#*x}

# 3. Text Block Content
TEXT_CONTENT="\
POINTS OF CONTACT
----------------------------------------
Primary Admin   : Jane Doe (ext. 4401)
Secondary Admin : John Smith (ext. 4402)
Service Desk    : helpdesk@domain.local

SYSTEM SPECIFICATIONS
----------------------------------------
Host / Domain   : ${HOSTNAME} / ${DOMAIN}
Serial Number   : ${SERIAL}
IPv4 Address    : ${IP_ADDR}
Operating Sys   : ${OS_DESC}
Kernel          : ${KERNEL}
System Uptime   : ${UPTIME}"

# 4. Render Base Canvas & Centered Card with ImageMagick
# - Creates an isolated centered label card
# - Layers it onto a dark base canvas
convert -size "${WIDTH}x${HEIGHT}" xc:'#12161c' \
    \( \
        -background '#1c222c' \
        -fill '#d4d4d4' \
        -font "$FONT" \
        -pointsize 14 \
        label:"$TEXT_CONTENT" \
        -bordercolor '#323c4b' \
        -border 2 \
        -bordercolor '#1c222c' \
        -border 25 \
        -bordercolor '#323c4b' \
        -border 1 \
    \) \
    -gravity center \
    -composite \
    "$OUTPUT_FILE"

# 5. Apply Background across Desktop Environments
# GNOME 3/40+
# if command -v gsettings &>/dev/null; then
#     gsettings set org.gnome.desktop.background picture-uri "file://$OUTPUT_FILE"
#     gsettings set org.gnome.desktop.background picture-uri-dark "file://$OUTPUT_FILE"
#     gsettings set org.gnome.desktop.background picture-options 'zoom'
# fi
#
# # XFCE (XRDP / Lightweight)
# if command -v xfconf-query &>/dev/null; then
#     for prop in $(xfconf-query -c xfce4-desktop -l | grep 'last-image'); do
#         xfconf-query -c xfce4-desktop -p "$prop" -s "$OUTPUT_FILE"
#     done
# fi
