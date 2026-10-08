#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------
# 1. Gather System Metrics
# ---------------------------------------------------------
HOSTNAME=$(hostname -s)
DOMAIN=$(dnsdomainname 2>/dev/null || hostname -d 2>/dev/null || echo "local")
OS_DESC=$(source /etc/os-release && echo "$PRETTY_NAME")
KERNEL=$(uname -r)
UPTIME=$(uptime -p | sed 's/up //')
SERIAL=$(cat /sys/class/dmi/id/product_serial 2>/dev/null || echo "N/A")

# Primary active IPv4 (excluding loopback)
# IP_ADDR=$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | paste -sd ' | ' -)
IP_ADDR=$(ip -4 -br a | tail -n +2 | grep -v '^br-' | awk '{print " "$NF" "}' | paste -sd '|' -)
[[ -z "$IP_ADDR" ]] && IP_ADDR="Disconnected / No IP"

# ---------------------------------------------------------
# 2. Output & Geometry Setup
# ---------------------------------------------------------
TARGET_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/dynamic-wallpaper"
mkdir -p "$TARGET_DIR"
OUTPUT_FILE="$TARGET_DIR/wallpaper.png"

# Detect display resolution (via xrandr if available, fallback to 1920x1080)
RES=$(xrandr 2>/dev/null | awk '/\*/ {print $1; exit}' || echo "1920x1080")
SCREEN_W=${RES%x*}
SCREEN_H=${RES#*x}

# Monospace font resolution
FONT_FILE=""
for f in \
    "/usr/share/fonts/liberation-mono/LiberationMono-Regular.ttf" \
    "/usr/share/fonts/dejavu-sans-mono-fonts/DejaVuSansMono.ttf" \
    "/usr/share/fonts/dejavu/DejaVuSansMono.ttf" \
    "/usr/share/fonts/liberation/LiberationMono-Regular.ttf"; do
    if [[ -f "$f" ]]; then
        FONT_FILE="$f"
        break
    fi
done
[[ -z "$FONT_FILE" ]] && FONT_FILE="Courier"

# ---------------------------------------------------------
# 3. Define Key-Value Records
# ---------------------------------------------------------
# Arrays structured as "Key|Value"
POCS=(
    "Primary Admin|Jane Doe (ext. 4401 / jdoe@domain.local)"
    "Secondary Admin|John Smith (ext. 4402 / jsmith@domain.local)"
    "Service Desk|Tier 1 Helpdesk (helpdesk@domain.local)"
)

SYSINFO=(
    "Host / Domain|${HOSTNAME} / ${DOMAIN}"
    "Serial Number|${SERIAL}"
    "IPv4 Address|${IP_ADDR}"
    "Operating Sys|${OS_DESC}"
    "Kernel|${KERNEL}"
    "System Uptime|${UPTIME}"
)


# ---------------------------------------------------------
# 4. Dimension & Column Calculations
# ---------------------------------------------------------
MAX_KEY_LEN=0
MAX_VAL_LEN=0

for entry in "${POCS[@]}" "${SYSINFO[@]}"; do
    key="${entry%%|*}"
    val="${entry#*|}"
    key_len=$((${#key} + 2)) # including ' :'
    val_len=${#val}
    (( key_len > MAX_KEY_LEN )) && MAX_KEY_LEN=$key_len
    (( val_len > MAX_VAL_LEN )) && MAX_VAL_LEN=$val_len
done

# Character metrics for standard 13pt/14px monospace font (~8.4px width, 24px line height)
CHAR_WIDTH=9
LINE_HEIGHT=24
PADDING_X=45
PADDING_Y=35
SECTION_GAP=22

KEY_COL_WIDTH=$(( MAX_KEY_LEN * CHAR_WIDTH ))
VAL_COL_WIDTH=$(( MAX_VAL_LEN * CHAR_WIDTH ))
COL_GAP=15

CONTENT_WIDTH=$(( KEY_COL_WIDTH + COL_GAP + VAL_COL_WIDTH ))
BOX_WIDTH=$(( CONTENT_WIDTH + (PADDING_X * 2) ))

TOTAL_LINES=$(( 2 + ${#POCS[@]} + ${#SYSINFO[@]} ))
BOX_HEIGHT=$(( (TOTAL_LINES * LINE_HEIGHT) + (SECTION_GAP * 2) + (PADDING_Y * 2) ))

# Center card coordinates
BOX_X=$(( (SCREEN_W - BOX_WIDTH) / 2 ))
BOX_Y=$(( (SCREEN_H - BOX_HEIGHT) / 2 ))
BOX_X2=$(( BOX_X + BOX_WIDTH ))
BOX_Y2=$(( BOX_Y + BOX_HEIGHT ))

START_X=$(( BOX_X + PADDING_X ))
VAL_X=$(( START_X + KEY_COL_WIDTH + COL_GAP ))
CUR_Y=$(( BOX_Y + PADDING_Y + 14 ))

# ---------------------------------------------------------
# 5. Build Draw Instructions
# ---------------------------------------------------------
DRAW_CMDS=()

# Background card and border
DRAW_CMDS+=("fill '#1c222c' stroke '#323c4b' stroke-width 1.5 rectangle ${BOX_X},${BOX_Y} ${BOX_X2},${BOX_Y2}")

render_section() {
    local title="$1"
    shift
    local items=("$@")

    # Section Header (Muted Blue)
    DRAW_CMDS+=("stroke none fill '#569cd6' font-size 15 font '${FONT_FILE}' text ${START_X},${CUR_Y} '${title^^}'")
    CUR_Y=$(( CUR_Y + LINE_HEIGHT + 4 ))

    # Key-Value pairs
    for item in "${items[@]}"; do
        local key="${item%%|*} :"
        local val="${item#*|}"
        # Label (Light Cyan/Blue)
        DRAW_CMDS+=("stroke none fill '#9cdcfe' font-size 13 font '${FONT_FILE}' text ${START_X},${CUR_Y} '${key}'")
        # Value (Crisp Light Gray)
        DRAW_CMDS+=("stroke none fill '#d4d4d4' font-size 13 font '${FONT_FILE}' text ${VAL_X},${CUR_Y} '${val}'")
        CUR_Y=$(( CUR_Y + LINE_HEIGHT ))
    done
    CUR_Y=$(( CUR_Y + SECTION_GAP ))
}

render_section "Points of Contact" "${POCS[@]}"
render_section "System Specifications" "${SYSINFO[@]}"

# ---------------------------------------------------------
# 6. Render Canvas & Apply
# ---------------------------------------------------------
convert -size "${SCREEN_W}x${SCREEN_H}" xc:'#12161c' \
    -draw "${DRAW_CMDS[*]}" \
    "$OUTPUT_FILE"

# Apply to GNOME if active
# if command -v gsettings &>/dev/null; then
#     gsettings set org.gnome.desktop.background picture-uri "file://$OUTPUT_FILE"
#     gsettings set org.gnome.desktop.background picture-uri-dark "file://$OUTPUT_FILE"
#     gsettings set org.gnome.desktop.background picture-options 'centered'
# fi
#
# # Apply to XFCE if active
# if command -v xfconf-query &>/dev/null; then
#     for prop in $(xfconf-query -c xfce4-desktop -l 2>/dev/null | grep 'last-image' || true); do
#         xfconf-query -c xfce4-desktop -p "$prop" -s "$OUTPUT_FILE"
#     done
# fi
