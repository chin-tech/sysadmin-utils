 #!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------
# 1. Gather Live System Specifications
# ---------------------------------------------------------
HOSTNAME=$(hostname -s)
DOMAIN=$(dnsdomainname 2>/dev/null || hostname -d 2>/dev/null || echo "local")
OS_DESC=$(source /etc/os-release && echo "$PRETTY_NAME")
SERIAL=$(cat /sys/class/dmi/id/product_serial 2>/dev/null || echo "N/A")
IP_ADDR=$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | paste -sd ' | ' -)
[[ -z "$IP_ADDR" ]] && IP_ADDR="Disconnected / No IP"

# ---------------------------------------------------------
# 2. POC Configuration & Random Pool Selection
# ---------------------------------------------------------
PRIMARY_ADMIN="Jane Doe (ext. 4401 / jdoe@domain.local)"

# Tech pool (can also be loaded from an external file via mapfile/readarray)
TECH_POOL=(
    "John Smith (ext. 4402 / jsmith@domain.local)"
    "Alice Cooper (ext. 4403 / acooper@domain.local)"
    "Bob Martin (ext. 4404 / bmartin@domain.local)"
    "Charlie Brown (ext. 4405 / cbrown@domain.local)"
    "Diana Prince (ext. 4406 / dprince@domain.local)"
    "Evan Wright (ext. 4407 / ewright@domain.local)"
    "Fiona Gallagher (ext. 4408 / fgallagher@domain.local)"
    "George Clark (ext. 4409 / gclark@domain.local)"
)

# Randomly select up to 5 technicians without repetition
RANDOM_LIMIT=5
SELECTED_TECHS=()
if (( ${#TECH_POOL[@]} > 0 )); then
    while IFS= read -r line; do
        [[ -n "$line" ]] && SELECTED_TECHS+=("$line")
    done < <(printf '%s\n' "${TECH_POOL[@]}" | shuf -n "$RANDOM_LIMIT")
fi

# ---------------------------------------------------------
# 3. Dynamic Height & Geometry Calculations
# ---------------------------------------------------------
RES=$(xrandr 2>/dev/null | awk '/\*/ {print $1; exit}' || echo "1920x1080")
WIDTH=${RES%x*}
HEIGHT=${RES#*x}

CARD_W=680
PADDING_X=35
PADDING_Y=35
LINE_HEIGHT=24
SECTION_GAP=28

# Calculate line counts
POC_COUNT=$(( 1 + ${#SELECTED_TECHS[@]} )) # Primary + selected pool
SYS_COUNT=4                                # Host, Serial, IP, OS
TOTAL_LINES=$(( POC_COUNT + SYS_COUNT ))

# Card dimensions
CARD_H=$(( (TOTAL_LINES * LINE_HEIGHT) + (2 * SECTION_GAP) + (PADDING_Y * 2) ))
CARD_X=$(( (WIDTH - CARD_W) / 2 ))
CARD_Y=$(( (HEIGHT - CARD_H) / 2 ))

TARGET_DIR="/var/cache/dynamic-wallpaper"
mkdir -p "$TARGET_DIR"
SVG_FILE="$TARGET_DIR/wallpaper.svg"

# ---------------------------------------------------------
# 4. Generate Dynamic SVG Elements
# ---------------------------------------------------------
CURRENT_Y=0
SVG_BODY=""

# Section 1: Points of Contact
SVG_BODY+="    <text y=\"${CURRENT_Y}\" class=\"header\">POINTS OF CONTACT</text>\n"
CURRENT_Y=$(( CURRENT_Y + LINE_HEIGHT ))

SVG_BODY+="    <text y=\"${CURRENT_Y}\" class=\"label\">Primary Admin   :</text>\n"
SVG_BODY+="    <text x=\"165\" y=\"${CURRENT_Y}\" class=\"value\">${PRIMARY_ADMIN}</text>\n"
CURRENT_Y=$(( CURRENT_Y + LINE_HEIGHT ))

tech_idx=1
for tech in "${SELECTED_TECHS[@]}"; do
    label=$(printf 'On-Call Tech %-2d :' "$tech_idx")
    SVG_BODY+="    <text y=\"${CURRENT_Y}\" class=\"label\">${label}</text>\n"
    SVG_BODY+="    <text x=\"165\" y=\"${CURRENT_Y}\" class=\"value\">${tech}</text>\n"
    CURRENT_Y=$(( CURRENT_Y + LINE_HEIGHT ))
    ((tech_idx++))
done

CURRENT_Y=$(( CURRENT_Y + SECTION_GAP ))

# Section 2: System Specifications
SVG_BODY+="    <text y=\"${CURRENT_Y}\" class=\"header\">SYSTEM SPECIFICATIONS</text>\n"
CURRENT_Y=$(( CURRENT_Y + LINE_HEIGHT ))

SVG_BODY+="    <text y=\"${CURRENT_Y}\" class=\"label\">Host / Domain   :</text>\n"
SVG_BODY+="    <text x=\"165\" y=\"${CURRENT_Y}\" class=\"value\">${HOSTNAME} / ${DOMAIN}</text>\n"
CURRENT_Y=$(( CURRENT_Y + LINE_HEIGHT ))

SVG_BODY+="    <text y=\"${CURRENT_Y}\" class=\"label\">Serial Number   :</text>\n"
SVG_BODY+="    <text x=\"165\" y=\"${CURRENT_Y}\" class=\"value\">${SERIAL}</text>\n"
CURRENT_Y=$(( CURRENT_Y + LINE_HEIGHT ))

SVG_BODY+="    <text y=\"${CURRENT_Y}\" class=\"label\">IPv4 Address    :</text>\n"
SVG_BODY+="    <text x=\"165\" y=\"${CURRENT_Y}\" class=\"value\">${IP_ADDR}</text>\n"
CURRENT_Y=$(( CURRENT_Y + LINE_HEIGHT ))

SVG_BODY+="    <text y=\"${CURRENT_Y}\" class=\"label\">Operating Sys   :</text>\n"
SVG_BODY+="    <text x=\"165\" y=\"${CURRENT_Y}\" class=\"value\">${OS_DESC}</text>\n"

# ---------------------------------------------------------
# 5. Write SVG Output
# ---------------------------------------------------------
cat <<EOF > "$SVG_FILE"
<svg xmlns="http://www.w3.org/2000/svg" width="${WIDTH}" height="${HEIGHT}" viewBox="0 0 ${WIDTH} ${HEIGHT}">
  <style>
    .bg { fill: #12161c; }
    .card { fill: #1c222c; stroke: #323c4b; stroke-width: 1.5; rx: 4; }
    .header { font-family: monospace; font-size: 15px; font-weight: bold; fill: #569cd6; }
    .label { font-family: monospace; font-size: 13px; fill: #9cdcfe; }
    .value { font-family: monospace; font-size: 13px; fill: #d4d4d4; }
  </style>

  <!-- Background Base Canvas -->
  <rect width="100%" height="100%" class="bg" />

  <!-- Centered Dynamic Card -->
  <rect x="${CARD_X}" y="${CARD_Y}" width="${CARD_W}" height="${CARD_H}" class="card" />

  <!-- Content Group -->
  <g transform="translate($((CARD_X + PADDING_X)), $((CARD_Y + PADDING_Y + 12)))">
$(printf "%b" "$SVG_BODY")
  </g>
</svg>
EOF

chmod 644 "$SVG_FILE"

# Apply dynamically if user session is active
if command -v gsettings &>/dev/null; then
    gsettings set org.gnome.desktop.background picture-uri "file://$SVG_FILE"
    gsettings set org.gnome.desktop.background picture-options 'zoom'
    gsettings set org.gnome.desktop.screensaver picture-uri "file://$SVG_FILE"
fi
