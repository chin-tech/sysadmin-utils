## HAve script run at startup via gnome xdg

[Desktop Entry]
Type=Application
Name=Dynamic Wallpaper
Exec=/usr/local/bin/generate-wallpaper.sh
Terminal=false
NoDisplay=true


### For network changes add in /etc/NetworkManager/dispatcher.d/refresh.sh
#!/usr/bin/env bash
if [[ "$2" == "up" || "$2" == "dhcp4-change" ]]; then
    # Iterate active desktop user sessions
    for user in $(who | awk '{print $1}' | sort -u); do
        su - "$user" -c "/usr/local/bin/generate-wallpaper.sh" &>/dev/null || true
    done
fi
