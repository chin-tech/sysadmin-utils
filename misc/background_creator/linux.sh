

## Background
cat << EOF > /etc/dconf/db/local.d/00-wallpaper
[org/gnome/login-screen]
logo='/usr/share/pixmaps/custom-logo.png'

[org/gnome/desktop/background]
picture-uri='file:///usr/share/backgrounds/custom-login.png'
picture-options='zoom'
EOF

## Gnome login logo

pictureURI='/usr/share/pixmaps/custom-logo.png'
cat << EOF > /etc/dconf/gdm.d/01-custom-logo && chmod 644 $pictureURI
[org/gnome/login-screen]
logo='$pictureURI'
[org/gnome/login-screen]
disable-user-list=true
[org/gnome/login-screen]
disable-restart-buttons=true
[org/gnome/desktop/interface]
clock-show-date=true
clock-show-seconds=true
EOF

## Gnome terminal pref
cat << EOF /etc/dconf/db/local.d/02-terminal
[org/gnome/terminal/legacy/profiles:]
default='b1d6170d-ae52-4356-ab5b-df82a6388b14'
list=['b1d6170d-ae52-4356-ab5b-df82a6388b14']

[org/gnome/terminal/legacy/profiles:/:b1d6170d-ae52-4356-ab5b-df82a6388b14]
visible-name='Default'
use-system-font=false
font='Monospace 11'
use-theme-colors=false
foreground-color='rgb(235,237,240)'
background-color='rgb(23,24,28)'
scrollback-unlimited=true
audible-bell=false
EOF
