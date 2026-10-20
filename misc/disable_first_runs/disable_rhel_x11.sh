#!/usr/bin/env bash

systemctl disable initial-setup.service

mkdir -p /etc/xdg/gnome-initial-setup.d/
echo "yes" > /etc/xdg/gnome-initial-setup.d/gnome-initial-setup-done

mkdir -p /etc/skel/.config
echo "yes" > /etc/skel/.config/gnome-initial-setup-done


