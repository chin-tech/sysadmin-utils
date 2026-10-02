#!/usr/bin/env bash


lapsdir=/root/.laps
mkdir -p $lapdirs
admin_pw_b64="c2VjcmV0cGFzcw=="
PREFIX="prefix"

echo -n $PREFIX > $lapsdir/P
head -c 50 /dev/urandom > $lapsdir/k
echo $admin_pw_b64 | base64 -d | openssl enc -aes-256-cbc -k $lapsdir/k -iter 256  -out e
openssl genpkey -algorithm RSA -pkeyopt rsa_pkey_bits:2048 -out K
openssl rsa -inkey K -pubout -out P
openssl pkeyutl -encrypt -in PW -inkey P -pubin -out E




cat << 'EOF' > $lapsdir/rotate && chmod +x $lapsdir/rotate
#!/usr/bin/env bash
lapsdir=/root/.laps
echo "$(date +%m%y)" -n > $lapsdir/D
newHash=$(cat $lapsdir/P <(openssl enc -d -aes-256-cbc -k $lapsdir/k $lapsdir/e) $lapsdir/D | paste -sd '' | openssl passwd -6)
usermod -p "$newHash" root
EOF

cat << 'EOF' > /etc/systemd/system/laps.service
[Unit]
Description=laps
Requires=multi-user.target
[Service]
WorkingDirectory=/root/.laps
ExecStart=/root/.laps/rotate
[Install]
WantedBy=multi-user.target
EOF

cat << 'EOF' > /etc/systemd/system/laps.timer
[Unit]
Description=laps-timer

[Timer]
OnBootSec=5min
OnCalendar=*-*-1 00:00:01
Persistent=true

[Install]
WantedBy=timers.target
EOF

