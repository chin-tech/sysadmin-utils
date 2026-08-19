#!/usr/bin/env bash

mobileName="$1"
mobileFile="$2"
mobileDump="$3"
outPath="deployTmp"
desiredHome="/mobiles/"

mkdir -p "$outPath"
: > "${outPath}/hashes"


mapfile -t linux_computers < <(
   awk 'tolower($0) == "[linux]" {p=1;next}/^\[/{p=0} p && NF' $mobileFile | tail -n +1
   )
users=$(awk 'tolower($0) == "[users]" {p=1;next}/^\[/{p=0} p && NF' $mobileFile | tail -n +1)
# userList=$(
#     sed -n '/^\[users\]/,/^\[/ { /^\[/d; /^$/d; p }' "$mobileFile" |
#         tail -n +2
# )



while IFS=, read -r u groups fullName; do
    [[ "$u" == "username" ]] && continue
    [[ -z "$u" ]] && continue

    isAdmin=1

    if grep -Eq '(^|;)(priv|admin|isso)(;|$)' <<< "$groups"; then
        isAdmin=0
    fi

    leHash=$(printf '%s' "$defaultPass" | openssl passwd -6 -stdin)

    if [[ -f "$mobileDump/$u" ]]; then
        while IFS=: read -r timestamp username password; do
           if [[ $username =~ (admin|priv|isso)$ ]]; then 
               leHash=$(printf '%s' "$password" | openssl passwd -6 -stdin)
               break
            elif [[ $username =~ dtr[wo]$ ]]; then
               continue
            else
               leHash=$(printf '%s' "$password" | openssl passwd -6 -stdin)
            fi
            
        done < <( openssl cms -recip "$certPath" -inform PEM -decrypt -in "$mobileDump/$u")
    fi

    printf '%s:%s:%s\n' "$u" "$isAdmin" "$leHash" >> "${outPath}/hashes"

done < <( awk ' tolower($0) == "[users]" { p=1; next } /^\[/ { p=0 } p && NF ' "$mobileFile")



cat << EOF > "${outPath}/service"
[Unit]
Description=Mobile Log Rotate Service
Requires=single-user.target

[Service]
Restart=on-failure
RemainAfterExit=no
WorkingDirectory=/path-to-logs
ExecStart=/path-to-logrotate

[Install]
WantedBy=multi-user.target
EOF

cat << EOF > "${outPath}/service.timer"
[Unit]

[Timer]
OnCalendar=Sun 23:59
Persistent=true

[Install]
WantedBy=timers.target
EOF




cat << 'EOF' > "${outPath}/script"
## Provivision Users
dzdo mkdir -p __DESIRED_HOME__
while IFS=: read u admin pw; do
   if [[ $admin -eq 0 ]]; then
      dzdo su -c "useradd -b __DESIRED_HOME__ -m -C 'mobile' -G wheel $u -p $pw"
   else
      dzdo su -c "useradd -m -b __DESIRED_HOME__ -C 'mobile' $u -p $pw"
   fi
done < "__OUT_PATH__/script"

cp __OUT_PATH__/service /etc/systemd/system/mobile-logrotate.service
cp __OUT_PATH__/service.timer /etc/systemd/system/mobile-logrotate.timer
dzdo systemctl daemon-reload
dzdo system enable --now mobile-logrotate.timer
EOF

sed -i -e "s/__OUT_PATH__/${outPath}/" "${outPath}/script" -e "s/__DESIRED_HOME__/${desiredHome}/g"

for c in "${linux_computers[@]}"; do
   ssh -i ~/.ssh/deployer "$c" 'bash -s' < "${outPath}/script"
done



