# Overview

These are a short snippet of scripts that can be rather useful for system administration, that solve particular problems.
These problems are usually due to restricted environments where some more obvious tools would be the go to choice...

## Systemd Mock Timer
cron sucks, because you can't specify something to actually occur specifically at once a month. You can get close, but then you can't make sure the thing runs when you need.
Systemd solves this with `Persistent=true` in a systemd-timer. What if your system doesn't run systemd?
You wrap cron in a helper script that triggers roughly every 5 minutes that checks a reference file and runs your desired program. 


## Mock LAPS
Security people haven't gotten the memo that password rotation of uncompromised passwords is actually bad security hygiene because it promotes bad passwords.
But when you work in an enterprise with multiple closed off networks, you need them all to know the password and need it to rotate for cybersecurity.
So this solves this issue. I have a linux and a windows version. The windows version also includes a fail-safe backdoor incase for some reason your local admin gets kicked out of the administrator group.


