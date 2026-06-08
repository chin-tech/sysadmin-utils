# from crypt import crypt

import subprocess
import os

enc_file = 'enc_pass'
key_file = 'key_file'
key = os.urandom(32)

admin = "admin"
prefix = "DesiredPrefixHere"
postfix = "DesiredPostFixHere"

cmd = ['openssl','enc','-d', '-aes-256-cbc', '-in', enc_file,  '-kfile', key_file  ]

r = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

if r.returncode == 0:
    p = prefix + r.stdout.decode('utf-8').strip() + postfix
    print(p)
    openssl_passwd = ['openssl','passwd','-6', 'stdin']
    process = subprocess.Popen(openssl_passwd, stdin=subprocess.PIPE, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    out, err = process.communicate(input=p.encode('utf-8'))
    print(out)
    # hashed = crypt(prefix + r.stdout.decode('utf-8').strip() + postfix) 
    # passwd_cmd = ['/sbin/usermod', '-p', hashed, admin]
    # print(passwd_cmd)
    #subprocess.run(passwd_cmd)

