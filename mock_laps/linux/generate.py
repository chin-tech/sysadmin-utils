#import crypt
import subprocess
import os


in_file = "in_pass"
out_file = 'enc_pass'
key_file = 'key_file'
key = os.urandom(32)
with open(key_file, 'wb') as f:
    f.write(key)

cmd = ['openssl','enc', '-aes-256-cbc', '-in', in_file, '-out', out_file, '-kfile', key_file  ]

subprocess.run(cmd, check=True)
