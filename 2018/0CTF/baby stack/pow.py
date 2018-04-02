#!/usr/bin/python -u
# encoding: utf-8

import random, string, subprocess, os, sys
from hashlib import sha256

os.chdir(os.path.dirname(os.path.realpath(__file__)))

def proof_of_work():
    chal = ''.join(random.choice(string.letters+string.digits) for _ in xrange(16))
    print chal
    sol = sys.stdin.read(4)
    if len(sol) != 4 or not sha256(chal + sol).digest().startswith('\0\0\0'):
        exit()


def exec_serv(name, payload):
    p = subprocess.Popen(name, stdin=subprocess.PIPE, stdout=file('/dev/null','w'), stderr=subprocess.STDOUT)
    p.stdin.write(payload)
    p.wait()

if __name__ == '__main__':
    proof_of_work()
    payload = sys.stdin.read(0x100)
    exec_serv('./babystack', payload)


0804A000  14 9F 04 08 18 69 F3 F7  00 70 F2 F7 00 FB E0 F7
0804A010  16 83 04 08 40 25 D5 F7  00 00 00 00 00 00 00 00

