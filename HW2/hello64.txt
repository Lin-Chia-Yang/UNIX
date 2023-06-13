
./hello64:     file format elf64-x86-64


Disassembly of section .text:

00000000004000b0 <_start>:
  4000b0:	b8 04 00 00 00       	mov    eax,0x4
  4000b5:	bb 01 00 00 00       	mov    ebx,0x1
  4000ba:	b9 d4 00 60 00       	mov    ecx,0x6000d4
  4000bf:	ba 0e 00 00 00       	mov    edx,0xe
  4000c4:	cd 80                	int    0x80
  4000c6:	b8 01 00 00 00       	mov    eax,0x1
  4000cb:	bb 00 00 00 00       	mov    ebx,0x0
  4000d0:	cd 80                	int    0x80
  4000d2:	c3                   	ret    

Disassembly of section .data:

00000000006000d4 <msg>:
  6000d4:	68 65 6c 6c 6f       	push   0x6f6c6c65
  6000d9:	2c 20                	sub    al,0x20
  6000db:	77 6f                	ja     60014c <_end+0x64>
  6000dd:	72 6c                	jb     60014b <_end+0x63>
  6000df:	64 21 0a             	and    DWORD PTR fs:[rdx],ecx
	...
