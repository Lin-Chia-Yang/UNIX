from pwn import *
f = open("got.txt",'w')
elf = ELF('./chals')
# print("main =", hex(elf.symbols['main']))
# print("{:<12s} {:<8s} {:<8s}".format("Func", "GOT", "Address"))
array = [0]*1477
for g in elf.got:
   if "code_" in g:
      # print("{:<12s} {:<8x} {:<8x}".format(g, elf.got[g], elf.symbols[g]))
      # print("{:<12s} {:<8x}".format(g, elf.got[g]))
      a = int(g[5:])
      # print(a)
      array[a] = elf.got[g]
      # f.write("{:<12s} {:<8x}\n".format(g, elf.got[g]))
for i in range(1477):
   f.write("0x{:<8x}, ".format(array[i]))
f.close()
