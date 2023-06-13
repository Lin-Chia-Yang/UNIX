import pow as pw
import base64
from pwn import *
def do_arith(num1, oper, num2):
    if(oper=='+'):
        return num1+num2
    elif(oper=='-'):
        return num1-num2
    elif(oper=='*'):
        return num1*num2
    elif(oper=='//'):
        return num1//num2
    elif(oper=='**'):
        return num1**num2
    elif(oper=='%'):
        return num1%num2
def little(ans):
    newbit = ""
    remain = len(ans) % 2
    if(remain==1):
        ans = '0' + ans
    for i in range(0, len(ans), 2):
        newbit = (ans[i] + ans[i+1]) + newbit
    return newbit

r = remote('up23.zoolab.org', 10363)
pw.solve_pow(r)
pre = r.recvuntil(b'?').decode()
sp = pre.split(' ')
times = int(sp[8])
print(sp[8])
print(int(sp[-5]), end=" ")
print(sp[-4], end=" ")
print(int(sp[-3]))
ans=hex(do_arith(int(sp[-5]), sp[-4], int(sp[-3])))
ans=ans[2:]
newbit = little(ans)
b = bytearray.fromhex(newbit)
b64 = base64.b64encode(b)
print(b64)
r.sendline(b64)

for i in range(times-1):
    pre = r.recvuntil(b'?').decode()
    sp = pre.split(' ')
    print(int(sp[-5]), end=" ")
    print(sp[-4], end=" ")
    print(int(sp[-3]))
    ans=hex(do_arith(int(sp[-5]), sp[-4], int(sp[-3])))
    ans=ans[2:]
    newbit = little(ans)
    b = bytearray.fromhex(newbit)
    b64 = base64.b64encode(b)
    print(b64)
    # print("b64={}".format(b64))
    r.sendline(b64)
    
r.interactive()

r.close()
